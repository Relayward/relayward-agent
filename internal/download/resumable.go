// Package download provides durable, verified artifact downloads.
package download

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

type ResponseValidator func(*http.Response) error

type Artifact struct {
	URL              string
	Path             string
	Size             int64
	SHA256           string
	Header           http.Header
	ValidateResponse ResponseValidator
}

func Fetch(ctx context.Context, client *http.Client, artifact Artifact) error {
	if client == nil {
		return errors.New("artifact HTTP client is required")
	}
	if !filepath.IsAbs(artifact.Path) || filepath.Clean(artifact.Path) != artifact.Path {
		return errors.New("artifact path must be absolute and clean")
	}
	if artifact.Size < 1 {
		return errors.New("artifact size must be positive")
	}
	digest, err := hex.DecodeString(artifact.SHA256)
	if err != nil || len(digest) != sha256.Size || hex.EncodeToString(digest) != artifact.SHA256 {
		return errors.New("artifact SHA-256 is invalid")
	}

	file, offset, complete, err := openPartial(artifact.Path, artifact.Size, artifact.SHA256)
	if err != nil {
		return err
	}
	if complete {
		return nil
	}
	defer file.Close()

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, artifact.URL, nil)
	if err != nil {
		return errors.New("create artifact request")
	}
	if artifact.Header != nil {
		request.Header = artifact.Header.Clone()
	}
	request.Header.Set("Accept-Encoding", "identity")
	if offset > 0 {
		request.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	response, err := client.Do(request)
	if err != nil {
		return errors.New("artifact endpoint unavailable")
	}
	defer response.Body.Close()
	if artifact.ValidateResponse != nil {
		if err := artifact.ValidateResponse(response); err != nil {
			return err
		}
	}

	switch {
	case offset == 0 && response.StatusCode != http.StatusOK:
		return fmt.Errorf("artifact endpoint returned HTTP %d", response.StatusCode)
	case offset > 0 && response.StatusCode == http.StatusPartialContent:
		expectedRange := fmt.Sprintf("bytes %d-%d/%d", offset, artifact.Size-1, artifact.Size)
		if strings.TrimSpace(response.Header.Get("Content-Range")) != expectedRange {
			return errors.New("artifact response range does not match the partial file")
		}
	case offset > 0 && response.StatusCode == http.StatusOK:
		if err := resetPartial(file); err != nil {
			return err
		}
		offset = 0
	case offset > 0:
		return fmt.Errorf("artifact endpoint returned HTTP %d", response.StatusCode)
	}

	remaining := artifact.Size - offset
	if response.ContentLength >= 0 && response.ContentLength != remaining {
		return errors.New("artifact response size does not match the expected range")
	}
	if _, err := file.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek partial artifact: %w", err)
	}
	written, copyErr := io.Copy(file, io.LimitReader(response.Body, remaining+1))
	if syncErr := file.Sync(); syncErr != nil {
		return fmt.Errorf("sync partial artifact: %w", errors.Join(copyErr, syncErr))
	}
	if copyErr != nil {
		return errors.New("read artifact response")
	}
	if written != remaining {
		if written > remaining {
			if err := file.Truncate(offset); err != nil {
				return fmt.Errorf("repair oversized partial artifact: %w", err)
			}
			if err := file.Sync(); err != nil {
				return fmt.Errorf("sync repaired partial artifact: %w", err)
			}
		}
		return errors.New("artifact response size does not match")
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close partial artifact: %w", err)
	}
	if err := verify(artifact.Path, artifact.Size, artifact.SHA256); err != nil {
		if removeErr := removePartial(artifact.Path); removeErr != nil {
			return errors.Join(err, removeErr)
		}
		return err
	}
	return nil
}

func openPartial(path string, size int64, digest string) (*os.File, int64, bool, error) {
	directory := filepath.Dir(path)
	info, err := os.Lstat(path)
	switch {
	case err == nil && !info.Mode().IsRegular():
		if err := removePartial(path); err != nil {
			return nil, 0, false, err
		}
	case err != nil && !errors.Is(err, os.ErrNotExist):
		return nil, 0, false, fmt.Errorf("inspect partial artifact: %w", err)
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o700)
	if err != nil {
		return nil, 0, false, fmt.Errorf("open partial artifact: %w", err)
	}
	closeWithError := func(cause error) (*os.File, int64, bool, error) {
		if closeErr := file.Close(); closeErr != nil {
			cause = errors.Join(cause, closeErr)
		}
		return nil, 0, false, cause
	}
	if err := file.Chmod(0o700); err != nil {
		return closeWithError(fmt.Errorf("protect partial artifact: %w", err))
	}
	info, err = file.Stat()
	if err != nil {
		return closeWithError(fmt.Errorf("inspect open partial artifact: %w", err))
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 {
		return closeWithError(errors.New("partial artifact must be a private executable regular file"))
	}
	if info.Size() > size {
		if err := resetPartial(file); err != nil {
			return closeWithError(err)
		}
		info, err = file.Stat()
		if err != nil {
			return closeWithError(fmt.Errorf("inspect repaired partial artifact: %w", err))
		}
	}
	if info.Size() == size {
		if err := file.Close(); err != nil {
			return nil, 0, false, fmt.Errorf("close complete partial artifact: %w", err)
		}
		if err := verify(path, size, digest); err == nil {
			return nil, size, true, nil
		}
		file, err = os.OpenFile(path, os.O_RDWR|os.O_TRUNC, 0o700)
		if err != nil {
			return nil, 0, false, fmt.Errorf("reset invalid partial artifact: %w", err)
		}
		if err := file.Chmod(0o700); err != nil {
			return closeWithError(fmt.Errorf("protect reset partial artifact: %w", err))
		}
		if err := file.Sync(); err != nil {
			return closeWithError(fmt.Errorf("sync reset partial artifact: %w", err))
		}
		info, err = file.Stat()
		if err != nil {
			return closeWithError(fmt.Errorf("inspect reset partial artifact: %w", err))
		}
	}
	if info.Size() == 0 {
		if err := syncDirectory(directory); err != nil {
			return closeWithError(fmt.Errorf("sync partial artifact directory: %w", err))
		}
	}
	return file, info.Size(), false, nil
}

func resetPartial(file *os.File) error {
	if err := file.Truncate(0); err != nil {
		return fmt.Errorf("truncate partial artifact: %w", err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return fmt.Errorf("seek reset partial artifact: %w", err)
	}
	if err := file.Sync(); err != nil {
		return fmt.Errorf("sync reset partial artifact: %w", err)
	}
	return nil
}

func verify(path string, size int64, digest string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("inspect downloaded artifact: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0o700 || info.Size() != size {
		return errors.New("downloaded artifact metadata does not match")
	}
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open downloaded artifact: %w", err)
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, io.LimitReader(file, size+1)); err != nil {
		return fmt.Errorf("hash downloaded artifact: %w", err)
	}
	if hex.EncodeToString(hash.Sum(nil)) != digest {
		return errors.New("downloaded artifact SHA-256 does not match")
	}
	return nil
}

func removePartial(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove invalid partial artifact: %w", err)
	}
	if err := syncDirectory(filepath.Dir(path)); err != nil {
		return fmt.Errorf("sync repaired artifact directory: %w", err)
	}
	return nil
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}
