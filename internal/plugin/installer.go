package plugin

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

const maximumRedirects = 10

type hostValidator func(*url.URL) error

type installer struct {
	store      *stateStore
	httpClient *http.Client
	validate   hostValidator
}

func newInstaller(store *stateStore, client *http.Client, validate hostValidator) *installer {
	if validate == nil {
		validate = validateGitHubArtifactURL
	}
	if client == nil {
		client = &http.Client{Transport: &http.Transport{
			Proxy:           http.ProxyFromEnvironment,
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		}}
	}
	copy := *client
	priorRedirect := copy.CheckRedirect
	copy.CheckRedirect = func(request *http.Request, via []*http.Request) error {
		if len(via) >= maximumRedirects {
			return errors.New("too many artifact redirects")
		}
		if err := validate(request.URL); err != nil {
			return err
		}
		if priorRedirect != nil {
			return priorRedirect(request, via)
		}
		return nil
	}
	return &installer{store: store, httpClient: &copy, validate: validate}
}

func (value *installer) fetch(ctx context.Context, desired desiredState) (string, error) {
	if desired.Artifact == nil {
		return "", errors.New("plugin artifact is missing")
	}
	parsed, err := url.Parse(desired.DownloadURL)
	if err != nil || value.validate(parsed) != nil {
		return "", errors.New("plugin artifact URL is not allowed")
	}
	destination := value.store.releasePath(desired.PluginID, desired.Version, desired.Artifact.SHA256)
	if info, err := os.Lstat(destination); err == nil {
		if err := verifyArtifact(destination, info, desired.Artifact); err == nil {
			return destination, nil
		}
		if err := os.Remove(destination); err != nil {
			return "", fmt.Errorf("remove invalid immutable plugin artifact: %w", err)
		}
		if err := syncDirectory(filepath.Dir(destination)); err != nil {
			return "", fmt.Errorf("sync repaired plugin release directory: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect plugin artifact: %w", err)
	}
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return "", fmt.Errorf("create plugin release directory: %w", err)
	}
	if err := os.Chmod(filepath.Dir(filepath.Dir(destination)), 0o700); err != nil {
		return "", fmt.Errorf("protect plugin release root: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return "", fmt.Errorf("protect plugin release directory: %w", err)
	}
	for _, durableDirectory := range []string{value.store.releasesDir, filepath.Dir(directory), directory} {
		if err := syncDirectory(durableDirectory); err != nil {
			return "", fmt.Errorf("sync plugin release directory: %w", err)
		}
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, desired.DownloadURL, nil)
	if err != nil {
		return "", errors.New("create plugin artifact request")
	}
	request.Header.Set("Accept", "application/octet-stream")
	response, err := value.httpClient.Do(request)
	if err != nil {
		return "", fmt.Errorf("download plugin artifact: %w", err)
	}
	defer response.Body.Close()
	if err := value.validate(response.Request.URL); err != nil {
		return "", errors.New("plugin artifact response URL is not allowed")
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("plugin artifact endpoint returned HTTP %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != desired.Artifact.Size {
		return "", errors.New("plugin artifact content length does not match")
	}

	temporary, err := os.CreateTemp(directory, ".artifact-*")
	if err != nil {
		return "", fmt.Errorf("create plugin artifact temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o700); err != nil {
		temporary.Close()
		return "", fmt.Errorf("protect plugin artifact temporary file: %w", err)
	}
	hash := sha256.New()
	written, copyErr := io.Copy(io.MultiWriter(temporary, hash), io.LimitReader(response.Body, desired.Artifact.Size+1))
	if copyErr != nil {
		temporary.Close()
		return "", errors.New("read plugin artifact")
	}
	if written != desired.Artifact.Size {
		temporary.Close()
		return "", errors.New("plugin artifact size does not match")
	}
	if actual := hex.EncodeToString(hash.Sum(nil)); actual != desired.Artifact.SHA256 {
		temporary.Close()
		return "", errors.New("plugin artifact SHA-256 does not match")
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return "", fmt.Errorf("sync plugin artifact: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return "", fmt.Errorf("close plugin artifact: %w", err)
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return "", fmt.Errorf("activate immutable plugin artifact: %w", err)
	}
	if err := syncDirectory(directory); err != nil {
		return "", fmt.Errorf("sync plugin release directory: %w", err)
	}
	return destination, nil
}

func verifyArtifact(path string, info os.FileInfo, expected *artifactState) error {
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Mode().Perm()&0o100 == 0 {
		return errors.New("artifact must be a private executable regular file")
	}
	if info.Size() != expected.Size {
		return errors.New("artifact size does not match")
	}
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return err
	}
	if hex.EncodeToString(hash.Sum(nil)) != expected.SHA256 {
		return errors.New("artifact SHA-256 does not match")
	}
	return nil
}

func validateGitHubArtifactURL(value *url.URL) error {
	if value == nil || value.Scheme != "https" || value.User != nil || value.Fragment != "" || value.Hostname() == "" {
		return errors.New("artifact URL must be HTTPS without credentials or a fragment")
	}
	if port := value.Port(); port != "" && port != "443" {
		return errors.New("artifact URL must use the HTTPS default port")
	}
	host := strings.ToLower(value.Hostname())
	switch host {
	case "github.com", "api.github.com", "objects.githubusercontent.com", "objects-origin.githubusercontent.com",
		"github-releases.githubusercontent.com", "github-registry-files.githubusercontent.com", "release-assets.githubusercontent.com":
		return nil
	default:
		return errors.New("artifact URL host is not a GitHub release host")
	}
}
