package download

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestFetchResumesInterruptedDownload(t *testing.T) {
	raw := []byte("durable artifact download")
	firstLength := 9
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if requests == 1 {
			writer.Header().Set("Content-Length", fmt.Sprint(len(raw)))
			_, _ = writer.Write(raw[:firstLength])
			return
		}
		if got, want := request.Header.Get("Range"), fmt.Sprintf("bytes=%d-", firstLength); got != want {
			t.Errorf("Range = %q, want %q", got, want)
		}
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", firstLength, len(raw)-1, len(raw)))
		writer.Header().Set("Content-Length", fmt.Sprint(len(raw)-firstLength))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(raw[firstLength:])
	}))
	defer server.Close()

	path := filepath.Join(t.TempDir(), "artifact.partial")
	artifact := Artifact{URL: server.URL, Path: path, Size: int64(len(raw)), SHA256: checksum(raw)}
	if err := Fetch(context.Background(), server.Client(), artifact); err == nil {
		t.Fatal("Fetch() succeeded after an interrupted response")
	}
	assertFile(t, path, raw[:firstLength], 0o700)
	if err := Fetch(context.Background(), server.Client(), artifact); err != nil {
		t.Fatalf("resumed Fetch() error = %v", err)
	}
	assertFile(t, path, raw, 0o700)
	if requests != 2 {
		t.Fatalf("requests = %d, want 2", requests)
	}
}

func TestFetchRestartsWhenServerIgnoresRange(t *testing.T) {
	raw := []byte("complete artifact")
	prefix := raw[:5]
	path := filepath.Join(t.TempDir(), "artifact.partial")
	if err := os.WriteFile(path, prefix, 0o600); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got, want := request.Header.Get("Range"), fmt.Sprintf("bytes=%d-", len(prefix)); got != want {
			t.Errorf("Range = %q, want %q", got, want)
		}
		_, _ = writer.Write(raw)
	}))
	defer server.Close()

	artifact := Artifact{URL: server.URL, Path: path, Size: int64(len(raw)), SHA256: checksum(raw)}
	if err := Fetch(context.Background(), server.Client(), artifact); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	assertFile(t, path, raw, 0o700)
}

func TestFetchRejectsWrongRangeWithoutChangingPartial(t *testing.T) {
	raw := []byte("complete artifact")
	prefix := raw[:5]
	path := filepath.Join(t.TempDir(), "artifact.partial")
	if err := os.WriteFile(path, prefix, 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", len(prefix)+1, len(raw)-1, len(raw)))
		writer.WriteHeader(http.StatusPartialContent)
		_, _ = writer.Write(raw[len(prefix):])
	}))
	defer server.Close()

	artifact := Artifact{URL: server.URL, Path: path, Size: int64(len(raw)), SHA256: checksum(raw)}
	if err := Fetch(context.Background(), server.Client(), artifact); err == nil {
		t.Fatal("Fetch() accepted the wrong Content-Range")
	}
	assertFile(t, path, prefix, 0o700)
}

func TestFetchResetsCompleteArtifactWithWrongChecksum(t *testing.T) {
	raw := []byte("expected artifact")
	path := filepath.Join(t.TempDir(), "artifact.partial")
	if err := os.WriteFile(path, bytes.Repeat([]byte("x"), len(raw)), 0o700); err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if got := request.Header.Get("Range"); got != "" {
			t.Errorf("Range = %q after invalid complete partial was reset", got)
		}
		_, _ = writer.Write(raw)
	}))
	defer server.Close()

	artifact := Artifact{URL: server.URL, Path: path, Size: int64(len(raw)), SHA256: checksum(raw)}
	if err := Fetch(context.Background(), server.Client(), artifact); err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	assertFile(t, path, raw, 0o700)
}

func assertFile(t *testing.T, path string, want []byte, mode os.FileMode) {
	t.Helper()
	actual, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	if !bytes.Equal(actual, want) {
		t.Fatalf("file contents = %q, want %q", actual, want)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat %s: %v", path, err)
	}
	if info.Mode().Perm() != mode {
		t.Fatalf("file mode = %#o, want %#o", info.Mode().Perm(), mode)
	}
}

func checksum(value []byte) string {
	digest := sha256.Sum256(value)
	return hex.EncodeToString(digest[:])
}
