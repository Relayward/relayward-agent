package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

func TestInstallerDownloadsAndRevalidatesImmutableArtifact(t *testing.T) {
	raw := []byte("executable plugin artifact")
	digest := sha256.Sum256(raw)
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		if request.URL.Path == "/start" {
			http.Redirect(writer, request, "/artifact", http.StatusFound)
			return
		}
		_, _ = writer.Write(raw)
	}))
	defer server.Close()
	allowed, _ := url.Parse(server.URL)
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	value := newInstaller(store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != allowed.Host || candidate.Scheme != "https" {
			return &url.Error{Op: "validate", URL: "redacted", Err: io.EOF}
		}
		return nil
	})
	desired, err := normalizeDesired(testArtifactCommand(server.URL+"/start", int64(len(raw)), hex.EncodeToString(digest[:])))
	if err != nil {
		t.Fatal(err)
	}
	path, err := value.fetch(context.Background(), desired)
	if err != nil {
		t.Fatalf("fetch() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("artifact mode = %v, error = %v", info.Mode().Perm(), err)
	}
	if requests != 2 {
		t.Fatalf("artifact requests = %d, want redirect plus artifact", requests)
	}
	if _, err := value.fetch(context.Background(), desired); err != nil || requests != 2 {
		t.Fatalf("cached fetch error = %v, requests = %d", err, requests)
	}
	if err := os.WriteFile(path, []byte("corrupt"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := value.fetch(context.Background(), desired); err != nil || requests != 4 {
		t.Fatalf("corrupt cached repair error = %v, requests = %d", err, requests)
	}
	repaired, err := os.ReadFile(path)
	if err != nil || string(repaired) != string(raw) {
		t.Fatalf("repaired artifact = %q, error = %v", repaired, err)
	}
}

func TestInstallerRejectsUnapprovedRedirectBeforeConnecting(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		http.Redirect(writer, request, "https://example.invalid/artifact", http.StatusFound)
	}))
	defer server.Close()
	allowed, _ := url.Parse(server.URL)
	store, _ := openStateStore(filepath.Join(t.TempDir(), "state"))
	value := newInstaller(store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != allowed.Host {
			return io.EOF
		}
		return nil
	})
	raw := []byte("artifact")
	digest := sha256.Sum256(raw)
	desired, _ := normalizeDesired(testArtifactCommand(server.URL, int64(len(raw)), hex.EncodeToString(digest[:])))
	if _, err := value.fetch(context.Background(), desired); err == nil {
		t.Fatal("fetch() followed an unapproved redirect")
	}
}

func TestInstallerRetainsAndResumesPartialArtifact(t *testing.T) {
	raw := []byte("resumable plugin artifact")
	firstLength := 8
	requests := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
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

	allowed, _ := url.Parse(server.URL)
	store, err := openStateStore(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	value := newInstaller(store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != allowed.Host || candidate.Scheme != "https" {
			return io.EOF
		}
		return nil
	})
	hash := sha256.Sum256(raw)
	desired, err := normalizeDesired(testArtifactCommand(server.URL, int64(len(raw)), hex.EncodeToString(hash[:])))
	if err != nil {
		t.Fatal(err)
	}
	destination := store.releasePath(desired.PluginID, desired.Version, desired.Artifact.SHA256)
	if _, err := value.fetch(context.Background(), desired); err == nil {
		t.Fatal("fetch() succeeded after an interrupted response")
	}
	partial, err := os.ReadFile(destination + ".partial")
	if err != nil || string(partial) != string(raw[:firstLength]) {
		t.Fatalf("partial artifact = %q, error = %v", partial, err)
	}
	path, err := value.fetch(context.Background(), desired)
	if err != nil {
		t.Fatalf("resumed fetch() error = %v", err)
	}
	if path != destination {
		t.Fatalf("artifact path = %q, want %q", path, destination)
	}
	installed, err := os.ReadFile(destination)
	if err != nil || string(installed) != string(raw) {
		t.Fatalf("installed artifact = %q, error = %v", installed, err)
	}
	if _, err := os.Stat(destination + ".partial"); !os.IsNotExist(err) {
		t.Fatalf("partial artifact remains after activation: %v", err)
	}
}

func TestGitHubArtifactURLAllowlist(t *testing.T) {
	for _, raw := range []string{
		"https://github.com/Relayward/plugin/releases/download/v1/plugin",
		"https://release-assets.githubusercontent.com/github-production-release-asset/file?sp=r",
		"https://objects.githubusercontent.com/github-production-release-asset/file",
	} {
		parsed, _ := url.Parse(raw)
		if err := validateGitHubArtifactURL(parsed); err != nil {
			t.Errorf("validateGitHubArtifactURL(%q) error = %v", raw, err)
		}
	}
	for _, raw := range []string{
		"http://github.com/Relayward/plugin",
		"https://github.com.evil.invalid/plugin",
		"https://raw.githubusercontent.com/Relayward/plugin/main/file",
		"https://token@github.com/Relayward/plugin",
		"https://github.com:8443/Relayward/plugin",
		"https://github.com/Relayward/plugin#fragment",
	} {
		parsed, _ := url.Parse(raw)
		if err := validateGitHubArtifactURL(parsed); err == nil {
			t.Errorf("validateGitHubArtifactURL(%q) succeeded", raw)
		}
	}
}

func testArtifactCommand(downloadURL string, size int64, digest string) agentv1.PluginReconcileCommand {
	return agentv1.PluginReconcileCommand{
		PluginID: "io.relayward.test", Generation: 1, DesiredState: agentv1.PluginStateRunning,
		Version: "1.2.3", Artifact: &agentv1.PluginArtifact{DownloadURL: downloadURL, Size: size, SHA256: digest},
		Configuration: json.RawMessage(`{}`),
	}
}
