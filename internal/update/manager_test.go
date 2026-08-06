package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const testRuntimeAssetsDigest = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"

func TestManagerUsesDedicatedReleaseDownloadTimeout(t *testing.T) {
	manager, err := NewManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if manager.httpClient.Timeout != releaseDownloadTimeout {
		t.Fatalf("release HTTP timeout = %s, want %s", manager.httpClient.Timeout, releaseDownloadTimeout)
	}
	if releaseDownloadTimeout <= HealthTimeout {
		t.Fatalf("release download timeout = %s, health timeout = %s", releaseDownloadTimeout, HealthTimeout)
	}
	if releaseDownloadTimeout >= agentv1.MaximumCommandExecution {
		t.Fatalf("release download timeout = %s, command execution limit = %s", releaseDownloadTimeout, agentv1.MaximumCommandExecution)
	}
}

func TestManagerPreparesConfirmsAndReusesImmutableRelease(t *testing.T) {
	binary := []byte("relayward-agent-v0.2.0")
	manager, stateDirectory := testReleaseManager(t, "0.2.0", binary)
	prepared, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0")
	if err != nil || !prepared.Restart || prepared.Activated || prepared.Version != "0.2.0" {
		t.Fatalf("Prepare() = %+v, %v", prepared, err)
	}
	wantTarget := filepath.Join("versions", "0.2.0-"+digest(binary), "relayward-agent")
	current, err := os.Readlink(filepath.Join(stateDirectory, "current"))
	if err != nil || current != wantTarget {
		t.Fatalf("current target = %q, %v", current, err)
	}
	previous, err := os.Readlink(filepath.Join(stateDirectory, "previous"))
	if err != nil || previous != "versions/0.1.0-bootstrap/relayward-agent" {
		t.Fatalf("previous target = %q, %v", previous, err)
	}
	pending, err := manager.Pending()
	if err != nil || pending.CommandID != "command-1" || pending.TargetTarget != wantTarget {
		t.Fatalf("Pending() = %+v, %v", pending, err)
	}
	if confirmed, err := manager.Confirm("0.1.0"); err == nil || confirmed {
		t.Fatalf("Confirm() accepted wrong running version: confirmed=%v error=%v", confirmed, err)
	}
	if confirmed, err := manager.Confirm("0.2.0"); err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	if err := manager.Observe("command-1", "0.2.0", "0.2.0"); err != nil {
		t.Fatalf("Observe() confirmed error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, pendingFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state after confirmation error = %v", err)
	}

	second, err := manager.Prepare(context.Background(), "command-2", "0.2.0", "0.2.0")
	if err != nil || second.Restart || !second.Activated {
		t.Fatalf("Prepare() already active = %+v, %v", second, err)
	}
	if err := manager.Observe("command-2", "0.2.0", "0.2.0"); err != nil {
		t.Fatalf("Observe() second confirmed error = %v", err)
	}
}

func TestManagerRejectsReleaseMismatchWithoutSwitching(t *testing.T) {
	tests := []struct {
		name       string
		mutate     func(*Manager, *Manifest)
		marker     string
		wantPhrase string
	}{
		{name: "runtime assets", marker: strings.Repeat("b", 64), wantPhrase: "runtime assets"},
		{name: "candidate version", marker: testRuntimeAssetsDigest, mutate: func(manager *Manager, _ *Manifest) {
			manager.runCandidateVersion = func(context.Context, string) (string, error) { return "0.3.0", nil }
		}, wantPhrase: "reports version"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			binary := []byte("candidate")
			manifest := testManifest("0.2.0", binary)
			manager, stateDirectory := testManagerWithManifest(t, manifest, binary, test.marker)
			if test.mutate != nil {
				test.mutate(manager, &manifest)
			}
			if _, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0"); err == nil || !strings.Contains(err.Error(), test.wantPhrase) {
				t.Fatalf("Prepare() error = %v", err)
			}
			current, _ := os.Readlink(filepath.Join(stateDirectory, "current"))
			if current != "versions/0.1.0-bootstrap/relayward-agent" {
				t.Fatalf("current target changed to %q", current)
			}
			if _, err := manager.Pending(); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("pending state after rejection error = %v", err)
			}
		})
	}
}

func TestManagerRejectsChecksumAndOversizedManifest(t *testing.T) {
	binary := []byte("candidate")
	manifest := testManifest("0.2.0", binary)
	manifest.Artifact.SHA256 = strings.Repeat("b", 64)
	manager, stateDirectory := testManagerWithManifest(t, manifest, binary, testRuntimeAssetsDigest)
	if _, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0"); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Prepare() checksum error = %v", err)
	}
	current, _ := os.Readlink(filepath.Join(stateDirectory, "current"))
	if current != "versions/0.1.0-bootstrap/relayward-agent" {
		t.Fatalf("current target changed to %q", current)
	}

	oversized := bytes.Repeat([]byte(" "), MaximumManifestBytes+1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) { _, _ = writer.Write(oversized) }))
	defer server.Close()
	stateDirectory, marker := setupManagedState(t, testRuntimeAssetsDigest)
	manager, err := newManager(stateDirectory, marker, server.URL, releaseRepository, true, server.Client())
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	if _, err := manager.Prepare(context.Background(), "command-2", "0.2.0", "0.1.0"); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Prepare() oversized manifest error = %v", err)
	}
}

func TestManagerDetectsFailedAndConflictingDurableState(t *testing.T) {
	manager, stateDirectory := testReleaseManager(t, "0.2.0", []byte("candidate"))
	if _, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0"); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := os.Rename(filepath.Join(stateDirectory, pendingFilename), filepath.Join(stateDirectory, failedFilename)); err != nil {
		t.Fatalf("record failed state: %v", err)
	}
	if err := manager.Observe("command-1", "0.2.0", "0.1.0"); !errors.Is(err, ErrActivationFailed) {
		t.Fatalf("Observe() failed state error = %v", err)
	}
	if err := manager.Observe("different-command", "0.3.0", "0.1.0"); !errors.Is(err, ErrStateNotFound) {
		t.Fatalf("Observe() stale terminal state error = %v", err)
	}

	state, err := manager.readState(filepath.Join(stateDirectory, failedFilename))
	if err != nil {
		t.Fatalf("read failed state: %v", err)
	}
	state.CommandID = "other-command"
	if err := writeJSONAtomic(filepath.Join(stateDirectory, pendingFilename), state, 0o600); err != nil {
		t.Fatalf("write conflicting pending state: %v", err)
	}
	if err := manager.Observe("command-1", "0.2.0", "0.1.0"); !errors.Is(err, ErrUpdateStateConflict) {
		t.Fatalf("Observe() conflicting pending state error = %v", err)
	}
}

func TestManagerAwaitsCandidateHealthConfirmation(t *testing.T) {
	manager, _ := testReleaseManager(t, "0.2.0", []byte("candidate"))
	if _, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0"); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- manager.AwaitActivation(context.Background(), "0.2.0") }()
	select {
	case err := <-done:
		t.Fatalf("AwaitActivation() returned before confirmation: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	if confirmed, err := manager.Confirm("0.2.0"); err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("AwaitActivation() error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("AwaitActivation() did not observe confirmation")
	}
}

func TestManagerRejectsExpiredCandidateActivation(t *testing.T) {
	manager, _ := testReleaseManager(t, "0.2.0", []byte("candidate"))
	manager.now = func() time.Time { return time.Now().UTC().Add(-HealthTimeout - time.Minute) }
	if _, err := manager.Prepare(context.Background(), "command-1", "0.2.0", "0.1.0"); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	manager.now = func() time.Time { return time.Now().UTC() }
	if err := manager.AwaitActivation(context.Background(), "0.2.0"); !errors.Is(err, ErrActivationTimeout) {
		t.Fatalf("AwaitActivation() error = %v", err)
	}
}

func TestManagerPruneProtectsRequestedInstalledTarget(t *testing.T) {
	manager, stateDirectory := testReleaseManager(t, "0.2.0", []byte("candidate"))
	target := filepath.Join("versions", "0.2.0-"+digest([]byte("candidate")), "relayward-agent")
	targetDirectory := filepath.Dir(filepath.Join(stateDirectory, target))
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		t.Fatalf("create target directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDirectory, target), []byte("candidate"), 0o700); err != nil {
		t.Fatalf("write target binary: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(targetDirectory, old, old); err != nil {
		t.Fatalf("age target directory: %v", err)
	}
	for index := 0; index < retainedVersions+1; index++ {
		directory := filepath.Join(stateDirectory, "versions", fmt.Sprintf("newer-%d", index))
		if err := os.MkdirAll(directory, 0o700); err != nil {
			t.Fatalf("create newer directory: %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "relayward-agent"), []byte("newer"), 0o700); err != nil {
			t.Fatalf("write newer binary: %v", err)
		}
	}
	if err := manager.pruneVersions(target); err != nil {
		t.Fatalf("pruneVersions() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(stateDirectory, target)); err != nil {
		t.Fatalf("requested installed target was pruned: %v", err)
	}
}

func testReleaseManager(t *testing.T, version string, binary []byte) (*Manager, string) {
	t.Helper()
	return testManagerWithManifest(t, testManifest(version, binary), binary, testRuntimeAssetsDigest)
}

func testManagerWithManifest(t *testing.T, manifest Manifest, binary []byte, markerValue string) (*Manager, string) {
	t.Helper()
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	assets := map[string][]byte{
		"/" + releaseRepository + "/releases/download/v" + manifest.Version + "/" + ManifestAssetName: manifestRaw,
		"/" + releaseRepository + "/releases/download/v" + manifest.Version + "/" + BinaryAssetName:   binary,
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		value, exists := assets[request.URL.Path]
		if !exists {
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(value)
	}))
	t.Cleanup(server.Close)
	stateDirectory, marker := setupManagedState(t, markerValue)
	manager, err := newManager(stateDirectory, marker, server.URL, releaseRepository, true, server.Client())
	if err != nil {
		t.Fatalf("newManager() error = %v", err)
	}
	manager.runCandidateVersion = func(context.Context, string) (string, error) { return manifest.Version, nil }
	return manager, stateDirectory
}

func setupManagedState(t *testing.T, markerValue string) (string, string) {
	t.Helper()
	stateDirectory := filepath.Join(t.TempDir(), "state")
	bootstrapDirectory := filepath.Join(stateDirectory, "versions", "0.1.0-bootstrap")
	if err := os.MkdirAll(bootstrapDirectory, 0o700); err != nil {
		t.Fatalf("create bootstrap directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bootstrapDirectory, "relayward-agent"), []byte("bootstrap"), 0o700); err != nil {
		t.Fatalf("write bootstrap binary: %v", err)
	}
	if err := os.Symlink("versions/0.1.0-bootstrap/relayward-agent", filepath.Join(stateDirectory, "current")); err != nil {
		t.Fatalf("create current link: %v", err)
	}
	marker := filepath.Join(t.TempDir(), "runtime-assets.sha256")
	if err := os.WriteFile(marker, []byte(markerValue+"\n"), 0o600); err != nil {
		t.Fatalf("write runtime assets marker: %v", err)
	}
	return stateDirectory, marker
}

func testManifest(version string, binary []byte) Manifest {
	return Manifest{
		APIVersion: ManifestAPIVersion, Version: version,
		PublishedAt:         time.Date(2026, time.August, 2, 10, 0, 0, 0, time.UTC),
		RuntimeAssetsSHA256: testRuntimeAssetsDigest,
		Artifact:            Artifact{File: BinaryAssetName, OS: "linux", Arch: "amd64", Size: int64(len(binary)), SHA256: digest(binary)},
	}
}

func digest(value []byte) string {
	sum := sha256.Sum256(value)
	return hex.EncodeToString(sum[:])
}
