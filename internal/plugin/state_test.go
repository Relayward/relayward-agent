package plugin

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

func TestStateStorePersistsMonotonicDesiredAndCommittedState(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	store, err := openStateStore(stateDirectory)
	if err != nil {
		t.Fatalf("openStateStore() error = %v", err)
	}
	first := testDesiredCommand(1, agentv1.PluginStateRunning, json.RawMessage(`{ "enabled": true }`))
	desired, current, alreadyCurrent, err := store.prepare(first)
	if err != nil || current != nil || alreadyCurrent {
		t.Fatalf("prepare(first) = %+v, %+v, %v, %v", desired, current, alreadyCurrent, err)
	}
	if string(desired.Configuration) != `{"enabled":true}` {
		t.Fatalf("normalized configuration = %s", desired.Configuration)
	}
	if _, err := store.commit(desired); err != nil {
		t.Fatalf("commit(first) error = %v", err)
	}
	info, err := os.Stat(store.statePath(first.PluginID))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("state file mode = %v, error = %v", info.Mode().Perm(), err)
	}

	reopened, err := openStateStore(stateDirectory)
	if err != nil {
		t.Fatalf("reopen state store: %v", err)
	}
	replay := first
	replay.Artifact.DownloadURL = "https://release-assets.githubusercontent.com/refreshed"
	_, current, alreadyCurrent, err = reopened.prepare(replay)
	if err != nil || !alreadyCurrent || current == nil || current.Generation != 1 {
		t.Fatalf("prepare(replay) current = %+v, already = %v, error = %v", current, alreadyCurrent, err)
	}

	stale := testDesiredCommand(1, agentv1.PluginStateStopped, json.RawMessage(`{"enabled":true}`))
	if _, _, _, err := reopened.prepare(stale); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("same generation conflict = %v", err)
	}
	second := testDesiredCommand(2, agentv1.PluginStateStopped, json.RawMessage(`{"enabled":false}`))
	pending, previous, _, err := reopened.prepare(second)
	if err != nil || previous == nil || previous.Generation != 1 {
		t.Fatalf("prepare(second) previous = %+v, error = %v", previous, err)
	}
	refreshed := second
	refreshed.Artifact.DownloadURL = "https://release-assets.githubusercontent.com/new-token"
	if _, _, _, err := reopened.prepare(refreshed); err != nil {
		t.Fatalf("refresh pending URL error = %v", err)
	}
	if _, err := reopened.commit(pending); err != nil {
		t.Fatalf("commit(second) error = %v", err)
	}
	if _, _, _, err := reopened.prepare(first); !errors.Is(err, ErrStaleGeneration) {
		t.Fatalf("stale generation error = %v", err)
	}
}

func TestStateStoreRejectsExposedStateFile(t *testing.T) {
	stateDirectory := filepath.Join(t.TempDir(), "state")
	store, err := openStateStore(stateDirectory)
	if err != nil {
		t.Fatal(err)
	}
	desired, _, _, err := store.prepare(testDesiredCommand(1, agentv1.PluginStateRunning, json.RawMessage(`{}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(store.statePath(desired.PluginID), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := openStateStore(stateDirectory); err == nil {
		t.Fatal("openStateStore() accepted a group-readable state file")
	}
}

func testDesiredCommand(generation uint64, state string, configuration json.RawMessage) agentv1.PluginReconcileCommand {
	return agentv1.PluginReconcileCommand{
		PluginID: "io.relayward.test", Generation: generation, DesiredState: state, Version: "1.2.3",
		Artifact: &agentv1.PluginArtifact{
			DownloadURL: "https://github.com/Relayward/test/releases/download/v1.2.3/plugin",
			Size:        123, SHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		Configuration: configuration,
	}
}
