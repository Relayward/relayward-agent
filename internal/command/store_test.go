package command

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

func TestStorePersistsCommandResultAndAcknowledgement(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	now := time.Date(2026, time.August, 2, 8, 0, 0, 0, time.UTC)
	command := testCommand(now)
	created, err := store.Accept("command-1", command, now)
	if err != nil || !created {
		t.Fatalf("Accept() created = %v, error = %v", created, err)
	}
	created, err = store.Accept("command-1", command, now.Add(time.Second))
	if err != nil || created {
		t.Fatalf("duplicate Accept() created = %v, error = %v", created, err)
	}
	changed := command
	changed.Payload = json.RawMessage(`{"value":2}`)
	if _, err := store.Accept("command-1", changed, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Accept() error = %v", err)
	}
	pending, err := store.NextPending()
	if err != nil || pending.CommandID != "command-1" {
		t.Fatalf("NextPending() = %+v, %v", pending, err)
	}
	result := agentv1.CommandResult{
		CommandID: pending.CommandID, RequestSHA256: pending.RequestSHA256, Status: agentv1.CommandStatusSucceeded,
		CompletedAt: now.Add(time.Minute), Output: json.RawMessage(`{"applied":true}`),
	}
	if err := store.Complete(pending.CommandID, pending.RequestSHA256, result, result.CompletedAt); err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if err := store.Complete(pending.CommandID, pending.RequestSHA256, result, result.CompletedAt); err != nil {
		t.Fatalf("duplicate Complete() error = %v", err)
	}
	different := result
	different.Output = json.RawMessage(`{"applied":false}`)
	if err := store.Complete(pending.CommandID, pending.RequestSHA256, different, different.CompletedAt); !errors.Is(err, ErrConflict) {
		t.Fatalf("conflicting Complete() error = %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, "commands", "command-1.json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("command state mode = %v, error = %v", info, err)
	}

	reopened, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() after completion error = %v", err)
	}
	storedResult, err := reopened.NextResult()
	if err != nil || !commandResultsEqual(storedResult, result) {
		t.Fatalf("NextResult() = %+v, %v", storedResult, err)
	}
	acknowledgedAt := now.Add(2 * time.Minute)
	if err := reopened.Acknowledge(pending.CommandID, pending.RequestSHA256, acknowledgedAt); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
	if err := reopened.Acknowledge(pending.CommandID, pending.RequestSHA256, acknowledgedAt.Add(time.Second)); err != nil {
		t.Fatalf("duplicate Acknowledge() error = %v", err)
	}
	finalStore, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() after acknowledgement error = %v", err)
	}
	if _, err := finalStore.NextResult(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("NextResult() after acknowledgement error = %v", err)
	}
	if err := finalStore.Cleanup(acknowledgedAt.Add(acknowledgedRetention)); err != nil {
		t.Fatalf("Cleanup() error = %v", err)
	}
	if _, err := os.Stat(filepath.Join(directory, "commands", "command-1.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("acknowledged command remains after retention: %v", err)
	}
}

func TestOpenStoreRejectsInsecureOrCorruptState(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	now := time.Now().UTC()
	if _, err := store.Accept("command-1", testCommand(now), now); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	path := filepath.Join(directory, "commands", "command-1.json")
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatalf("chmod command state: %v", err)
	}
	if _, err := OpenStore(directory); err == nil {
		t.Fatal("OpenStore() accepted group-readable command state")
	}
}

func testCommand(now time.Time) agentv1.Command {
	return agentv1.Command{
		Kind: "agent.test", IssuedAt: now, ExpiresAt: now.Add(time.Hour), Payload: json.RawMessage(`{"value":1}`),
	}
}
