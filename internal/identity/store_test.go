package identity

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const testCredential = "rwc_BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB"

func testIdentity() Identity {
	return Identity{
		APIVersion: agentv1.APIVersion,
		NodeID:     "123e4567-e89b-42d3-a456-426614174000",
		NodeName:   "Edge one",
		Credential: testCredential,
	}
}

func TestStoreSaveLoadAndPermissions(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "state"))
	want := testIdentity()
	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got != want {
		t.Fatalf("Load() = %+v, want %+v", got, want)
	}
	info, err := os.Stat(store.Path())
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("identity mode = %o", info.Mode().Perm())
	}
	directory, err := os.Stat(filepath.Dir(store.Path()))
	if err != nil {
		t.Fatalf("stat state directory: %v", err)
	}
	if directory.Mode().Perm() != 0o700 {
		t.Fatalf("state directory mode = %o", directory.Mode().Perm())
	}
}

func TestStoreRejectsUnsafeAndOversizedIdentity(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "state"))
	if err := store.Save(testIdentity()); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	if err := os.Chmod(store.Path(), 0o644); err != nil {
		t.Fatalf("chmod identity: %v", err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "group or others") {
		t.Fatalf("Load() permissions error = %v", err)
	}
	if err := os.WriteFile(store.Path(), make([]byte, maxIdentityBytes+1), 0o600); err != nil {
		t.Fatalf("write oversized identity: %v", err)
	}
	if err := os.Chmod(store.Path(), 0o600); err != nil {
		t.Fatalf("protect oversized identity: %v", err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("Load() size error = %v", err)
	}
}

func TestStoreRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write target: %v", err)
	}
	store := NewStore(filepath.Join(directory, "state"))
	if err := os.MkdirAll(filepath.Dir(store.Path()), 0o700); err != nil {
		t.Fatalf("create state directory: %v", err)
	}
	if err := os.Symlink(target, store.Path()); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
	if _, err := store.Load(); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("Load() symlink error = %v", err)
	}
}
