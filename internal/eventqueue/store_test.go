package eventqueue

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	bolt "go.etcd.io/bbolt"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const testNodeID = "123e4567-e89b-42d3-a456-426614174000"

func TestQueuePersistsSequenceAndAcknowledgement(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	store, err := Open(Config{Path: path, NodeID: testNodeID, MaxBytes: 1 << 20, MaxEvents: 10})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	now := time.Now().UTC()
	first, err := store.Enqueue("system.test", now, map[string]bool{"ok": true})
	if err != nil || first.Sequence != 1 {
		t.Fatalf("first Enqueue() = %+v, %v", first, err)
	}
	before, _ := store.Info()
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	reopened, err := Open(Config{Path: path, NodeID: testNodeID, MaxBytes: 1 << 20, MaxEvents: 10})
	if err != nil {
		t.Fatalf("Open() after restart error = %v", err)
	}
	defer reopened.Close()
	second, err := reopened.Enqueue("system.test", now.Add(time.Second), map[string]bool{"ok": true})
	if err != nil || second.Sequence != 2 {
		t.Fatalf("second Enqueue() = %+v, %v", second, err)
	}
	batch, err := reopened.Batch(10, 1<<20)
	if err != nil || batch.FirstSequence != 1 || batch.LastSequence != 2 || batch.StreamID != before.StreamID {
		t.Fatalf("Batch() = %+v, %v", batch, err)
	}
	if err := reopened.Acknowledge(batch.StreamID, batch.LastSequence); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
	info, err := reopened.Info()
	if err != nil || info.PendingEvents != 0 || info.PendingBytes != 0 || info.HighestAckedSequence != 2 {
		t.Fatalf("Info() after acknowledgement = %+v, %v", info, err)
	}
	if _, err := reopened.Batch(10, 1<<20); !errors.Is(err, ErrNotFound) {
		t.Fatalf("empty Batch() error = %v", err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil || fileInfo.Mode().Perm() != 0o600 {
		t.Fatalf("event queue mode = %v, error = %v", fileInfo, err)
	}
}

func TestQueueCapacityDoesNotAdvanceSequence(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "events.db"), NodeID: testNodeID, MaxBytes: 1 << 20, MaxEvents: 1})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	now := time.Now().UTC()
	if _, err := store.Enqueue("system.test", now, map[string]bool{"ok": true}); err != nil {
		t.Fatalf("first Enqueue() error = %v", err)
	}
	if _, err := store.Enqueue("system.test", now, map[string]bool{"ok": true}); !errors.Is(err, ErrFull) {
		t.Fatalf("full Enqueue() error = %v", err)
	}
	batch, err := store.Batch(10, 1<<20)
	if err != nil || batch.LastSequence != 1 {
		t.Fatalf("Batch() after capacity error = %+v, %v", batch, err)
	}
}

func TestQueueRejectsMismatchedOrFutureAcknowledgement(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "events.db"), NodeID: testNodeID})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	event, err := store.Enqueue("system.test", time.Now().UTC(), map[string]bool{"ok": true})
	if err != nil {
		t.Fatalf("Enqueue() error = %v", err)
	}
	info, _ := store.Info()
	if err := store.Acknowledge("1123456789abcdef0123456789abcdef", event.Sequence); err == nil {
		t.Fatal("Acknowledge() accepted a different stream")
	}
	if err := store.Acknowledge(info.StreamID, event.Sequence+1); err == nil {
		t.Fatal("Acknowledge() accepted an unassigned sequence")
	}
}

func TestQueueRejectsReuseForDifferentNode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "events.db")
	store, err := Open(Config{Path: path, NodeID: testNodeID})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if _, err := Open(Config{Path: path, NodeID: "223e4567-e89b-42d3-a456-426614174000"}); err == nil {
		t.Fatal("Open() accepted an event queue owned by another node")
	}
}

func TestQueueRejectsSequenceBeyondProtocolLimit(t *testing.T) {
	store, err := Open(Config{Path: filepath.Join(t.TempDir(), "events.db"), NodeID: testNodeID})
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer store.Close()
	if err := store.db.Update(func(transaction *bolt.Tx) error {
		return putUint64(transaction.Bucket(bucketMeta), keyNextSequence, agentv1.MaximumEventSequence+1)
	}); err != nil {
		t.Fatalf("set next sequence: %v", err)
	}
	if _, err := store.Enqueue("system.test", time.Now().UTC(), map[string]bool{"ok": true}); err == nil || err.Error() != "event queue sequence is exhausted" {
		t.Fatalf("Enqueue() exhaustion error = %v", err)
	}
}
