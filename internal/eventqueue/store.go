package eventqueue

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"
)

const (
	DefaultMaxBytes  = 64 << 20
	DefaultMaxEvents = 100000
)

var ErrFull = errors.New("event queue capacity reached")
var ErrNotFound = errors.New("event queue is empty")

var (
	bucketMeta       = []byte("meta")
	bucketEvents     = []byte("events")
	keyNodeID        = []byte("node-id")
	keyStreamID      = []byte("stream-id")
	keyNextSequence  = []byte("next-sequence")
	keyAckedSequence = []byte("acked-sequence")
	keyPendingBytes  = []byte("pending-bytes")
	keyPendingEvents = []byte("pending-events")
)

type Config struct {
	Path      string
	NodeID    string
	MaxBytes  uint64
	MaxEvents uint64
}

type Info struct {
	StreamID             string
	PendingEvents        uint64
	PendingBytes         uint64
	HighestAckedSequence uint64
	OldestObservedAt     *time.Time
}

type Store struct {
	db        *bolt.DB
	nodeID    string
	maxBytes  uint64
	maxEvents uint64
	notify    chan struct{}
}

func Open(config Config) (*Store, error) {
	if err := agentv1.ValidateNodeID(config.NodeID); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.Path) || filepath.Clean(config.Path) != config.Path {
		return nil, errors.New("event queue path must be absolute and clean")
	}
	if config.MaxBytes == 0 {
		config.MaxBytes = DefaultMaxBytes
	}
	if config.MaxEvents == 0 {
		config.MaxEvents = DefaultMaxEvents
	}
	directory := filepath.Dir(config.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create event queue directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect event queue directory: %w", err)
	}
	database, err := bolt.Open(config.Path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		return nil, fmt.Errorf("open event queue: %w", err)
	}
	if err := os.Chmod(config.Path, 0o600); err != nil {
		database.Close()
		return nil, fmt.Errorf("protect event queue: %w", err)
	}
	store := &Store{
		db: database, nodeID: config.NodeID, maxBytes: config.MaxBytes, maxEvents: config.MaxEvents,
		notify: make(chan struct{}, 1),
	}
	if err := store.initialize(); err != nil {
		database.Close()
		return nil, err
	}
	return store, nil
}

func (store *Store) Close() error {
	if store == nil || store.db == nil {
		return nil
	}
	return store.db.Close()
}

func (store *Store) Enqueue(kind string, observedAt time.Time, payload any) (agentv1.Event, error) {
	var event agentv1.Event
	err := store.db.Update(func(transaction *bolt.Tx) error {
		meta := transaction.Bucket(bucketMeta)
		streamID := string(meta.Get(keyStreamID))
		sequence := readUint64(meta.Get(keyNextSequence))
		if sequence > agentv1.MaximumEventSequence {
			return errors.New("event queue sequence is exhausted")
		}
		value, err := agentv1.NewEvent(store.nodeID, streamID, sequence, kind, observedAt, payload)
		if err != nil {
			return err
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("encode queued event: %w", err)
		}
		pendingBytes := readUint64(meta.Get(keyPendingBytes))
		pendingEvents := readUint64(meta.Get(keyPendingEvents))
		eventBytes := uint64(len(raw))
		if eventBytes > store.maxBytes || pendingBytes > store.maxBytes-eventBytes || pendingEvents >= store.maxEvents {
			return ErrFull
		}
		if err := transaction.Bucket(bucketEvents).Put(sequenceKey(sequence), raw); err != nil {
			return err
		}
		if err := putUint64(meta, keyNextSequence, sequence+1); err != nil {
			return err
		}
		if err := putUint64(meta, keyPendingBytes, pendingBytes+uint64(len(raw))); err != nil {
			return err
		}
		if err := putUint64(meta, keyPendingEvents, pendingEvents+1); err != nil {
			return err
		}
		event = value
		return nil
	})
	if err != nil {
		return agentv1.Event{}, err
	}
	store.signal()
	return event, nil
}

func (store *Store) Batch(maxEvents, maxBytes int) (agentv1.EventBatch, error) {
	if maxEvents <= 0 || maxEvents > agentv1.MaximumEventBatchEvents {
		maxEvents = agentv1.MaximumEventBatchEvents
	}
	if maxBytes <= 0 || maxBytes > agentv1.MaximumEventBatchExpandedBytes {
		maxBytes = agentv1.MaximumEventBatchExpandedBytes
	}
	batch := agentv1.EventBatch{APIVersion: agentv1.APIVersion, NodeID: store.nodeID}
	err := store.db.View(func(transaction *bolt.Tx) error {
		batch.StreamID = string(transaction.Bucket(bucketMeta).Get(keyStreamID))
		cursor := transaction.Bucket(bucketEvents).Cursor()
		total := 0
		for _, raw := cursor.First(); raw != nil && len(batch.Events) < maxEvents; _, raw = cursor.Next() {
			if total+len(raw) > maxBytes && len(batch.Events) > 0 {
				break
			}
			var event agentv1.Event
			if err := json.Unmarshal(raw, &event); err != nil {
				return fmt.Errorf("decode queued event: %w", err)
			}
			batch.Events = append(batch.Events, event)
			total += len(raw)
		}
		return nil
	})
	if err != nil {
		return agentv1.EventBatch{}, err
	}
	if len(batch.Events) == 0 {
		return batch, ErrNotFound
	}
	batch.FirstSequence = batch.Events[0].Sequence
	batch.LastSequence = batch.Events[len(batch.Events)-1].Sequence
	if err := agentv1.ValidateEventBatch(batch); err != nil {
		return agentv1.EventBatch{}, fmt.Errorf("validate queued event batch: %w", err)
	}
	return batch, nil
}

func (store *Store) Acknowledge(streamID string, sequence uint64) error {
	return store.db.Update(func(transaction *bolt.Tx) error {
		meta := transaction.Bucket(bucketMeta)
		if streamID != string(meta.Get(keyStreamID)) {
			return errors.New("event acknowledgement stream does not match")
		}
		next := readUint64(meta.Get(keyNextSequence))
		if sequence == 0 || sequence >= next {
			return errors.New("event acknowledgement exceeds assigned sequence")
		}
		acked := readUint64(meta.Get(keyAckedSequence))
		if sequence <= acked {
			return nil
		}
		pendingBytes := readUint64(meta.Get(keyPendingBytes))
		pendingEvents := readUint64(meta.Get(keyPendingEvents))
		cursor := transaction.Bucket(bucketEvents).Cursor()
		for key, raw := cursor.First(); key != nil && readUint64(key) <= sequence; key, raw = cursor.Next() {
			if uint64(len(raw)) > pendingBytes || pendingEvents == 0 {
				return errors.New("event queue accounting is inconsistent")
			}
			pendingBytes -= uint64(len(raw))
			pendingEvents--
			if err := cursor.Delete(); err != nil {
				return err
			}
		}
		if err := putUint64(meta, keyAckedSequence, sequence); err != nil {
			return err
		}
		if err := putUint64(meta, keyPendingBytes, pendingBytes); err != nil {
			return err
		}
		return putUint64(meta, keyPendingEvents, pendingEvents)
	})
}

func (store *Store) Info() (Info, error) {
	var info Info
	err := store.db.View(func(transaction *bolt.Tx) error {
		meta := transaction.Bucket(bucketMeta)
		info.StreamID = string(meta.Get(keyStreamID))
		info.PendingEvents = readUint64(meta.Get(keyPendingEvents))
		info.PendingBytes = readUint64(meta.Get(keyPendingBytes))
		info.HighestAckedSequence = readUint64(meta.Get(keyAckedSequence))
		_, raw := transaction.Bucket(bucketEvents).Cursor().First()
		if raw != nil {
			var event agentv1.Event
			if err := json.Unmarshal(raw, &event); err != nil {
				return fmt.Errorf("decode oldest queued event: %w", err)
			}
			value := event.ObservedAt
			info.OldestObservedAt = &value
		}
		return nil
	})
	return info, err
}

func (store *Store) Notifications() <-chan struct{} {
	return store.notify
}

func (store *Store) initialize() error {
	return store.db.Update(func(transaction *bolt.Tx) error {
		meta, err := transaction.CreateBucketIfNotExists(bucketMeta)
		if err != nil {
			return fmt.Errorf("create event queue metadata: %w", err)
		}
		if _, err := transaction.CreateBucketIfNotExists(bucketEvents); err != nil {
			return fmt.Errorf("create event queue events: %w", err)
		}
		storedNodeID := string(meta.Get(keyNodeID))
		if storedNodeID == "" {
			if err := meta.Put(keyNodeID, []byte(store.nodeID)); err != nil {
				return err
			}
		} else if storedNodeID != store.nodeID {
			return errors.New("event queue belongs to a different node")
		}
		if len(meta.Get(keyStreamID)) == 0 {
			streamID, err := protocol.NewID()
			if err != nil {
				return err
			}
			if err := meta.Put(keyStreamID, []byte(streamID)); err != nil {
				return err
			}
		}
		if readUint64(meta.Get(keyNextSequence)) == 0 {
			return putUint64(meta, keyNextSequence, 1)
		}
		return nil
	})
}

func (store *Store) signal() {
	select {
	case store.notify <- struct{}{}:
	default:
	}
}

func sequenceKey(sequence uint64) []byte {
	var key [8]byte
	binary.BigEndian.PutUint64(key[:], sequence)
	return key[:]
}

func readUint64(value []byte) uint64 {
	if len(value) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(value)
}

func putUint64(bucket *bolt.Bucket, key []byte, value uint64) error {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return bucket.Put(key, raw[:])
}
