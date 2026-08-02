package command

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"
)

const (
	statePending      = "pending"
	stateCompleted    = "completed"
	stateAcknowledged = "acknowledged"

	maxRecordBytes        = agentv1.MaximumMessageBytes + 64<<10
	acknowledgedRetention = 24 * time.Hour
)

var ErrNotFound = errors.New("command not found")
var ErrConflict = errors.New("command conflicts with durable state")

type record struct {
	APIVersion     string                 `json:"api_version"`
	CommandID      string                 `json:"command_id"`
	RequestSHA256  string                 `json:"request_sha256"`
	Command        agentv1.Command        `json:"command"`
	State          string                 `json:"state"`
	Result         *agentv1.CommandResult `json:"result,omitempty"`
	ReceivedAt     time.Time              `json:"received_at"`
	UpdatedAt      time.Time              `json:"updated_at"`
	AcknowledgedAt *time.Time             `json:"acknowledged_at,omitempty"`
}

type Store struct {
	directory string
	mu        sync.Mutex
	records   map[string]record
}

func OpenStore(stateDirectory string) (*Store, error) {
	directory := filepath.Join(stateDirectory, "commands")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, fmt.Errorf("create command state directory: %w", err)
	}
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("protect Agent state directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, fmt.Errorf("protect command state directory: %w", err)
	}
	store := &Store{directory: directory, records: make(map[string]record)}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, fmt.Errorf("read command state directory: %w", err)
	}
	removedTemporary := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".command-") {
			if err := os.Remove(filepath.Join(directory, entry.Name())); err != nil {
				return nil, fmt.Errorf("remove stale command temporary file: %w", err)
			}
			removedTemporary = true
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		value, err := readRecord(filepath.Join(directory, entry.Name()))
		if err != nil {
			return nil, err
		}
		if entry.Name() != value.CommandID+".json" {
			return nil, fmt.Errorf("command state filename does not match its command ID")
		}
		if _, exists := store.records[value.CommandID]; exists {
			return nil, fmt.Errorf("duplicate command state %q", value.CommandID)
		}
		store.records[value.CommandID] = value
	}
	if removedTemporary {
		if err := syncDirectory(directory); err != nil {
			return nil, err
		}
	}
	return store, nil
}

func (store *Store) Accept(commandID string, value agentv1.Command, receivedAt time.Time) (bool, error) {
	if err := protocol.ValidateIdempotencyKey(commandID); err != nil {
		return false, fmt.Errorf("validate command ID: %w", err)
	}
	digest, err := agentv1.CommandDigest(value)
	if err != nil {
		return false, fmt.Errorf("validate command: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if existing, exists := store.records[commandID]; exists {
		if existing.RequestSHA256 != digest {
			return false, ErrConflict
		}
		return false, nil
	}
	record := record{
		APIVersion: agentv1.APIVersion, CommandID: commandID, RequestSHA256: digest,
		Command: value, State: statePending, ReceivedAt: receivedAt.UTC(), UpdatedAt: receivedAt.UTC(),
	}
	if err := store.writeLocked(record); err != nil {
		return false, err
	}
	store.records[commandID] = record
	return true, nil
}

func (store *Store) NextPending() (record, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	values := store.sortedLocked(statePending)
	if len(values) == 0 {
		return record{}, ErrNotFound
	}
	return values[0], nil
}

func (store *Store) Complete(commandID, requestSHA256 string, result agentv1.CommandResult, completedAt time.Time) error {
	if err := agentv1.ValidateCommandResult(result); err != nil {
		return fmt.Errorf("validate command result: %w", err)
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, exists := store.records[commandID]
	if !exists {
		return ErrNotFound
	}
	if existing.RequestSHA256 != requestSHA256 || result.CommandID != commandID || result.RequestSHA256 != requestSHA256 {
		return ErrConflict
	}
	if existing.State != statePending {
		if existing.Result != nil && commandResultsEqual(*existing.Result, result) {
			return nil
		}
		return ErrConflict
	}
	existing.State = stateCompleted
	existing.Result = &result
	existing.UpdatedAt = completedAt.UTC()
	if err := store.writeLocked(existing); err != nil {
		return err
	}
	store.records[commandID] = existing
	return nil
}

func (store *Store) NextResult() (agentv1.CommandResult, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	values := store.sortedLocked(stateCompleted)
	if len(values) == 0 || values[0].Result == nil {
		return agentv1.CommandResult{}, ErrNotFound
	}
	return *values[0].Result, nil
}

func (store *Store) Acknowledge(commandID, requestSHA256 string, acknowledgedAt time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	existing, exists := store.records[commandID]
	if !exists {
		return ErrNotFound
	}
	if existing.RequestSHA256 != requestSHA256 {
		return ErrConflict
	}
	if existing.State == stateAcknowledged {
		return nil
	}
	if existing.State != stateCompleted || existing.Result == nil {
		return ErrConflict
	}
	value := acknowledgedAt.UTC()
	existing.State = stateAcknowledged
	existing.UpdatedAt = value
	existing.AcknowledgedAt = &value
	if err := store.writeLocked(existing); err != nil {
		return err
	}
	store.records[commandID] = existing
	return nil
}

func (store *Store) Cleanup(now time.Time) error {
	store.mu.Lock()
	defer store.mu.Unlock()
	cutoff := now.UTC().Add(-acknowledgedRetention)
	for commandID, existing := range store.records {
		if existing.State != stateAcknowledged || existing.AcknowledgedAt == nil || existing.AcknowledgedAt.After(cutoff) {
			continue
		}
		if err := os.Remove(store.path(commandID)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove acknowledged command state: %w", err)
		}
		delete(store.records, commandID)
	}
	return syncDirectory(store.directory)
}

func (store *Store) sortedLocked(state string) []record {
	values := make([]record, 0, len(store.records))
	for _, value := range store.records {
		if value.State == state {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(left, right int) bool {
		if values[left].ReceivedAt.Equal(values[right].ReceivedAt) {
			return values[left].CommandID < values[right].CommandID
		}
		return values[left].ReceivedAt.Before(values[right].ReceivedAt)
	})
	return values
}

func (store *Store) writeLocked(value record) error {
	if err := validateRecord(value); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode command state: %w", err)
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(store.directory, ".command-*")
	if err != nil {
		return fmt.Errorf("create command state temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect command state temporary file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write command state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync command state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close command state: %w", err)
	}
	if err := os.Rename(temporaryPath, store.path(value.CommandID)); err != nil {
		return fmt.Errorf("replace command state: %w", err)
	}
	return syncDirectory(store.directory)
}

func (store *Store) path(commandID string) string {
	return filepath.Join(store.directory, commandID+".json")
}

func readRecord(path string) (record, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return record{}, fmt.Errorf("stat command state: %w", err)
	}
	if !info.Mode().IsRegular() {
		return record{}, errors.New("command state must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return record{}, errors.New("command state must not be accessible by group or others")
	}
	if info.Size() > maxRecordBytes {
		return record{}, fmt.Errorf("command state exceeds %d bytes", maxRecordBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return record{}, fmt.Errorf("open command state: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRecordBytes+1))
	decoder.DisallowUnknownFields()
	var value record
	if err := decoder.Decode(&value); err != nil {
		return record{}, fmt.Errorf("decode command state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return record{}, errors.New("command state contains trailing JSON")
	}
	if err := validateRecord(value); err != nil {
		return record{}, err
	}
	return value, nil
}

func validateRecord(value record) error {
	if value.APIVersion != agentv1.APIVersion {
		return errors.New("command state has an unsupported API version")
	}
	if err := protocol.ValidateIdempotencyKey(value.CommandID); err != nil {
		return errors.New("command state has an invalid command ID")
	}
	digest, err := agentv1.CommandDigest(value.Command)
	if err != nil || digest != value.RequestSHA256 {
		return errors.New("command state request digest does not match")
	}
	if value.ReceivedAt.IsZero() || value.UpdatedAt.IsZero() {
		return errors.New("command state timestamps must be set")
	}
	switch value.State {
	case statePending:
		if value.Result != nil || value.AcknowledgedAt != nil {
			return errors.New("pending command state contains terminal data")
		}
	case stateCompleted:
		if value.Result == nil || value.AcknowledgedAt != nil {
			return errors.New("completed command state is invalid")
		}
	case stateAcknowledged:
		if value.Result == nil || value.AcknowledgedAt == nil || value.AcknowledgedAt.IsZero() {
			return errors.New("acknowledged command state is invalid")
		}
	default:
		return errors.New("command state has an unsupported state")
	}
	if value.Result != nil {
		if err := agentv1.ValidateCommandResult(*value.Result); err != nil || value.Result.CommandID != value.CommandID || value.Result.RequestSHA256 != value.RequestSHA256 {
			return errors.New("command state contains an invalid result")
		}
	}
	return nil
}

func commandResultsEqual(left, right agentv1.CommandResult) bool {
	leftRaw, leftErr := json.Marshal(left)
	rightRaw, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftRaw, rightRaw)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open command state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync command state directory: %w", err)
	}
	return nil
}
