package identity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

const filename = "identity.json"
const maxIdentityBytes = 64 << 10

type Identity struct {
	APIVersion string `json:"api_version"`
	NodeID     string `json:"node_id"`
	NodeName   string `json:"node_name"`
	Credential string `json:"credential"`
}

type Store struct {
	directory string
}

func NewStore(directory string) *Store {
	return &Store{directory: directory}
}

func (store *Store) Path() string {
	return filepath.Join(store.directory, filename)
}

func (store *Store) Load() (Identity, error) {
	info, err := os.Lstat(store.Path())
	if err != nil {
		return Identity{}, err
	}
	if !info.Mode().IsRegular() {
		return Identity{}, errors.New("identity must be a regular file")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return Identity{}, errors.New("identity must not be accessible by group or others")
	}
	if info.Size() > maxIdentityBytes {
		return Identity{}, fmt.Errorf("identity exceeds %d bytes", maxIdentityBytes)
	}
	file, err := os.Open(store.Path())
	if err != nil {
		return Identity{}, fmt.Errorf("open identity: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxIdentityBytes+1))
	decoder.DisallowUnknownFields()
	var value Identity
	if err := decoder.Decode(&value); err != nil {
		return Identity{}, fmt.Errorf("decode identity: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return Identity{}, errors.New("identity contains trailing JSON")
	}
	if err := Validate(value); err != nil {
		return Identity{}, err
	}
	return value, nil
}

func (store *Store) Save(value Identity) error {
	if err := Validate(value); err != nil {
		return err
	}
	if err := os.MkdirAll(store.directory, 0o700); err != nil {
		return fmt.Errorf("create state directory: %w", err)
	}
	if err := os.Chmod(store.directory, 0o700); err != nil {
		return fmt.Errorf("protect state directory: %w", err)
	}
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encode identity: %w", err)
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(store.directory, ".identity-*")
	if err != nil {
		return fmt.Errorf("create identity temporary file: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect identity temporary file: %w", err)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return fmt.Errorf("write identity: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync identity: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close identity: %w", err)
	}
	if err := os.Rename(temporaryPath, store.Path()); err != nil {
		return fmt.Errorf("replace identity: %w", err)
	}
	directory, err := os.Open(store.directory)
	if err != nil {
		return fmt.Errorf("open state directory: %w", err)
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil {
		return fmt.Errorf("sync state directory: %w", err)
	}
	return nil
}

func Validate(value Identity) error {
	response := agentv1.RegisterResponse{
		APIVersion: value.APIVersion, NodeID: value.NodeID, NodeName: value.NodeName, Credential: value.Credential,
	}
	if err := agentv1.ValidateRegisterResponse(response); err != nil {
		return fmt.Errorf("identity: %w", err)
	}
	return nil
}
