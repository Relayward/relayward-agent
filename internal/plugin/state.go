package plugin

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/contract"
)

const (
	stateAPIVersion   = "relayward.agent-plugin-state/v1"
	maximumStateBytes = 2 << 20
)

var (
	ErrGenerationConflict = errors.New("plugin generation conflicts with durable state")
	ErrStaleGeneration    = errors.New("plugin generation is older than durable state")
)

type artifactState struct {
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

type desiredState struct {
	PluginID            string          `json:"plugin_id"`
	Generation          uint64          `json:"generation"`
	State               string          `json:"state"`
	Version             string          `json:"version,omitempty"`
	Artifact            *artifactState  `json:"artifact,omitempty"`
	DownloadURL         string          `json:"download_url,omitempty"`
	Configuration       json.RawMessage `json:"configuration,omitempty"`
	ConfigurationSHA256 string          `json:"configuration_sha256,omitempty"`
}

type revision struct {
	Generation          uint64          `json:"generation"`
	State               string          `json:"state"`
	Version             string          `json:"version,omitempty"`
	Artifact            *artifactState  `json:"artifact,omitempty"`
	Configuration       json.RawMessage `json:"configuration,omitempty"`
	ConfigurationSHA256 string          `json:"configuration_sha256,omitempty"`
}

type pluginState struct {
	APIVersion     string        `json:"api_version"`
	PluginID       string        `json:"plugin_id"`
	LastGeneration uint64        `json:"last_generation"`
	Current        *revision     `json:"current,omitempty"`
	Previous       *revision     `json:"previous,omitempty"`
	Pending        *desiredState `json:"pending,omitempty"`
	RestartCount   uint64        `json:"restart_count"`
}

type stateStore struct {
	root        string
	statesDir   string
	releasesDir string
	dataDir     string
	runtimeDir  string

	mu     sync.Mutex
	states map[string]pluginState
}

func openStateStore(stateDirectory string) (*stateStore, error) {
	root := filepath.Join(stateDirectory, "plugins")
	store := &stateStore{
		root:        root,
		statesDir:   filepath.Join(root, "state"),
		releasesDir: filepath.Join(root, "releases"),
		dataDir:     filepath.Join(root, "data"),
		runtimeDir:  filepath.Join(root, "runtime"),
		states:      make(map[string]pluginState),
	}
	for _, directory := range []string{stateDirectory, root, store.statesDir, store.releasesDir, store.dataDir, store.runtimeDir} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, fmt.Errorf("create plugin state directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, fmt.Errorf("protect plugin state directory: %w", err)
		}
	}
	entries, err := os.ReadDir(store.statesDir)
	if err != nil {
		return nil, fmt.Errorf("read plugin states: %w", err)
	}
	removedTemporary := false
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasPrefix(entry.Name(), ".plugin-state-") {
			if err := os.Remove(filepath.Join(store.statesDir, entry.Name())); err != nil {
				return nil, fmt.Errorf("remove stale plugin state temporary file: %w", err)
			}
			removedTemporary = true
			continue
		}
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".json" {
			continue
		}
		value, err := readPluginState(filepath.Join(store.statesDir, entry.Name()))
		if err != nil {
			return nil, err
		}
		if entry.Name() != value.PluginID+".json" {
			return nil, errors.New("plugin state filename does not match its plugin ID")
		}
		if _, exists := store.states[value.PluginID]; exists {
			return nil, fmt.Errorf("duplicate plugin state %q", value.PluginID)
		}
		store.states[value.PluginID] = value
	}
	if removedTemporary {
		if err := syncDirectory(store.statesDir); err != nil {
			return nil, err
		}
	}
	if err := cleanupArtifactTemporaries(store.releasesDir); err != nil {
		return nil, err
	}
	return store, nil
}

func (store *stateStore) prepare(value agentv1.PluginReconcileCommand) (desiredState, *revision, bool, error) {
	desired, err := normalizeDesired(value)
	if err != nil {
		return desiredState{}, nil, false, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state := store.states[value.PluginID]
	if state.APIVersion == "" {
		state = pluginState{APIVersion: stateAPIVersion, PluginID: value.PluginID}
	}
	if desired.Generation < state.LastGeneration {
		return desiredState{}, cloneRevision(state.Current), false, ErrStaleGeneration
	}
	if desired.Generation == state.LastGeneration {
		if currentMatches(state.Current, desired) {
			return desired, cloneRevision(state.Current), true, nil
		}
		if state.Pending == nil || !sameDesired(*state.Pending, desired) {
			return desiredState{}, cloneRevision(state.Current), false, ErrGenerationConflict
		}
		if state.Pending.DownloadURL != desired.DownloadURL {
			state.Pending.DownloadURL = desired.DownloadURL
			if err := store.writeLocked(state); err != nil {
				return desiredState{}, cloneRevision(state.Current), false, err
			}
			store.states[value.PluginID] = state
		}
		return desired, cloneRevision(state.Current), false, nil
	}
	state.LastGeneration = desired.Generation
	state.Pending = &desired
	if err := store.writeLocked(state); err != nil {
		return desiredState{}, cloneRevision(state.Current), false, err
	}
	store.states[value.PluginID] = state
	return desired, cloneRevision(state.Current), false, nil
}

func (store *stateStore) commit(desired desiredState) (revision, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists := store.states[desired.PluginID]
	if !exists || state.Pending == nil || state.LastGeneration != desired.Generation || !sameDesired(*state.Pending, desired) {
		return revision{}, ErrGenerationConflict
	}
	next := desired.revision()
	if next.State == agentv1.PluginStateAbsent {
		state.Current = &next
		state.Previous = nil
	} else {
		if state.Current != nil && state.Current.State != agentv1.PluginStateAbsent && !sameRevision(*state.Current, next) {
			state.Previous = cloneRevision(state.Current)
		}
		state.Current = &next
	}
	state.Pending = nil
	state.RestartCount = 0
	if err := store.writeLocked(state); err != nil {
		return revision{}, err
	}
	store.states[desired.PluginID] = state
	return next, nil
}

func (store *stateStore) current(pluginID string) (*revision, uint64, error) {
	if err := contract.ValidatePluginID(pluginID); err != nil {
		return nil, 0, err
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists := store.states[pluginID]
	if !exists {
		return nil, 0, nil
	}
	return cloneRevision(state.Current), state.RestartCount, nil
}

func (store *stateStore) list() []pluginState {
	store.mu.Lock()
	defer store.mu.Unlock()
	values := make([]pluginState, 0, len(store.states))
	for _, state := range store.states {
		state.Current = cloneRevision(state.Current)
		state.Previous = cloneRevision(state.Previous)
		if state.Pending != nil {
			pending := *state.Pending
			pending.Configuration = bytes.Clone(state.Pending.Configuration)
			state.Pending = &pending
		}
		values = append(values, state)
	}
	sort.Slice(values, func(left, right int) bool { return values[left].PluginID < values[right].PluginID })
	return values
}

func (store *stateStore) incrementRestart(pluginID string) (uint64, error) {
	store.mu.Lock()
	defer store.mu.Unlock()
	state, exists := store.states[pluginID]
	if !exists || state.Current == nil || state.Current.State != agentv1.PluginStateRunning {
		return 0, errors.New("running plugin state not found")
	}
	state.RestartCount++
	if err := store.writeLocked(state); err != nil {
		return 0, err
	}
	store.states[pluginID] = state
	return state.RestartCount, nil
}

func (store *stateStore) pruneReleases(pluginID string) error {
	store.mu.Lock()
	state := store.states[pluginID]
	keep := make(map[string]struct{}, 3)
	add := func(version string, artifact *artifactState) {
		if artifact != nil {
			keep[version+"-"+artifact.SHA256] = struct{}{}
		}
	}
	if state.Current != nil {
		add(state.Current.Version, state.Current.Artifact)
	}
	if state.Previous != nil {
		add(state.Previous.Version, state.Previous.Artifact)
	}
	if state.Pending != nil {
		add(state.Pending.Version, state.Pending.Artifact)
	}
	store.mu.Unlock()
	directory := filepath.Join(store.releasesDir, pluginID)
	entries, err := os.ReadDir(directory)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	changed := false
	for _, entry := range entries {
		if _, retained := keep[entry.Name()]; retained {
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, entry.Name())); err != nil {
			return err
		}
		changed = true
	}
	if changed {
		return syncDirectory(directory)
	}
	return nil
}

func (store *stateStore) writeLocked(value pluginState) error {
	if err := validatePluginState(value); err != nil {
		return err
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return fmt.Errorf("encode plugin state: %w", err)
	}
	raw = append(raw, '\n')
	if len(raw) > maximumStateBytes {
		return fmt.Errorf("plugin state exceeds %d bytes", maximumStateBytes)
	}
	return atomicWrite(store.statesDir, ".plugin-state-*", store.statePath(value.PluginID), raw, 0o600)
}

func (store *stateStore) statePath(pluginID string) string {
	return filepath.Join(store.statesDir, pluginID+".json")
}

func (store *stateStore) releasePath(pluginID, version, digest string) string {
	return filepath.Join(store.releasesDir, pluginID, version+"-"+digest, "plugin")
}

func (store *stateStore) dataPath(pluginID string) string {
	return filepath.Join(store.dataDir, pluginID)
}

func (store *stateStore) runtimePath(pluginID string) string {
	return filepath.Join(store.runtimeDir, pluginID)
}

func (store *stateStore) socketPath(pluginID string) string {
	digest := sha256.Sum256([]byte(pluginID))
	return filepath.Join(store.runtimeDir, hex.EncodeToString(digest[:16])+".sock")
}

func normalizeDesired(value agentv1.PluginReconcileCommand) (desiredState, error) {
	if err := agentv1.ValidatePluginReconcileCommand(value); err != nil {
		return desiredState{}, err
	}
	desired := desiredState{PluginID: value.PluginID, Generation: value.Generation, State: value.DesiredState, Version: value.Version}
	if value.DesiredState == agentv1.PluginStateAbsent {
		return desired, nil
	}
	compact := bytes.NewBuffer(make([]byte, 0, len(value.Configuration)))
	if err := json.Compact(compact, value.Configuration); err != nil {
		return desiredState{}, err
	}
	digest, err := agentv1.PluginConfigurationDigest(compact.Bytes())
	if err != nil {
		return desiredState{}, err
	}
	desired.Artifact = &artifactState{Size: value.Artifact.Size, SHA256: value.Artifact.SHA256}
	desired.DownloadURL = value.Artifact.DownloadURL
	desired.Configuration = compact.Bytes()
	desired.ConfigurationSHA256 = digest
	return desired, nil
}

func (desired desiredState) revision() revision {
	return revision{
		Generation: desired.Generation, State: desired.State, Version: desired.Version,
		Artifact: cloneArtifact(desired.Artifact), Configuration: bytes.Clone(desired.Configuration),
		ConfigurationSHA256: desired.ConfigurationSHA256,
	}
}

func currentMatches(current *revision, desired desiredState) bool {
	return current != nil && sameRevision(*current, desired.revision())
}

func sameDesired(left, right desiredState) bool {
	return left.PluginID == right.PluginID && sameRevision(left.revision(), right.revision())
}

func sameRevision(left, right revision) bool {
	return left.Generation == right.Generation && left.State == right.State && left.Version == right.Version &&
		left.ConfigurationSHA256 == right.ConfigurationSHA256 && sameArtifact(left.Artifact, right.Artifact)
}

func sameArtifact(left, right *artifactState) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return left.Size == right.Size && left.SHA256 == right.SHA256
}

func cloneArtifact(value *artifactState) *artifactState {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneRevision(value *revision) *revision {
	if value == nil {
		return nil
	}
	copy := *value
	copy.Artifact = cloneArtifact(value.Artifact)
	copy.Configuration = bytes.Clone(value.Configuration)
	return &copy
}

func readPluginState(path string) (pluginState, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return pluginState{}, fmt.Errorf("stat plugin state: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return pluginState{}, errors.New("plugin state must be a private regular file")
	}
	if info.Size() > maximumStateBytes {
		return pluginState{}, fmt.Errorf("plugin state exceeds %d bytes", maximumStateBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return pluginState{}, fmt.Errorf("open plugin state: %w", err)
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumStateBytes+1))
	decoder.DisallowUnknownFields()
	var value pluginState
	if err := decoder.Decode(&value); err != nil {
		return pluginState{}, fmt.Errorf("decode plugin state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return pluginState{}, errors.New("plugin state contains trailing JSON")
	}
	if err := validatePluginState(value); err != nil {
		return pluginState{}, err
	}
	return value, nil
}

func validatePluginState(value pluginState) error {
	if value.APIVersion != stateAPIVersion {
		return errors.New("plugin state has an unsupported API version")
	}
	if err := contract.ValidatePluginID(value.PluginID); err != nil {
		return errors.New("plugin state has an invalid plugin ID")
	}
	if value.LastGeneration == 0 {
		return errors.New("plugin state has no generation")
	}
	validateRevision := func(entry *revision) error {
		if entry == nil {
			return nil
		}
		command := agentv1.PluginReconcileCommand{PluginID: value.PluginID, Generation: entry.Generation, DesiredState: entry.State, Version: entry.Version}
		if entry.Artifact != nil {
			command.Artifact = &agentv1.PluginArtifact{DownloadURL: "https://github.com/relayward/placeholder", Size: entry.Artifact.Size, SHA256: entry.Artifact.SHA256}
			command.Configuration = entry.Configuration
		}
		if err := agentv1.ValidatePluginReconcileCommand(command); err != nil {
			return err
		}
		digest := ""
		if len(entry.Configuration) != 0 {
			digest, _ = agentv1.PluginConfigurationDigest(entry.Configuration)
		}
		if digest != entry.ConfigurationSHA256 {
			return errors.New("configuration digest does not match")
		}
		return nil
	}
	if err := validateRevision(value.Current); err != nil {
		return fmt.Errorf("plugin current state is invalid: %w", err)
	}
	if err := validateRevision(value.Previous); err != nil {
		return fmt.Errorf("plugin previous state is invalid: %w", err)
	}
	if value.Current != nil && value.Current.Generation > value.LastGeneration {
		return errors.New("plugin current generation exceeds the last generation")
	}
	if value.Previous != nil && (value.Current == nil || value.Previous.Generation >= value.Current.Generation) {
		return errors.New("plugin previous generation is not older than current")
	}
	if value.Current != nil && value.Current.State == agentv1.PluginStateAbsent && value.Previous != nil {
		return errors.New("absent plugin state must not retain a previous revision")
	}
	if value.Pending != nil {
		command := agentv1.PluginReconcileCommand{PluginID: value.PluginID, Generation: value.Pending.Generation, DesiredState: value.Pending.State, Version: value.Pending.Version, Configuration: value.Pending.Configuration}
		if value.Pending.Artifact != nil {
			command.Artifact = &agentv1.PluginArtifact{DownloadURL: value.Pending.DownloadURL, Size: value.Pending.Artifact.Size, SHA256: value.Pending.Artifact.SHA256}
		}
		if err := agentv1.ValidatePluginReconcileCommand(command); err != nil {
			return fmt.Errorf("plugin pending state is invalid: %w", err)
		}
		if value.Pending.PluginID != value.PluginID || value.Pending.Generation != value.LastGeneration {
			return errors.New("plugin pending state identity does not match")
		}
		digest, _ := agentv1.PluginConfigurationDigest(value.Pending.Configuration)
		if value.Pending.State != agentv1.PluginStateAbsent && digest != value.Pending.ConfigurationSHA256 {
			return errors.New("plugin pending configuration digest does not match")
		}
	}
	if value.Current == nil && value.Pending == nil {
		return errors.New("plugin state has neither current nor pending state")
	}
	return nil
}

func atomicWrite(directory, pattern, destination string, raw []byte, mode os.FileMode) error {
	temporary, err := os.CreateTemp(directory, pattern)
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryPath, destination); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func cleanupArtifactTemporaries(root string) error {
	changed := make(map[string]struct{})
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasPrefix(entry.Name(), ".artifact-") {
			return nil
		}
		if err := os.Remove(path); err != nil {
			return err
		}
		changed[filepath.Dir(path)] = struct{}{}
		return nil
	})
	if err != nil {
		return fmt.Errorf("clean stale plugin artifact temporary files: %w", err)
	}
	for directory := range changed {
		if err := syncDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}
