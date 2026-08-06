package update

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/contract"
	"github.com/Relayward/relayward-sdk/protocol"

	"github.com/Relayward/relayward-agent/internal/buildinfo"
	"github.com/Relayward/relayward-agent/internal/download"
)

const (
	MaximumManifestBytes   = 64 << 10
	MaximumBinaryBytes     = 64 << 20
	HealthTimeout          = 2 * time.Minute
	releaseDownloadTimeout = 5 * time.Minute
	retainedVersions       = 3

	releaseBaseURL          = "https://github.com"
	releaseRepository       = "Relayward/relayward-agent"
	runtimeAssetsMarkerPath = "/etc/relayward-agent/runtime-assets.sha256"
	pendingFilename         = "update-pending.json"
	confirmedFilename       = "update-confirmed.json"
	failedFilename          = "update-failed.json"
	updateStateAPIVersion   = "relayward.agent-update/v1"
	maximumStateBytes       = 16 << 10
)

var (
	ErrStateNotFound       = errors.New("Agent update state not found")
	ErrActivationPending   = errors.New("Agent update activation is pending")
	ErrActivationFailed    = errors.New("Agent update activation failed")
	ErrActivationTimeout   = errors.New("Agent update activation timed out")
	ErrUpdateStateConflict = errors.New("Agent update conflicts with durable state")
)

type State struct {
	APIVersion     string    `json:"api_version"`
	CommandID      string    `json:"command_id"`
	PreviousTarget string    `json:"previous_target"`
	TargetTarget   string    `json:"target_target"`
	TargetVersion  string    `json:"target_version"`
	StartedAt      time.Time `json:"started_at"`
}

type Preparation struct {
	Version   string
	Restart   bool
	Activated bool
}

type Manager struct {
	stateDirectory      string
	runtimeAssetsPath   string
	baseURL             string
	repository          string
	allowInsecure       bool
	httpClient          *http.Client
	runCandidateVersion func(context.Context, string) (string, error)
	now                 func() time.Time

	mu      sync.Mutex
	changed chan struct{}
}

func NewManager(stateDirectory string) (*Manager, error) {
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
		},
	}
	return newManager(stateDirectory, runtimeAssetsMarkerPath, releaseBaseURL, releaseRepository, false, &http.Client{
		Transport: transport,
		Timeout:   releaseDownloadTimeout,
		CheckRedirect: func(request *http.Request, previous []*http.Request) error {
			if len(previous) >= 10 {
				return errors.New("too many Agent release redirects")
			}
			if request.URL.Scheme != "https" {
				return errors.New("Agent release redirect must use HTTPS")
			}
			return nil
		},
	})
}

func newManager(stateDirectory, runtimeAssetsPath, baseURL, repository string, allowInsecure bool, httpClient *http.Client) (*Manager, error) {
	if !filepath.IsAbs(stateDirectory) || filepath.Clean(stateDirectory) != stateDirectory {
		return nil, errors.New("Agent update state directory must be absolute and clean")
	}
	if !filepath.IsAbs(runtimeAssetsPath) || filepath.Clean(runtimeAssetsPath) != runtimeAssetsPath {
		return nil, errors.New("Agent runtime assets marker path must be absolute and clean")
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil || parsedBase.Host == "" || parsedBase.User != nil || parsedBase.RawQuery != "" || parsedBase.Fragment != "" {
		return nil, errors.New("Agent release base URL is invalid")
	}
	if parsedBase.Scheme != "https" && !(allowInsecure && parsedBase.Scheme == "http") {
		return nil, errors.New("Agent release base URL must use HTTPS")
	}
	if repository == "" || strings.Contains(repository, "..") || strings.Count(repository, "/") != 1 {
		return nil, errors.New("Agent release repository is invalid")
	}
	if httpClient == nil {
		return nil, errors.New("Agent release HTTP client is required")
	}
	if err := os.MkdirAll(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("create Agent update state directory: %w", err)
	}
	if err := os.Chmod(stateDirectory, 0o700); err != nil {
		return nil, fmt.Errorf("protect Agent update state directory: %w", err)
	}
	manager := &Manager{
		stateDirectory: stateDirectory, runtimeAssetsPath: runtimeAssetsPath,
		baseURL: strings.TrimRight(baseURL, "/"), repository: repository,
		allowInsecure: allowInsecure, httpClient: httpClient,
		runCandidateVersion: candidateVersion,
		now:                 func() time.Time { return time.Now().UTC() },
		changed:             make(chan struct{}),
	}
	return manager, nil
}

func (manager *Manager) Pending() (State, error) {
	return manager.readState(manager.statePath(pendingFilename))
}

func (manager *Manager) AwaitActivation(ctx context.Context, runningVersion string) error {
	pending, err := manager.Pending()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if pending.TargetVersion != runningVersion {
		return fmt.Errorf("running Agent version %q does not match pending version %q", runningVersion, pending.TargetVersion)
	}
	current, err := os.Readlink(filepath.Join(manager.stateDirectory, "current"))
	if err != nil {
		return fmt.Errorf("read current Agent target: %w", err)
	}
	if current != pending.TargetTarget {
		return errors.New("current Agent target does not match the pending update")
	}
	if err := manager.validateManagedTarget(current); err != nil {
		return err
	}

	deadline := pending.StartedAt.Add(HealthTimeout)
	for {
		switch observed := manager.Observe(pending.CommandID, pending.TargetVersion, runningVersion); {
		case observed == nil:
			return nil
		case errors.Is(observed, ErrActivationPending):
		case errors.Is(observed, ErrActivationFailed):
			return observed
		default:
			return fmt.Errorf("observe Agent update activation: %w", observed)
		}
		if !manager.now().Before(deadline) {
			return ErrActivationTimeout
		}
		waitContext, cancel := context.WithDeadline(ctx, deadline)
		err := manager.WaitForStateChange(waitContext)
		cancel()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			if errors.Is(err, context.DeadlineExceeded) {
				return ErrActivationTimeout
			}
			return err
		}
	}
}

func (manager *Manager) Confirm(runningVersion string) (bool, error) {
	manager.mu.Lock()
	defer manager.mu.Unlock()
	pending, err := manager.readState(manager.statePath(pendingFilename))
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if pending.TargetVersion != runningVersion {
		return false, fmt.Errorf("running Agent version %q does not match pending version %q", runningVersion, pending.TargetVersion)
	}
	current, err := os.Readlink(filepath.Join(manager.stateDirectory, "current"))
	if err != nil {
		return false, fmt.Errorf("read current Agent target: %w", err)
	}
	if current != pending.TargetTarget {
		return false, errors.New("current Agent target does not match the pending update")
	}
	if err := os.Rename(manager.statePath(pendingFilename), manager.statePath(confirmedFilename)); err != nil {
		return false, fmt.Errorf("confirm Agent update: %w", err)
	}
	if err := syncDirectory(manager.stateDirectory); err != nil {
		return false, err
	}
	manager.signalLocked()
	return true, nil
}

func (manager *Manager) Observe(commandID, version, runningVersion string) error {
	for _, item := range []struct {
		name string
		err  error
	}{
		{name: pendingFilename, err: ErrActivationPending},
		{name: confirmedFilename},
		{name: failedFilename, err: ErrActivationFailed},
	} {
		state, err := manager.readState(manager.statePath(item.name))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		if state.CommandID != commandID || state.TargetVersion != version {
			if item.name == pendingFilename {
				return ErrUpdateStateConflict
			}
			continue
		}
		if item.name == pendingFilename && runningVersion != version {
			return ErrActivationPending
		}
		return item.err
	}
	return ErrStateNotFound
}

func (manager *Manager) WaitForStateChange(ctx context.Context) error {
	manager.mu.Lock()
	changed := manager.changed
	manager.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-changed:
		return nil
	case <-time.After(100 * time.Millisecond):
		return nil
	}
}

func (manager *Manager) Prepare(ctx context.Context, commandID, version, runningVersion string) (Preparation, error) {
	if err := protocol.ValidateIdempotencyKey(commandID); err != nil {
		return Preparation{}, errors.New("Agent update command ID is invalid")
	}
	if err := contract.ValidateSemanticVersion(version); err != nil {
		return Preparation{}, fmt.Errorf("Agent update version: %w", err)
	}
	if observed := manager.Observe(commandID, version, runningVersion); observed == nil {
		return Preparation{Version: version, Activated: true}, nil
	} else if errors.Is(observed, ErrActivationFailed) || errors.Is(observed, ErrUpdateStateConflict) {
		return Preparation{}, observed
	} else if errors.Is(observed, ErrActivationPending) {
		return Preparation{Version: version, Restart: runningVersion != version}, nil
	} else if !errors.Is(observed, ErrStateNotFound) {
		return Preparation{}, observed
	}

	manifest, err := manager.downloadManifest(ctx, version)
	if err != nil {
		return Preparation{}, err
	}
	if manifest.Version != version {
		return Preparation{}, fmt.Errorf("Agent release manifest version %q does not match requested version %q", manifest.Version, version)
	}
	if err := manager.verifyRuntimeAssets(manifest.RuntimeAssetsSHA256); err != nil {
		return Preparation{}, err
	}
	target, err := manager.downloadAndInstall(ctx, manifest)
	if err != nil {
		return Preparation{}, err
	}
	if err := manager.pruneVersions(target); err != nil {
		return Preparation{}, fmt.Errorf("prune Agent versions: %w", err)
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if _, err := manager.readState(manager.statePath(pendingFilename)); err == nil {
		return Preparation{}, errors.New("another Agent update is pending")
	} else if !errors.Is(err, os.ErrNotExist) {
		return Preparation{}, err
	}
	currentPath := filepath.Join(manager.stateDirectory, "current")
	previousTarget, err := os.Readlink(currentPath)
	if err != nil {
		return Preparation{}, fmt.Errorf("read current Agent target: %w", err)
	}
	if err := validateTarget(previousTarget); err != nil {
		return Preparation{}, fmt.Errorf("current Agent target: %w", err)
	}
	if err := manager.validateManagedTarget(previousTarget); err != nil {
		return Preparation{}, err
	}
	state := State{
		APIVersion: updateStateAPIVersion, CommandID: commandID,
		PreviousTarget: previousTarget, TargetTarget: target,
		TargetVersion: version, StartedAt: manager.now(),
	}
	if previousTarget == target {
		if err := manager.replaceState(confirmedFilename, state); err != nil {
			return Preparation{}, err
		}
		manager.signalLocked()
		return Preparation{Version: version, Activated: true}, nil
	}
	if err := atomicSymlink(previousTarget, filepath.Join(manager.stateDirectory, "previous")); err != nil {
		return Preparation{}, fmt.Errorf("record previous Agent target: %w", err)
	}
	if err := manager.removeTerminalStates(); err != nil {
		return Preparation{}, err
	}
	if err := writeJSONAtomic(manager.statePath(pendingFilename), state, 0o600); err != nil {
		return Preparation{}, err
	}
	if err := atomicSymlink(target, currentPath); err != nil {
		_ = os.Remove(manager.statePath(pendingFilename))
		return Preparation{}, fmt.Errorf("switch current Agent target: %w", err)
	}
	manager.signalLocked()
	return Preparation{Version: version, Restart: true}, nil
}

func (manager *Manager) downloadManifest(ctx context.Context, version string) (Manifest, error) {
	raw, err := manager.downloadBytes(ctx, manager.releaseURL(version, ManifestAssetName), MaximumManifestBytes)
	if err != nil {
		return Manifest{}, fmt.Errorf("download Agent release manifest: %w", err)
	}
	manifest, err := DecodeManifest(bytes.NewReader(raw))
	if err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

func (manager *Manager) downloadAndInstall(ctx context.Context, manifest Manifest) (string, error) {
	versionsDirectory := filepath.Join(manager.stateDirectory, "versions")
	if err := os.MkdirAll(versionsDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create Agent versions directory: %w", err)
	}
	releaseDirectory := manifest.Version + "-" + manifest.Artifact.SHA256
	targetDirectory := filepath.Join(versionsDirectory, releaseDirectory)
	if err := os.MkdirAll(targetDirectory, 0o700); err != nil {
		return "", fmt.Errorf("create Agent version directory: %w", err)
	}
	targetBinary := filepath.Join(targetDirectory, "relayward-agent")
	if info, err := os.Lstat(targetBinary); err == nil {
		if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			return "", errors.New("existing Agent version target is invalid")
		}
		digest, err := fileSHA256(targetBinary)
		if err != nil {
			return "", fmt.Errorf("verify existing Agent version target: %w", err)
		}
		if digest != manifest.Artifact.SHA256 {
			return "", errors.New("existing Agent version target checksum is invalid")
		}
		reportedVersion, err := manager.runCandidateVersion(ctx, targetBinary)
		if err != nil {
			return "", fmt.Errorf("validate existing Agent release binary: %w", err)
		}
		if reportedVersion != manifest.Version {
			return "", fmt.Errorf("existing Agent release binary reports version %q instead of %q", reportedVersion, manifest.Version)
		}
		return filepath.Join("versions", releaseDirectory, "relayward-agent"), nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("inspect Agent version target: %w", err)
	}
	partial := targetBinary + ".partial"
	if err := download.Fetch(ctx, manager.httpClient, download.Artifact{
		URL: manager.releaseURL(manifest.Version, manifest.Artifact.File), Path: partial,
		Size: manifest.Artifact.Size, SHA256: manifest.Artifact.SHA256,
		Header: http.Header{
			"Accept":     []string{"application/octet-stream"},
			"User-Agent": []string{"relayward-agent-update"},
		},
		ValidateResponse: func(response *http.Response) error {
			if !manager.allowInsecure && response.Request.URL.Scheme != "https" {
				return errors.New("Agent release response did not use HTTPS")
			}
			return nil
		},
	}); err != nil {
		return "", fmt.Errorf("download Agent release binary: %w", err)
	}
	reportedVersion, err := manager.runCandidateVersion(ctx, partial)
	if err != nil {
		return "", fmt.Errorf("validate Agent release binary: %w", err)
	}
	if reportedVersion != manifest.Version {
		return "", fmt.Errorf("Agent release binary reports version %q instead of %q", reportedVersion, manifest.Version)
	}
	if err := os.Rename(partial, targetBinary); err != nil {
		return "", fmt.Errorf("install Agent release binary: %w", err)
	}
	if err := syncDirectory(targetDirectory); err != nil {
		return "", err
	}
	return filepath.Join("versions", releaseDirectory, "relayward-agent"), nil
}

func (manager *Manager) downloadBytes(ctx context.Context, target string, maximum int64) ([]byte, error) {
	var output bytes.Buffer
	if _, err := manager.downloadTo(ctx, target, -1, &limitedWriter{writer: &output, remaining: maximum}); err != nil {
		return nil, err
	}
	return output.Bytes(), nil
}

func (manager *Manager) downloadTo(ctx context.Context, target string, expectedSize int64, destination io.Writer) (int64, error) {
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return 0, err
	}
	request.Header.Set("Accept", "application/octet-stream, application/json")
	request.Header.Set("Accept-Encoding", "identity")
	request.Header.Set("User-Agent", "relayward-agent-update")
	response, err := manager.httpClient.Do(request)
	if err != nil {
		return 0, errors.New("Agent release endpoint unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("Agent release endpoint returned HTTP %d", response.StatusCode)
	}
	if !manager.allowInsecure && response.Request.URL.Scheme != "https" {
		return 0, errors.New("Agent release response did not use HTTPS")
	}
	if expectedSize >= 0 && response.ContentLength >= 0 && response.ContentLength != expectedSize {
		return 0, errors.New("Agent release response size does not match its manifest")
	}
	maximum := int64(MaximumBinaryBytes)
	if expectedSize >= 0 {
		maximum = expectedSize
	}
	limited := io.LimitReader(response.Body, maximum+1)
	written, err := io.Copy(destination, limited)
	if err != nil {
		return written, err
	}
	if written > maximum {
		return written, errors.New("Agent release response exceeds its size limit")
	}
	return written, nil
}

func (manager *Manager) releaseURL(version, asset string) string {
	return manager.baseURL + "/" + manager.repository + "/releases/download/v" + version + "/" + asset
}

func (manager *Manager) verifyRuntimeAssets(expected string) error {
	raw, err := os.ReadFile(manager.runtimeAssetsPath)
	if errors.Is(err, os.ErrNotExist) {
		return errors.New("Agent runtime assets are not registered; run the release installer")
	}
	if err != nil {
		return fmt.Errorf("read Agent runtime assets marker: %w", err)
	}
	if strings.TrimSpace(string(raw)) != expected {
		return errors.New("Agent runtime assets do not match the release; run the release installer")
	}
	return nil
}

func (manager *Manager) validateManagedTarget(target string) error {
	resolved, err := filepath.EvalSymlinks(filepath.Join(manager.stateDirectory, target))
	if err != nil {
		return fmt.Errorf("resolve current Agent target: %w", err)
	}
	versionsDirectory := filepath.Join(manager.stateDirectory, "versions")
	relative, err := filepath.Rel(versionsDirectory, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return errors.New("current Agent target is outside the managed versions directory")
	}
	return nil
}

func (manager *Manager) replaceState(filename string, state State) error {
	if err := manager.removeTerminalStates(); err != nil {
		return err
	}
	return writeJSONAtomic(manager.statePath(filename), state, 0o600)
}

func (manager *Manager) removeTerminalStates() error {
	for _, filename := range []string{confirmedFilename, failedFilename} {
		if err := os.Remove(manager.statePath(filename)); err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove stale Agent update state: %w", err)
		}
	}
	return syncDirectory(manager.stateDirectory)
}

func (manager *Manager) readState(path string) (State, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return State{}, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > maximumStateBytes {
		return State{}, errors.New("Agent update state file is invalid")
	}
	file, err := os.Open(path)
	if err != nil {
		return State{}, err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maximumStateBytes+1))
	decoder.DisallowUnknownFields()
	var state State
	if err := decoder.Decode(&state); err != nil {
		return State{}, fmt.Errorf("decode Agent update state: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return State{}, errors.New("Agent update state contains trailing JSON")
	}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func validateState(state State) error {
	if state.APIVersion != updateStateAPIVersion {
		return errors.New("Agent update state API version is unsupported")
	}
	if err := protocol.ValidateIdempotencyKey(state.CommandID); err != nil {
		return errors.New("Agent update state command ID is invalid")
	}
	if err := contract.ValidateSemanticVersion(state.TargetVersion); err != nil {
		return errors.New("Agent update state version is invalid")
	}
	if err := validateTarget(state.PreviousTarget); err != nil {
		return err
	}
	if err := validateTarget(state.TargetTarget); err != nil {
		return err
	}
	if state.StartedAt.IsZero() {
		return errors.New("Agent update state start time is missing")
	}
	return nil
}

func validateTarget(target string) error {
	if target == "" || filepath.IsAbs(target) || filepath.Clean(target) != target {
		return errors.New("Agent update target is invalid")
	}
	parts := strings.Split(target, string(filepath.Separator))
	if len(parts) != 3 || parts[0] != "versions" || parts[1] == "" || parts[2] != "relayward-agent" {
		return errors.New("Agent update target is outside the versions directory")
	}
	return nil
}

func (manager *Manager) statePath(filename string) string {
	return filepath.Join(manager.stateDirectory, filename)
}

func (manager *Manager) signalLocked() {
	close(manager.changed)
	manager.changed = make(chan struct{})
}

func (manager *Manager) pruneVersions(target string) error {
	directory := filepath.Join(manager.stateDirectory, "versions")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	protected := make(map[string]bool)
	targetParts := strings.Split(target, string(filepath.Separator))
	if len(targetParts) == 3 {
		protected[targetParts[1]] = true
	}
	for _, link := range []string{"current", "previous"} {
		if target, err := os.Readlink(filepath.Join(manager.stateDirectory, link)); err == nil {
			parts := strings.Split(target, string(filepath.Separator))
			if len(parts) == 3 {
				protected[parts[1]] = true
			}
		}
	}
	type installed struct {
		name     string
		modified time.Time
	}
	versions := make([]installed, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		binary := filepath.Join(directory, entry.Name(), "relayward-agent")
		info, err := os.Lstat(binary)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
			continue
		}
		directoryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		versions = append(versions, installed{name: entry.Name(), modified: directoryInfo.ModTime()})
	}
	sort.Slice(versions, func(left, right int) bool {
		if versions[left].modified.Equal(versions[right].modified) {
			return versions[left].name > versions[right].name
		}
		return versions[left].modified.After(versions[right].modified)
	})
	for index, version := range versions {
		if index < retainedVersions || protected[version.name] {
			continue
		}
		if err := os.RemoveAll(filepath.Join(directory, version.name)); err != nil {
			return err
		}
	}
	return syncDirectory(directory)
}

func candidateVersion(ctx context.Context, path string) (string, error) {
	checkContext, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	command := exec.CommandContext(checkContext, path, "version")
	var stdout bytes.Buffer
	command.Stdout = &limitedWriter{writer: &stdout, remaining: 64 << 10}
	command.Stderr = &limitedWriter{writer: io.Discard, remaining: 64 << 10}
	if err := command.Run(); err != nil {
		return "", err
	}
	decoder := json.NewDecoder(&stdout)
	decoder.DisallowUnknownFields()
	var info buildinfo.Info
	if err := decoder.Decode(&info); err != nil {
		return "", err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return "", errors.New("candidate version output contains trailing JSON")
	}
	if err := contract.ValidateSemanticVersion(info.Version); err != nil {
		return "", fmt.Errorf("candidate version is invalid: %w", err)
	}
	return info.Version, nil
}

type limitedWriter struct {
	writer    io.Writer
	remaining int64
}

func (writer *limitedWriter) Write(value []byte) (int, error) {
	if int64(len(value)) > writer.remaining {
		return 0, errors.New("data exceeds limit")
	}
	written, err := writer.writer.Write(value)
	writer.remaining -= int64(written)
	return written, err
}

func atomicSymlink(target, path string) error {
	temporary := path + ".tmp"
	if err := os.Remove(temporary); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.Symlink(target, temporary); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		_ = os.Remove(temporary)
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeJSONAtomic(path string, value any, mode os.FileMode) error {
	directory := filepath.Dir(path)
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	temporary, err := os.CreateTemp(directory, ".update-state-*")
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
	if err := os.Rename(temporaryPath, path); err != nil {
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

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hasher := sha256.New()
	written, err := io.Copy(hasher, io.LimitReader(file, MaximumBinaryBytes+1))
	if err != nil {
		return "", err
	}
	if written > MaximumBinaryBytes {
		return "", errors.New("Agent binary exceeds size limit")
	}
	return hex.EncodeToString(hasher.Sum(nil)), nil
}

func activatedOutput(version string) (json.RawMessage, error) {
	return agentv1.EncodeAgentUpdateOutput(agentv1.AgentUpdateOutput{Version: version, State: agentv1.AgentUpdateStateActivated})
}
