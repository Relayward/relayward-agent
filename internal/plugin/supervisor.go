package plugin

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"github.com/Relayward/relayward-sdk/protocol"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
)

const (
	stableProcessDuration       = 5 * time.Minute
	defaultHealthCheckInterval  = 30 * time.Second
	healthFailuresBeforeRestart = 3
)

type eventSink interface {
	Enqueue(string, time.Time, any) (agentv1.Event, error)
}

type pluginActor struct {
	mu          sync.Mutex
	process     *managedProcess
	crashStreak uint
}

type Supervisor struct {
	store               *stateStore
	installer           *installer
	runtime             *processRuntime
	logger              *slog.Logger
	healthCheckInterval time.Duration

	mu           sync.Mutex
	actors       map[string]*pluginActor
	capabilities map[string][]string
	events       eventSink
	ctx          context.Context
	cancel       context.CancelFunc
	started      bool
	stopping     bool
}

func NewSupervisor(stateDirectory string, logger *slog.Logger) (*Supervisor, error) {
	store, err := openStateStore(stateDirectory)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Supervisor{
		store: store, installer: newInstaller(store, nil, nil), runtime: &processRuntime{store: store},
		logger: logger, healthCheckInterval: defaultHealthCheckInterval, actors: make(map[string]*pluginActor),
		capabilities: make(map[string][]string),
	}, nil
}

func (supervisor *Supervisor) SetEventSink(sink eventSink) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	supervisor.events = sink
}

func (supervisor *Supervisor) Start(parent context.Context) error {
	supervisor.mu.Lock()
	if supervisor.started {
		supervisor.mu.Unlock()
		return errors.New("plugin supervisor already started")
	}
	supervisor.ctx, supervisor.cancel = context.WithCancel(parent)
	supervisor.started = true
	supervisor.stopping = false
	supervisor.mu.Unlock()

	for _, state := range supervisor.store.list() {
		actor := supervisor.actor(state.PluginID)
		actor.mu.Lock()
		current := state.Current
		switch {
		case current == nil:
		case current.State == agentv1.PluginStateRunning:
			process, err := supervisor.startRevision(supervisor.ctx, state.PluginID, *current)
			if err != nil {
				supervisor.emitFailed(state.PluginID, current.Generation, current.Version, current.ConfigurationSHA256, state.RestartCount, "plugin recovery failed")
				supervisor.logger.Error("recover plugin process", "plugin_id", state.PluginID, "error", err)
				go supervisor.retryRecovery(state.PluginID, actor)
			} else {
				actor.process = process
				if err := supervisor.emitRevision(state.PluginID, *current, state.RestartCount); err != nil {
					supervisor.logger.Error("queue recovered plugin status", "plugin_id", state.PluginID, "error", err)
				}
				supervisor.watch(state.PluginID, actor, process)
			}
		case current.State == agentv1.PluginStateStopped, current.State == agentv1.PluginStateAbsent:
			if current.State == agentv1.PluginStateStopped {
				if _, err := supervisor.verifyRevisionArtifact(state.PluginID, *current); err != nil {
					supervisor.emitFailed(state.PluginID, current.Generation, current.Version, current.ConfigurationSHA256, state.RestartCount, "installed plugin artifact failed verification")
					actor.mu.Unlock()
					continue
				}
			}
			if err := supervisor.emitRevision(state.PluginID, *current, state.RestartCount); err != nil {
				supervisor.logger.Error("queue recovered plugin status", "plugin_id", state.PluginID, "error", err)
			}
		}
		actor.mu.Unlock()
	}
	return nil
}

func (supervisor *Supervisor) Close(ctx context.Context) error {
	supervisor.mu.Lock()
	if !supervisor.started || supervisor.stopping {
		supervisor.mu.Unlock()
		return nil
	}
	supervisor.stopping = true
	if supervisor.cancel != nil {
		supervisor.cancel()
	}
	actors := make([]*pluginActor, 0, len(supervisor.actors))
	for _, actor := range supervisor.actors {
		actors = append(actors, actor)
	}
	supervisor.mu.Unlock()
	var result error
	for _, actor := range actors {
		actor.mu.Lock()
		process := actor.process
		actor.process = nil
		if process != nil {
			result = errors.Join(result, process.stop(ctx))
		}
		actor.mu.Unlock()
	}
	return result
}

func (supervisor *Supervisor) Execute(ctx context.Context, _ string, command agentv1.Command) commandstate.Execution {
	if command.Kind != agentv1.CommandPluginReconcile {
		return commandstate.UnsupportedExecutor{}.Execute(ctx, "", command)
	}
	request, err := agentv1.DecodePluginReconcileCommand(command)
	if err != nil {
		return pluginFailure(protocol.ErrorInvalidArgument, "invalid plugin reconcile command", false)
	}
	if !supervisor.isRunning() {
		return pluginFailure(protocol.ErrorUnavailable, "plugin supervisor is not running", true)
	}
	actor := supervisor.actor(request.PluginID)
	actor.mu.Lock()
	defer actor.mu.Unlock()
	if !supervisor.isRunning() {
		return pluginFailure(protocol.ErrorUnavailable, "plugin supervisor is stopping", true)
	}
	desired, previous, alreadyCurrent, err := supervisor.store.prepare(request)
	if err != nil {
		switch {
		case errors.Is(err, ErrStaleGeneration), errors.Is(err, ErrGenerationConflict):
			return pluginFailure(protocol.ErrorConflict, "plugin generation conflicts with durable state", false)
		default:
			return pluginFailure(protocol.ErrorInternal, "persist plugin desired state", false)
		}
	}
	if err := supervisor.store.pruneReleases(desired.PluginID); err != nil {
		supervisor.logger.Error("prune plugin releases", "plugin_id", desired.PluginID, "error", err)
	}
	if alreadyCurrent {
		if err := supervisor.ensureCurrent(ctx, actor, desired, previous); err != nil {
			return pluginFailure(protocol.ErrorUnavailable, "restore current plugin state", true)
		}
		_, restartCount, _ := supervisor.store.current(desired.PluginID)
		if previous != nil {
			if err := supervisor.emitRevision(desired.PluginID, *previous, restartCount); err != nil {
				return pluginFailure(protocol.ErrorUnavailable, "queue plugin status event", true)
			}
		}
		return supervisor.success(desired)
	}

	if desired.State == agentv1.PluginStateAbsent {
		if err := supervisor.detachAndStop(ctx, actor); err != nil {
			return pluginFailure(protocol.ErrorUnavailable, "current plugin process failed to stop", true)
		}
		committed, err := supervisor.store.commit(desired)
		if err != nil {
			supervisor.rollback(actor, desired.PluginID, previous)
			return pluginFailure(protocol.ErrorInternal, "commit absent plugin state", false)
		}
		if err := supervisor.removePluginData(desired.PluginID); err != nil {
			supervisor.emitFailed(desired.PluginID, desired.Generation, "", "", 0, "plugin private state removal failed")
			return pluginFailure(protocol.ErrorInternal, "remove plugin private state", false)
		}
		if err := supervisor.emitRevision(desired.PluginID, committed, 0); err != nil {
			return pluginFailure(protocol.ErrorUnavailable, "queue plugin status event", true)
		}
		return supervisor.success(desired)
	}

	executable, err := supervisor.installer.fetch(ctx, desired)
	if err != nil {
		return pluginFailure(protocol.ErrorUnavailable, "plugin artifact download or verification failed", true)
	}
	if err := supervisor.detachAndStop(ctx, actor); err != nil {
		return pluginFailure(protocol.ErrorUnavailable, "current plugin process failed to stop", true)
	}
	candidate, client, err := supervisor.runtime.start(ctx, desired.PluginID, desired.Version, executable)
	if err != nil {
		if errors.Is(err, ErrPluginIdentityMismatch) {
			supervisor.rollback(actor, desired.PluginID, previous)
			return pluginFailure(protocol.ErrorInvalidArgument, "plugin artifact identity validation failed", false)
		}
		supervisor.rollback(actor, desired.PluginID, previous)
		return pluginFailure(protocol.ErrorUnavailable, "plugin process failed to start", true)
	}
	if err := client.validate(ctx, desired); err != nil {
		client.close()
		if stopErr := candidate.stop(context.Background()); stopErr != nil {
			actor.process = candidate
			return pluginFailure(protocol.ErrorUnavailable, "failed candidate process did not stop", true)
		}
		supervisor.rollback(actor, desired.PluginID, previous)
		if errors.Is(err, ErrConfigurationRejected) {
			return pluginFailure(protocol.ErrorInvalidArgument, "plugin configuration validation failed", false)
		}
		return pluginFailure(protocol.ErrorUnavailable, "plugin configuration validation failed", true)
	}
	if desired.State == agentv1.PluginStateRunning {
		if err := client.apply(ctx, desired); err != nil {
			client.close()
			if stopErr := candidate.stop(context.Background()); stopErr != nil {
				actor.process = candidate
				return pluginFailure(protocol.ErrorUnavailable, "failed candidate process did not stop", true)
			}
			supervisor.rollback(actor, desired.PluginID, previous)
			return pluginFailure(protocol.ErrorUnavailable, "plugin configuration application or health check failed", true)
		}
	}
	if desired.State == agentv1.PluginStateStopped {
		if err := candidate.stop(ctx); err != nil {
			actor.process = candidate
			return pluginFailure(protocol.ErrorUnavailable, "plugin process failed to stop", true)
		}
		candidate = nil
	}
	committed, err := supervisor.store.commit(desired)
	if err != nil {
		if candidate != nil {
			if stopErr := candidate.stop(context.Background()); stopErr != nil {
				actor.process = candidate
				return pluginFailure(protocol.ErrorUnavailable, "uncommitted plugin process did not stop", true)
			}
		}
		supervisor.rollback(actor, desired.PluginID, previous)
		return pluginFailure(protocol.ErrorInternal, "commit plugin state", false)
	}
	if candidate != nil {
		candidate.ready = true
		actor.process = candidate
		supervisor.setCapabilities(desired.PluginID, candidate.client.capabilities)
		actor.crashStreak = 0
		supervisor.watch(desired.PluginID, actor, candidate)
	}
	if err := supervisor.emitRevision(desired.PluginID, committed, 0); err != nil {
		return pluginFailure(protocol.ErrorUnavailable, "queue plugin status event", true)
	}
	if err := supervisor.store.pruneReleases(desired.PluginID); err != nil {
		supervisor.logger.Error("prune plugin releases", "plugin_id", desired.PluginID, "error", err)
	}
	return supervisor.success(desired)
}

func (supervisor *Supervisor) ensureCurrent(ctx context.Context, actor *pluginActor, desired desiredState, current *revision) error {
	if current == nil {
		return errors.New("current plugin state is missing")
	}
	if current.State != agentv1.PluginStateAbsent {
		if _, err := supervisor.installer.fetch(ctx, desired); err != nil {
			return err
		}
	}
	switch current.State {
	case agentv1.PluginStateAbsent:
		if err := supervisor.detachAndStop(ctx, actor); err != nil {
			return err
		}
		return supervisor.removePluginData(desired.PluginID)
	case agentv1.PluginStateStopped:
		return supervisor.detachAndStop(ctx, actor)
	case agentv1.PluginStateRunning:
		if actor.process != nil && !actor.process.exited() {
			return nil
		}
		process, err := supervisor.startRevision(ctx, desired.PluginID, *current)
		if err != nil {
			return err
		}
		actor.process = process
		supervisor.watch(desired.PluginID, actor, process)
		return nil
	default:
		return errors.New("current plugin state is invalid")
	}
}

func (supervisor *Supervisor) startRevision(ctx context.Context, pluginID string, value revision) (*managedProcess, error) {
	executable, err := supervisor.verifyRevisionArtifact(pluginID, value)
	if err != nil {
		return nil, err
	}
	process, client, err := supervisor.runtime.start(ctx, pluginID, value.Version, executable)
	if err != nil {
		return nil, err
	}
	desired := desiredState{
		PluginID: pluginID, Generation: value.Generation, State: value.State, Version: value.Version,
		Artifact: cloneArtifact(value.Artifact), Configuration: value.Configuration,
		ConfigurationSHA256: value.ConfigurationSHA256,
	}
	if err := client.validate(ctx, desired); err == nil {
		err = client.apply(ctx, desired)
	}
	if err != nil {
		return nil, errors.Join(err, process.stop(context.Background()))
	}
	process.ready = true
	supervisor.setCapabilities(pluginID, client.capabilities)
	return process, nil
}

func (supervisor *Supervisor) verifyRevisionArtifact(pluginID string, value revision) (string, error) {
	if value.Artifact == nil {
		return "", errors.New("plugin artifact state is missing")
	}
	executable := supervisor.store.releasePath(pluginID, value.Version, value.Artifact.SHA256)
	info, err := os.Lstat(executable)
	if err != nil || verifyArtifact(executable, info, value.Artifact) != nil {
		return "", errors.New("installed plugin artifact failed verification")
	}
	return executable, nil
}

func (supervisor *Supervisor) rollback(actor *pluginActor, pluginID string, previous *revision) {
	if previous == nil {
		return
	}
	if previous.State != agentv1.PluginStateRunning {
		_, restartCount, _ := supervisor.store.current(pluginID)
		if err := supervisor.emitRevision(pluginID, *previous, restartCount); err != nil {
			supervisor.logger.Error("queue restored plugin status", "plugin_id", pluginID, "error", err)
		}
		return
	}
	ctx, cancel := context.WithTimeout(supervisor.context(), pluginStartupTimeout+pluginRPCTimeout+pluginHealthTimeout)
	defer cancel()
	process, err := supervisor.startRevision(ctx, pluginID, *previous)
	if err != nil {
		_, restartCount, _ := supervisor.store.current(pluginID)
		supervisor.emitFailed(pluginID, previous.Generation, previous.Version, previous.ConfigurationSHA256, restartCount, "previous plugin state restoration failed")
		supervisor.logger.Error("restore previous plugin state", "plugin_id", pluginID, "error", err)
		go supervisor.retryRecovery(pluginID, actor)
		return
	}
	actor.process = process
	supervisor.watch(pluginID, actor, process)
	_, restartCount, _ := supervisor.store.current(pluginID)
	if err := supervisor.emitRevision(pluginID, *previous, restartCount); err != nil {
		supervisor.logger.Error("queue restored plugin status", "plugin_id", pluginID, "error", err)
	}
}

func (supervisor *Supervisor) detachAndStop(ctx context.Context, actor *pluginActor) error {
	process := actor.process
	actor.process = nil
	if process == nil {
		return nil
	}
	if err := process.stop(ctx); err != nil {
		if !process.exited() {
			actor.process = process
		}
		return err
	}
	supervisor.clearCapabilities(process)
	return nil
}

func (supervisor *Supervisor) removePluginData(pluginID string) error {
	for _, path := range []string{
		filepath.Join(supervisor.store.dataDir, pluginID),
		filepath.Join(supervisor.store.runtimeDir, pluginID),
		filepath.Join(supervisor.store.releasesDir, pluginID),
		supervisor.store.socketPath(pluginID),
	} {
		if err := os.RemoveAll(path); err != nil {
			return err
		}
		if err := syncDirectory(filepath.Dir(path)); err != nil {
			return err
		}
	}
	return nil
}

func (supervisor *Supervisor) watch(pluginID string, actor *pluginActor, process *managedProcess) {
	go func() {
		interval := supervisor.healthCheckInterval
		if interval <= 0 {
			interval = defaultHealthCheckInterval
		}
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		healthFailures := 0
		for {
			reason := "plugin process exited unexpectedly"
			select {
			case <-process.done:
			case <-ticker.C:
				current, _, err := supervisor.store.current(pluginID)
				if err == nil && current == nil {
					err = errors.New("current plugin state is missing")
				}
				if err == nil {
					healthContext, cancel := context.WithTimeout(supervisor.context(), pluginRPCTimeout)
					err = process.client.checkHealthy(healthContext, current.Generation, current.ConfigurationSHA256)
					cancel()
				}
				if err == nil {
					healthFailures = 0
					continue
				}
				healthFailures++
				if healthFailures < healthFailuresBeforeRestart {
					continue
				}
				reason = "plugin health checks failed"
			}
			if reason == "plugin process exited unexpectedly" {
				process.client.close()
			}

			actor.mu.Lock()
			if actor.process != process {
				actor.mu.Unlock()
				return
			}
			current, existingRestartCount, _ := supervisor.store.current(pluginID)
			actor.process = nil
			if reason != "plugin process exited unexpectedly" {
				if stopErr := process.stop(context.Background()); stopErr != nil && !process.exited() {
					actor.process = process
					if current != nil {
						supervisor.emitFailed(pluginID, current.Generation, current.Version, current.ConfigurationSHA256, existingRestartCount, "unhealthy plugin process did not stop")
					}
					supervisor.watch(pluginID, actor, process)
					actor.mu.Unlock()
					return
				}
			}
			supervisor.setCapabilities(pluginID, nil)
			if time.Since(process.startedAt) >= stableProcessDuration {
				actor.crashStreak = 0
			}
			actor.crashStreak++
			restartCount, err := supervisor.store.incrementRestart(pluginID)
			if err == nil && current != nil {
				supervisor.emitFailed(pluginID, current.Generation, current.Version, current.ConfigurationSHA256, restartCount, reason)
			}
			actor.mu.Unlock()
			supervisor.retryRecovery(pluginID, actor)
			return
		}
	}()
}

func (supervisor *Supervisor) retryRecovery(pluginID string, actor *pluginActor) {
	for {
		if !supervisor.isRunning() {
			return
		}
		actor.mu.Lock()
		streak := actor.crashStreak
		if streak == 0 {
			streak = 1
		}
		actor.mu.Unlock()
		delay := time.Second << min(streak-1, 6)
		timer := time.NewTimer(delay)
		select {
		case <-supervisor.context().Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		actor.mu.Lock()
		current, restartCount, err := supervisor.store.current(pluginID)
		if err != nil || current == nil || current.State != agentv1.PluginStateRunning || actor.process != nil || !supervisor.isRunning() {
			actor.mu.Unlock()
			return
		}
		process, startErr := supervisor.startRevision(supervisor.context(), pluginID, *current)
		if startErr == nil {
			actor.process = process
			if err := supervisor.emitRevision(pluginID, *current, restartCount); err != nil {
				supervisor.logger.Error("queue restarted plugin status", "plugin_id", pluginID, "error", err)
			}
			supervisor.watch(pluginID, actor, process)
			actor.mu.Unlock()
			return
		}
		actor.crashStreak++
		supervisor.emitFailed(pluginID, current.Generation, current.Version, current.ConfigurationSHA256, restartCount, "plugin process restart failed")
		actor.mu.Unlock()
	}
}

func (supervisor *Supervisor) success(desired desiredState) commandstate.Execution {
	output, err := agentv1.EncodePluginReconcileOutput(agentv1.PluginReconcileOutput{
		PluginID: desired.PluginID, Generation: desired.Generation, State: desired.State,
		Version: desired.Version, ConfigurationSHA256: desired.ConfigurationSHA256,
	})
	if err != nil {
		return pluginFailure(protocol.ErrorInternal, "encode plugin reconcile result", false)
	}
	return commandstate.Execution{Output: output}
}

func (supervisor *Supervisor) emitRevision(pluginID string, value revision, restartCount uint64) error {
	health := agentv1.PluginHealthUnknown
	if value.State == agentv1.PluginStateRunning {
		health = agentv1.PluginHealthHealthy
	}
	capabilities := supervisor.pluginCapabilities(pluginID)
	if value.State != agentv1.PluginStateRunning {
		capabilities = nil
	}
	return supervisor.emit(agentv1.PluginStatusEvent{
		PluginID: pluginID, Generation: value.Generation, State: value.State, Version: value.Version,
		ConfigurationSHA256: value.ConfigurationSHA256, Health: health, RestartCount: restartCount, Capabilities: capabilities,
	})
}

func (supervisor *Supervisor) emitFailed(pluginID string, generation uint64, version, configurationSHA256 string, restartCount uint64, reason string) {
	if err := supervisor.emit(agentv1.PluginStatusEvent{
		PluginID: pluginID, Generation: generation, State: agentv1.PluginStateFailed, Version: version,
		ConfigurationSHA256: configurationSHA256, Health: agentv1.PluginHealthUnhealthy,
		Reason: reason, RestartCount: restartCount,
	}); err != nil {
		supervisor.logger.Error("queue plugin failure status", "plugin_id", pluginID, "error", err)
	}
}

func (supervisor *Supervisor) emit(value agentv1.PluginStatusEvent) error {
	if err := agentv1.ValidatePluginStatusEvent(value); err != nil {
		return err
	}
	supervisor.mu.Lock()
	sink := supervisor.events
	supervisor.mu.Unlock()
	if sink == nil {
		return errors.New("plugin event sink is not configured")
	}
	_, err := sink.Enqueue(agentv1.EventPluginStatus, time.Now().UTC(), value)
	return err
}

func (supervisor *Supervisor) actor(pluginID string) *pluginActor {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	actor := supervisor.actors[pluginID]
	if actor == nil {
		actor = &pluginActor{}
		supervisor.actors[pluginID] = actor
	}
	return actor
}

func (supervisor *Supervisor) isRunning() bool {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return supervisor.started && !supervisor.stopping
}

func (supervisor *Supervisor) context() context.Context {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if supervisor.ctx == nil {
		return context.Background()
	}
	return supervisor.ctx
}

type RuntimeInfo struct {
	PluginID          string
	InstanceID        string
	Capabilities      []string
	TelemetryStreamID string
}

var ErrPluginUnavailable = errors.New("plugin runtime is unavailable")

func (supervisor *Supervisor) RunningPlugins() []RuntimeInfo {
	supervisor.mu.Lock()
	pluginIDs := make([]string, 0, len(supervisor.actors))
	for pluginID := range supervisor.actors {
		pluginIDs = append(pluginIDs, pluginID)
	}
	supervisor.mu.Unlock()
	sort.Strings(pluginIDs)
	values := make([]RuntimeInfo, 0, len(pluginIDs))
	for _, pluginID := range pluginIDs {
		actor := supervisor.actor(pluginID)
		actor.mu.Lock()
		process := actor.process
		if process != nil && process.ready && !process.exited() {
			values = append(values, RuntimeInfo{PluginID: pluginID, InstanceID: processInstanceID(process),
				Capabilities: append([]string(nil), process.client.capabilities...), TelemetryStreamID: process.client.telemetryStreamID})
		}
		actor.mu.Unlock()
	}
	return values
}

func (supervisor *Supervisor) CollectTelemetry(ctx context.Context, pluginID string, afterSequence uint64) (*nodepluginv1.CollectTelemetryResponse, error) {
	actor := supervisor.actor(pluginID)
	actor.mu.Lock()
	defer actor.mu.Unlock()
	if actor.process == nil || !actor.process.ready || actor.process.exited() {
		return nil, ErrPluginUnavailable
	}
	return actor.process.client.collectTelemetry(ctx, afterSequence)
}

func (supervisor *Supervisor) SetServiceState(ctx context.Context, pluginID string, request *nodepluginv1.SetServiceStateRequest) error {
	actor := supervisor.actor(pluginID)
	actor.mu.Lock()
	defer actor.mu.Unlock()
	if actor.process == nil || !actor.process.ready || actor.process.exited() {
		return ErrPluginUnavailable
	}
	return actor.process.client.setServiceState(ctx, request)
}

func (supervisor *Supervisor) ReplaceDynamicBlocks(ctx context.Context, pluginID string, request *nodepluginv1.ReplaceDynamicBlocksRequest) error {
	actor := supervisor.actor(pluginID)
	actor.mu.Lock()
	defer actor.mu.Unlock()
	if actor.process == nil || !actor.process.ready || actor.process.exited() {
		return ErrPluginUnavailable
	}
	return actor.process.client.replaceDynamicBlocks(ctx, request)
}

func (supervisor *Supervisor) setCapabilities(pluginID string, values []string) {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	if len(values) == 0 {
		delete(supervisor.capabilities, pluginID)
		return
	}
	supervisor.capabilities[pluginID] = append([]string(nil), values...)
}

func (supervisor *Supervisor) pluginCapabilities(pluginID string) []string {
	supervisor.mu.Lock()
	defer supervisor.mu.Unlock()
	return append([]string(nil), supervisor.capabilities[pluginID]...)
}

func (supervisor *Supervisor) clearCapabilities(process *managedProcess) {
	if process == nil {
		return
	}
	supervisor.setCapabilities(process.pluginID, nil)
}

func processInstanceID(process *managedProcess) string {
	if process == nil || process.command == nil || process.command.Process == nil {
		return ""
	}
	return fmt.Sprintf("%d:%d", process.command.Process.Pid, process.startedAt.UnixNano())
}

func pluginFailure(code protocol.ErrorCode, message string, retryable bool) commandstate.Execution {
	return commandstate.Execution{Problem: &protocol.Problem{Code: code, Message: message, Retryable: retryable}}
}

func min(left, right uint) uint {
	if left < right {
		return left
	}
	return right
}

var _ commandstate.Executor = (*Supervisor)(nil)
