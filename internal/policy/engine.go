package policy

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"github.com/Relayward/relayward-sdk/protocol"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
	"github.com/Relayward/relayward-agent/internal/plugin"
)

const (
	defaultEvaluationInterval = 10 * time.Second
	maximumTelemetryPages     = 16
)

type eventSink interface {
	Enqueue(string, time.Time, any) (agentv1.Event, error)
}

type runtimeHost interface {
	RunningPlugins() []plugin.RuntimeInfo
	CollectTelemetry(context.Context, string, uint64) (*nodepluginv1.CollectTelemetryResponse, error)
	SetServiceState(context.Context, string, *nodepluginv1.SetServiceStateRequest) error
	ReplaceDynamicBlocks(context.Context, string, *nodepluginv1.ReplaceDynamicBlocksRequest) error
}

type Engine struct {
	store    *Store
	runtimes runtimeHost
	logger   *slog.Logger
	interval time.Duration
	now      func() time.Time

	mu     sync.Mutex
	events eventSink
	cycle  sync.Mutex
}

func NewEngine(statePath string, runtimes runtimeHost, logger *slog.Logger) (*Engine, error) {
	if runtimes == nil {
		return nil, errors.New("plugin runtime host is required")
	}
	store, err := Open(statePath)
	if err != nil {
		return nil, err
	}
	if logger == nil {
		logger = slog.Default()
	}
	return &Engine{
		store: store, runtimes: runtimes, logger: logger,
		interval: defaultEvaluationInterval, now: func() time.Time { return time.Now().UTC() },
	}, nil
}

func (engine *Engine) SetEventSink(sink eventSink) {
	engine.mu.Lock()
	engine.events = sink
	engine.mu.Unlock()
}

func (engine *Engine) Close() error {
	return engine.store.Close()
}

func (engine *Engine) Execute(ctx context.Context, _ string, command agentv1.Command) commandstate.Execution {
	if command.Kind != agentv1.CommandPolicyReconcile {
		return commandstate.UnsupportedExecutor{}.Execute(ctx, "", command)
	}
	request, err := agentv1.DecodePolicyReconcileCommand(command)
	if err != nil {
		return policyFailure(protocol.ErrorInvalidArgument, "invalid policy reconcile command", false)
	}
	engine.cycle.Lock()
	defer engine.cycle.Unlock()
	runtimes := runtimeMap(engine.runtimes.RunningPlugins())
	missingRuntime, capabilityErr := validateCapabilities(request, runtimes)
	if capabilityErr != nil {
		return policyFailure(protocol.ErrorUnsupported, capabilityErr.Error(), false)
	}
	if _, err := engine.store.Reconcile(request); err != nil {
		switch {
		case errors.Is(err, ErrGenerationConflict), errors.Is(err, ErrStaleGeneration):
			return policyFailure(protocol.ErrorConflict, "policy generation conflicts with durable state", false)
		default:
			return policyFailure(protocol.ErrorInternal, "persist policy snapshot", false)
		}
	}
	if missingRuntime {
		return policyFailure(protocol.ErrorUnavailable, "a bound runtime plugin is unavailable", true)
	}
	err = engine.applyAndPublish(ctx, runtimes)
	if err != nil {
		return policyFailure(protocol.ErrorUnavailable, "apply local policy", true)
	}
	output, err := agentv1.EncodePolicyReconcileOutput(agentv1.PolicyReconcileOutput{
		Generation: request.Generation, AuthorizationCount: uint32(len(request.Authorizations)),
	})
	if err != nil {
		return policyFailure(protocol.ErrorInternal, "encode policy reconcile result", false)
	}
	return commandstate.Execution{Output: output}
}

func (engine *Engine) Run(ctx context.Context) error {
	interval := engine.interval
	if interval <= 0 {
		interval = defaultEvaluationInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := engine.runCycle(ctx); err != nil && ctx.Err() == nil {
			engine.logger.Warn("local policy cycle failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (engine *Engine) runCycle(ctx context.Context) error {
	engine.cycle.Lock()
	defer engine.cycle.Unlock()
	runtimes := runtimeMap(engine.runtimes.RunningPlugins())
	var result error
	for _, runtime := range runtimes {
		if !nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityTrafficCounters) &&
			!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityRecentActivity) {
			continue
		}
		if err := engine.collectRuntime(ctx, runtime); err != nil {
			result = errors.Join(result, fmt.Errorf("collect plugin %s telemetry: %w", runtime.PluginID, err))
		}
	}
	result = errors.Join(result, engine.applyAndPublish(ctx, runtimes))
	return result
}

func (engine *Engine) collectRuntime(ctx context.Context, runtime plugin.RuntimeInfo) error {
	streamID := runtime.TelemetryStreamID
	hasActivity := nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityRecentActivity)
	if hasActivity && streamID == "" {
		return errors.New("plugin did not report a telemetry stream")
	}
	var cursor uint64
	if hasActivity {
		var err error
		cursor, err = engine.store.TelemetryCursor(runtime.PluginID, streamID)
		if err != nil {
			return err
		}
	}
	for page := 0; page < maximumTelemetryPages; page++ {
		response, err := engine.runtimes.CollectTelemetry(ctx, runtime.PluginID, cursor)
		if err != nil {
			return err
		}
		if nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityTrafficCounters) {
			if err := engine.store.ApplyCounters(runtime.PluginID, response.Counters, engine.now()); err != nil {
				return err
			}
		} else if len(response.Counters) != 0 {
			return errors.New("plugin returned counters without the traffic capability")
		}
		if !hasActivity && len(response.Events) != 0 {
			return errors.New("plugin returned access events without the activity capability")
		}
		for _, event := range response.Events {
			known, err := engine.store.BindingKnown(runtime.PluginID, event.AuthorizationId, event.ServiceId)
			if err != nil {
				return err
			}
			if known {
				observedAt := time.Unix(0, event.ObservedAtUnixNano).UTC()
				value := agentv1.AccessEvent{
					SourceStreamID: streamID, SourceEventID: event.EventId,
					PluginID: runtime.PluginID, ServiceID: event.ServiceId,
					AuthorizationID: event.AuthorizationId, SourceIP: event.SourceIp, Destination: event.Destination,
					DestinationPort: event.DestinationPort, Network: event.Network, Protocol: event.Protocol, Action: event.Action,
				}
				sink := engine.eventSink()
				if sink == nil {
					return errors.New("policy event sink is not configured")
				}
				if _, err := sink.Enqueue(agentv1.EventAccess, observedAt, value); err != nil {
					return err
				}
				if event.Action == agentv1.AccessActionAccepted && event.SourceIp != "" {
					if _, err := engine.store.ObserveActivity(event.AuthorizationId, event.SourceIp, observedAt); err != nil {
						return err
					}
				}
			}
			if err := engine.store.AdvanceTelemetryCursor(runtime.PluginID, streamID, cursor, event.Sequence); err != nil {
				return err
			}
			cursor = event.Sequence
		}
		if len(response.Events) == 0 && response.NextSequence != cursor {
			return errors.New("plugin advanced an empty telemetry page")
		}
		if !response.HasMore {
			return nil
		}
	}
	return errors.New("plugin telemetry page limit reached")
}

func (engine *Engine) applyAndPublish(ctx context.Context, runtimes map[string]plugin.RuntimeInfo) error {
	var result error
	if err := engine.queueTraffic(); err != nil {
		result = errors.Join(result, err)
	}
	if err := engine.applyDesired(ctx, runtimes); err != nil {
		result = errors.Join(result, err)
	}
	if err := engine.store.RefreshStatuses(engine.now(), runtimeInstances(runtimes)); err != nil {
		result = errors.Join(result, err)
	}
	if err := engine.queueStatuses(); err != nil {
		result = errors.Join(result, err)
	}
	return result
}

func (engine *Engine) applyDesired(ctx context.Context, runtimes map[string]plugin.RuntimeInfo) error {
	services, blocks, err := engine.store.Desired(engine.now())
	if err != nil {
		return err
	}
	var result error
	for _, desired := range services {
		runtime, exists := runtimes[desired.PluginID]
		if !exists {
			result = errors.Join(result, fmt.Errorf("plugin %s is unavailable", desired.PluginID))
			continue
		}
		if !nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityTrafficCounters) ||
			!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityServiceControl) {
			result = errors.Join(result, fmt.Errorf("plugin %s lacks traffic or service-control capability", desired.PluginID))
			continue
		}
		if desired.RequiresSoftIP &&
			(!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityRecentActivity) ||
				!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityDynamicBlocking)) {
			result = errors.Join(result, fmt.Errorf("plugin %s lacks activity or dynamic-blocking capability", desired.PluginID))
			continue
		}
		needed, err := engine.store.ServiceNeedsApply(desired, runtime.InstanceID)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if !needed {
			continue
		}
		if err := engine.runtimes.SetServiceState(ctx, desired.PluginID, desired.Request); err != nil {
			result = errors.Join(result, fmt.Errorf("apply plugin %s service state: %w", desired.PluginID, err))
			continue
		}
		if err := engine.store.MarkServiceApplied(desired, runtime.InstanceID); err != nil {
			result = errors.Join(result, err)
		}
	}
	for _, desired := range blocks {
		runtime, exists := runtimes[desired.PluginID]
		if !exists {
			result = errors.Join(result, fmt.Errorf("plugin %s is unavailable", desired.PluginID))
			continue
		}
		if !nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityDynamicBlocking) {
			result = errors.Join(result, fmt.Errorf("plugin %s lacks dynamic blocking", desired.PluginID))
			continue
		}
		needed, err := engine.store.BlocksNeedApply(desired, runtime.InstanceID)
		if err != nil {
			result = errors.Join(result, err)
			continue
		}
		if !needed {
			continue
		}
		if err := engine.runtimes.ReplaceDynamicBlocks(ctx, desired.PluginID, desired.Request); err != nil {
			result = errors.Join(result, fmt.Errorf("apply plugin %s dynamic blocks: %w", desired.PluginID, err))
			continue
		}
		if err := engine.store.MarkBlocksApplied(desired, runtime.InstanceID); err != nil {
			result = errors.Join(result, err)
		}
	}
	return result
}

func (engine *Engine) queueTraffic() error {
	values, err := engine.store.PendingTrafficSnapshots(engine.now())
	if err != nil {
		return err
	}
	sink := engine.eventSink()
	if sink == nil {
		return errors.New("policy event sink is not configured")
	}
	for _, value := range values {
		if _, err := sink.Enqueue(agentv1.EventTrafficSnapshot, engine.now(), value); err != nil {
			return err
		}
		if err := engine.store.MarkTrafficQueued(value); err != nil {
			return err
		}
	}
	return nil
}

func (engine *Engine) queueStatuses() error {
	values, err := engine.store.PendingStatuses()
	if err != nil {
		return err
	}
	sink := engine.eventSink()
	if sink == nil {
		return errors.New("policy event sink is not configured")
	}
	for _, value := range values {
		if _, err := sink.Enqueue(agentv1.EventPolicyStatus, engine.now(), value); err != nil {
			return err
		}
		if err := engine.store.MarkStatusQueued(value); err != nil {
			return err
		}
	}
	return nil
}

func (engine *Engine) eventSink() eventSink {
	engine.mu.Lock()
	defer engine.mu.Unlock()
	return engine.events
}

func runtimeMap(values []plugin.RuntimeInfo) map[string]plugin.RuntimeInfo {
	result := make(map[string]plugin.RuntimeInfo, len(values))
	for _, value := range values {
		result[value.PluginID] = value
	}
	return result
}

func runtimeInstances(values map[string]plugin.RuntimeInfo) map[string]string {
	result := make(map[string]string, len(values))
	for pluginID, value := range values {
		result[pluginID] = value.InstanceID
	}
	return result
}

func validateCapabilities(value agentv1.PolicyReconcileCommand, runtimes map[string]plugin.RuntimeInfo) (bool, error) {
	missing := false
	for _, policy := range value.Authorizations {
		for _, binding := range policy.Bindings {
			runtime, exists := runtimes[binding.PluginID]
			if !exists {
				missing = true
				continue
			}
			if !nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityTrafficCounters) ||
				!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityServiceControl) {
				return false, fmt.Errorf("a bound runtime plugin lacks traffic or service-control capability")
			}
			if policy.SoftIPLimit != nil &&
				(!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityRecentActivity) ||
					!nodepluginv1.HasCapability(runtime.Capabilities, nodepluginv1.CapabilityDynamicBlocking)) {
				return false, fmt.Errorf("a soft IP policy requires activity and dynamic-blocking capabilities")
			}
		}
	}
	return missing, nil
}

func policyFailure(code protocol.ErrorCode, message string, retryable bool) commandstate.Execution {
	return commandstate.Execution{Problem: &protocol.Problem{Code: code, Message: message, Retryable: retryable}}
}

var _ commandstate.Executor = (*Engine)(nil)
