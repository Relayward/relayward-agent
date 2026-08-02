package policy

import (
	"context"
	"errors"
	"log/slog"
	"path/filepath"
	"sync"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"github.com/Relayward/relayward-sdk/protocol"
	"google.golang.org/protobuf/proto"

	"github.com/Relayward/relayward-agent/internal/plugin"
)

type memorySink struct {
	mu     sync.Mutex
	events []queuedEvent
	fail   bool
}

type queuedEvent struct {
	kind       string
	observedAt time.Time
	payload    any
}

func (sink *memorySink) Enqueue(kind string, observedAt time.Time, payload any) (agentv1.Event, error) {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.fail {
		sink.fail = false
		return agentv1.Event{}, errors.New("queue full")
	}
	sink.events = append(sink.events, queuedEvent{kind: kind, observedAt: observedAt, payload: payload})
	return agentv1.Event{}, nil
}

type fakeRuntimeHost struct {
	mu           sync.Mutex
	runtimes     []plugin.RuntimeInfo
	telemetry    map[string]*nodepluginv1.CollectTelemetryResponse
	serviceCalls []*nodepluginv1.SetServiceStateRequest
	blockCalls   []*nodepluginv1.ReplaceDynamicBlocksRequest
	serviceErr   error
	blockErr     error
}

func (host *fakeRuntimeHost) RunningPlugins() []plugin.RuntimeInfo {
	host.mu.Lock()
	defer host.mu.Unlock()
	return append([]plugin.RuntimeInfo(nil), host.runtimes...)
}

func (host *fakeRuntimeHost) CollectTelemetry(_ context.Context, pluginID string, after uint64) (*nodepluginv1.CollectTelemetryResponse, error) {
	host.mu.Lock()
	defer host.mu.Unlock()
	value := host.telemetry[pluginID]
	if value == nil {
		return &nodepluginv1.CollectTelemetryResponse{ObservedAtUnixNano: time.Now().UnixNano(), NextSequence: after}, nil
	}
	copy := proto.Clone(value).(*nodepluginv1.CollectTelemetryResponse)
	copy.Events = nil
	for _, event := range value.Events {
		if event.Sequence > after {
			copy.Events = append(copy.Events, proto.Clone(event).(*nodepluginv1.AccessEvent))
		}
	}
	copy.NextSequence = after
	if len(copy.Events) > 0 {
		copy.NextSequence = copy.Events[len(copy.Events)-1].Sequence
	}
	copy.HasMore = false
	return copy, nil
}

func (host *fakeRuntimeHost) SetServiceState(_ context.Context, _ string, request *nodepluginv1.SetServiceStateRequest) error {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.serviceErr != nil {
		return host.serviceErr
	}
	host.serviceCalls = append(host.serviceCalls, proto.Clone(request).(*nodepluginv1.SetServiceStateRequest))
	return nil
}

func (host *fakeRuntimeHost) ReplaceDynamicBlocks(_ context.Context, _ string, request *nodepluginv1.ReplaceDynamicBlocksRequest) error {
	host.mu.Lock()
	defer host.mu.Unlock()
	if host.blockErr != nil {
		return host.blockErr
	}
	host.blockCalls = append(host.blockCalls, proto.Clone(request).(*nodepluginv1.ReplaceDynamicBlocksRequest))
	return nil
}

func TestEngineDoesNotReportPolicyStatusBeforePluginAppliesState(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	host := &fakeRuntimeHost{
		runtimes: []plugin.RuntimeInfo{{
			PluginID: "io.relayward.alpha", InstanceID: "alpha-1",
			Capabilities: []string{nodepluginv1.CapabilityServiceControl, nodepluginv1.CapabilityTrafficCounters},
		}},
		telemetry:  make(map[string]*nodepluginv1.CollectTelemetryResponse),
		serviceErr: errors.New("apply failed"),
	}
	engine, err := NewEngine(filepath.Join(t.TempDir(), "policy.db"), host, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.now = func() time.Time { return now }
	sink := &memorySink{}
	engine.SetEventSink(sink)
	policy := testPolicyCommand(t, now, nil, nil, []agentv1.ServiceBinding{{PluginID: "io.relayward.alpha", ServiceID: "main"}})
	command, _ := agentv1.NewPolicyReconcileCommand(policy, now, now.Add(time.Hour))
	execution := engine.Execute(context.Background(), "command", command)
	if execution.Problem == nil || !execution.Problem.Retryable {
		t.Fatalf("failed apply execution = %+v", execution.Problem)
	}
	if countEvents(sink, agentv1.EventPolicyStatus) != 0 {
		t.Fatal("policy status was queued before service state applied")
	}
	host.serviceErr = nil
	if err := engine.runCycle(context.Background()); err != nil {
		t.Fatal(err)
	}
	if countEvents(sink, agentv1.EventPolicyStatus) != 1 {
		t.Fatalf("policy status event count = %d", countEvents(sink, agentv1.EventPolicyStatus))
	}
}

func TestEngineAggregatesTwoRuntimesEnforcesQuotaAndSoftIP(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	streamAlpha := "0123456789abcdef0123456789abcdef"
	streamBeta := "1123456789abcdef0123456789abcdef"
	capabilities := []string{
		nodepluginv1.CapabilityRecentActivity,
		nodepluginv1.CapabilityDynamicBlocking,
		nodepluginv1.CapabilityServiceControl,
		nodepluginv1.CapabilityTrafficCounters,
	}
	host := &fakeRuntimeHost{
		runtimes: []plugin.RuntimeInfo{
			{PluginID: "io.relayward.alpha", InstanceID: "alpha-1", Capabilities: capabilities, TelemetryStreamID: streamAlpha},
			{PluginID: "io.relayward.beta", InstanceID: "beta-1", Capabilities: capabilities, TelemetryStreamID: streamBeta},
		},
		telemetry: make(map[string]*nodepluginv1.CollectTelemetryResponse),
	}
	engine, err := NewEngine(filepath.Join(t.TempDir(), "policy.db"), host, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.now = func() time.Time { return now }
	sink := &memorySink{}
	engine.SetEventSink(sink)
	limit := uint64(400)
	softLimit := uint32(2)
	policy := testPolicyCommand(t, now, &limit, &softLimit, []agentv1.ServiceBinding{
		{PluginID: "io.relayward.alpha", ServiceID: "main"},
		{PluginID: "io.relayward.beta", ServiceID: "main"},
	})
	command, err := agentv1.NewPolicyReconcileCommand(policy, now, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	execution := engine.Execute(context.Background(), "command-1", command)
	if execution.Problem != nil {
		t.Fatalf("initial policy execution = %+v", execution.Problem)
	}
	output, err := agentv1.DecodePolicyReconcileOutput(execution.Output)
	if err != nil || output.Generation != 1 || output.AuthorizationCount != 1 {
		t.Fatalf("policy output = %+v, %v", output, err)
	}
	if len(host.serviceCalls) != 2 || len(host.blockCalls) != 2 {
		t.Fatalf("initial calls: services=%d blocks=%d", len(host.serviceCalls), len(host.blockCalls))
	}

	host.telemetry["io.relayward.alpha"] = telemetry(now,
		&nodepluginv1.TrafficCounter{AuthorizationId: testAuthorizationID, ServiceId: "main", CounterEpoch: "alpha-1", UploadBytes: 100, DownloadBytes: 200},
		access(1, "alpha-1", "192.0.2.1", now),
		access(2, "alpha-2", "192.0.2.2", now.Add(time.Second)),
	)
	host.telemetry["io.relayward.beta"] = telemetry(now,
		&nodepluginv1.TrafficCounter{AuthorizationId: testAuthorizationID, ServiceId: "main", CounterEpoch: "beta-1", UploadBytes: 50, DownloadBytes: 50},
		access(1, "beta-1", "192.0.2.3", now.Add(2*time.Second)),
	)
	if err := engine.runCycle(context.Background()); err != nil {
		t.Fatalf("runCycle() error = %v", err)
	}
	if len(host.serviceCalls) != 4 {
		t.Fatalf("quota did not disable both services: calls=%d", len(host.serviceCalls))
	}
	for _, call := range host.serviceCalls[len(host.serviceCalls)-2:] {
		if call.Enabled || call.Reason != nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_QUOTA_EXCEEDED {
			t.Fatalf("quota service call = %+v", call)
		}
	}
	if len(host.blockCalls) != 4 {
		t.Fatalf("soft IP block was not applied to both plugins: calls=%d", len(host.blockCalls))
	}
	for _, call := range host.blockCalls[len(host.blockCalls)-2:] {
		if len(call.Blocks) != 1 {
			t.Fatalf("dynamic block call = %+v", call)
		}
	}
	traffic := latestTrafficEvent(t, sink)
	if traffic.UploadBytes != 150 || traffic.DownloadBytes != 250 {
		t.Fatalf("traffic snapshot = %+v", traffic)
	}
	status := latestPolicyStatus(t, sink)
	if status.ServicesEnabled || status.Reason != agentv1.PolicyReasonQuotaExceeded ||
		status.ActiveIPCount != 2 || status.BlockedIPCount != 1 {
		t.Fatalf("policy status = %+v", status)
	}
	for _, queued := range sink.events {
		if queued.kind != agentv1.EventAccess {
			continue
		}
		access := queued.payload.(agentv1.AccessEvent)
		expected := streamAlpha
		if access.PluginID == "io.relayward.beta" {
			expected = streamBeta
		}
		if access.SourceStreamID != expected {
			t.Fatalf("access source stream = %q, want %q", access.SourceStreamID, expected)
		}
	}

	serviceCalls, blockCalls, eventCount := len(host.serviceCalls), len(host.blockCalls), len(sink.events)
	if err := engine.runCycle(context.Background()); err != nil {
		t.Fatalf("idempotent runCycle() error = %v", err)
	}
	if len(host.serviceCalls) != serviceCalls || len(host.blockCalls) != blockCalls || len(sink.events) != eventCount {
		t.Fatalf("idempotent cycle changed calls/events: services=%d blocks=%d events=%d", len(host.serviceCalls), len(host.blockCalls), len(sink.events))
	}

	host.runtimes[0].InstanceID = "alpha-2"
	host.runtimes[1].InstanceID = "beta-2"
	if err := engine.runCycle(context.Background()); err != nil {
		t.Fatalf("restart runCycle() error = %v", err)
	}
	if len(host.serviceCalls) != serviceCalls+2 || len(host.blockCalls) != blockCalls+2 {
		t.Fatalf("plugin restart did not replay state: services=%d blocks=%d", len(host.serviceCalls), len(host.blockCalls))
	}
}

func TestEngineQueueFailureLeavesAbsoluteTrafficPending(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	host := &fakeRuntimeHost{
		runtimes: []plugin.RuntimeInfo{{
			PluginID: "io.relayward.alpha", InstanceID: "alpha-1",
			Capabilities: []string{nodepluginv1.CapabilityServiceControl, nodepluginv1.CapabilityTrafficCounters},
		}},
		telemetry: map[string]*nodepluginv1.CollectTelemetryResponse{
			"io.relayward.alpha": telemetry(now, &nodepluginv1.TrafficCounter{
				AuthorizationId: testAuthorizationID, ServiceId: "main", CounterEpoch: "epoch", UploadBytes: 10, DownloadBytes: 20,
			}),
		},
	}
	engine, err := NewEngine(filepath.Join(t.TempDir(), "policy.db"), host, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.now = func() time.Time { return now }
	sink := &memorySink{}
	engine.SetEventSink(sink)
	policy := testPolicyCommand(t, now, nil, nil, []agentv1.ServiceBinding{{PluginID: "io.relayward.alpha", ServiceID: "main"}})
	command, _ := agentv1.NewPolicyReconcileCommand(policy, now, now.Add(time.Hour))
	if execution := engine.Execute(context.Background(), "command", command); execution.Problem != nil {
		t.Fatal(execution.Problem)
	}
	sink.fail = true
	if err := engine.runCycle(context.Background()); err == nil {
		t.Fatal("runCycle() succeeded despite queue failure")
	}
	if err := engine.runCycle(context.Background()); err != nil {
		t.Fatalf("retry runCycle() error = %v", err)
	}
	traffic := latestTrafficEvent(t, sink)
	if traffic.UploadBytes != 10 || traffic.DownloadBytes != 20 {
		t.Fatalf("retried traffic snapshot = %+v", traffic)
	}
}

func TestEngineCapabilityGateAndUnavailablePersistence(t *testing.T) {
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	softLimit := uint32(2)
	host := &fakeRuntimeHost{
		runtimes: []plugin.RuntimeInfo{{
			PluginID: "io.relayward.alpha", InstanceID: "alpha",
			Capabilities: []string{nodepluginv1.CapabilityServiceControl, nodepluginv1.CapabilityTrafficCounters},
		}},
		telemetry: make(map[string]*nodepluginv1.CollectTelemetryResponse),
	}
	engine, err := NewEngine(filepath.Join(t.TempDir(), "policy.db"), host, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	engine.now = func() time.Time { return now }
	engine.SetEventSink(&memorySink{})
	policy := testPolicyCommand(t, now, nil, &softLimit, []agentv1.ServiceBinding{{PluginID: "io.relayward.alpha", ServiceID: "main"}})
	command, _ := agentv1.NewPolicyReconcileCommand(policy, now, now.Add(time.Hour))
	execution := engine.Execute(context.Background(), "command", command)
	if execution.Problem == nil || execution.Problem.Code != protocol.ErrorUnsupported {
		t.Fatalf("capability failure = %+v", execution.Problem)
	}
	if generation, _ := engine.store.Generation(); generation != 0 {
		t.Fatalf("unsupported policy was persisted at generation %d", generation)
	}

	host.runtimes = nil
	policy.Authorizations[0].SoftIPLimit = nil
	command, _ = agentv1.NewPolicyReconcileCommand(policy, now, now.Add(time.Hour))
	execution = engine.Execute(context.Background(), "command-2", command)
	if execution.Problem == nil || execution.Problem.Code != protocol.ErrorUnavailable || !execution.Problem.Retryable {
		t.Fatalf("unavailable failure = %+v", execution.Problem)
	}
	if generation, _ := engine.store.Generation(); generation != 1 {
		t.Fatalf("unavailable policy generation = %d", generation)
	}
	host.runtimes = []plugin.RuntimeInfo{{
		PluginID: "io.relayward.alpha", InstanceID: "alpha-incomplete",
		Capabilities: []string{nodepluginv1.CapabilityServiceControl},
	}}
	if err := engine.runCycle(context.Background()); err == nil {
		t.Fatal("runCycle() accepted a persisted policy with incomplete runtime capabilities")
	}
	if len(host.serviceCalls) != 0 || countEvents(engine.eventSink().(*memorySink), agentv1.EventPolicyStatus) != 0 {
		t.Fatalf("incomplete runtime applied policy: calls=%d", len(host.serviceCalls))
	}
}

func telemetry(now time.Time, counter *nodepluginv1.TrafficCounter, events ...*nodepluginv1.AccessEvent) *nodepluginv1.CollectTelemetryResponse {
	counters := []*nodepluginv1.TrafficCounter(nil)
	if counter != nil {
		counters = append(counters, counter)
	}
	return &nodepluginv1.CollectTelemetryResponse{
		ObservedAtUnixNano: now.UnixNano(), Counters: counters, Events: events,
	}
}

func access(sequence uint64, id, sourceIP string, now time.Time) *nodepluginv1.AccessEvent {
	return &nodepluginv1.AccessEvent{
		Sequence: sequence, EventId: id, ObservedAtUnixNano: now.UnixNano(),
		AuthorizationId: testAuthorizationID, ServiceId: "main", SourceIp: sourceIP,
		Destination: "example.com", DestinationPort: 443, Network: "tcp", Protocol: "tls", Action: agentv1.AccessActionAccepted,
	}
}

func latestTrafficEvent(t *testing.T, sink *memorySink) agentv1.TrafficSnapshotEvent {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for index := len(sink.events) - 1; index >= 0; index-- {
		if sink.events[index].kind == agentv1.EventTrafficSnapshot {
			return sink.events[index].payload.(agentv1.TrafficSnapshotEvent)
		}
	}
	t.Fatal("traffic event not found")
	return agentv1.TrafficSnapshotEvent{}
}

func latestPolicyStatus(t *testing.T, sink *memorySink) agentv1.PolicyStatusEvent {
	t.Helper()
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for index := len(sink.events) - 1; index >= 0; index-- {
		if sink.events[index].kind == agentv1.EventPolicyStatus {
			return sink.events[index].payload.(agentv1.PolicyStatusEvent)
		}
	}
	t.Fatal("policy status event not found")
	return agentv1.PolicyStatusEvent{}
}

func countEvents(sink *memorySink, kind string) int {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	count := 0
	for _, event := range sink.events {
		if event.kind == kind {
			count++
		}
	}
	return count
}
