package policy

import (
	"errors"
	"math"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	policyv1 "github.com/Relayward/relayward-sdk/policy/v1"
)

const testAuthorizationID = "123e4567-e89b-42d3-a456-426614174000"

func TestStoreAggregatesMonotonicCountersAcrossPluginsAndPeriods(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	limit := uint64(1000)
	command := testPolicyCommand(t, now, &limit, nil, []agentv1.ServiceBinding{
		{PluginID: "io.relayward.alpha", ServiceID: "main"},
		{PluginID: "io.relayward.beta", ServiceID: "main"},
	})
	if changed, err := store.Reconcile(command); err != nil || !changed {
		t.Fatalf("Reconcile() = %v, %v", changed, err)
	}
	if changed, err := store.Reconcile(command); err != nil || changed {
		t.Fatalf("replayed Reconcile() = %v, %v", changed, err)
	}
	conflict := command
	conflict.Authorizations = append([]agentv1.AuthorizationPolicy(nil), command.Authorizations...)
	conflict.Authorizations[0].Enabled = false
	if _, err := store.Reconcile(conflict); !errors.Is(err, ErrGenerationConflict) {
		t.Fatalf("conflicting Reconcile() error = %v", err)
	}

	initial := pendingTraffic(t, store, now)
	if initial.Revision != 1 || initial.UploadBytes != 0 || initial.DownloadBytes != 0 {
		t.Fatalf("initial traffic = %+v", initial)
	}
	if err := store.MarkTrafficQueued(initial); err != nil {
		t.Fatal(err)
	}
	applyCounter(t, store, "io.relayward.alpha", "epoch-1", 100, 200, now)
	applyCounter(t, store, "io.relayward.alpha", "epoch-1", 100, 200, now.Add(time.Second))
	applyCounter(t, store, "io.relayward.beta", "epoch-1", 50, 50, now.Add(2*time.Second))
	applyCounter(t, store, "io.relayward.alpha", "epoch-1", 110, 220, now.Add(3*time.Second))
	applyCounter(t, store, "io.relayward.alpha", "epoch-1", 5, 6, now.Add(4*time.Second))
	traffic := pendingTraffic(t, store, now.Add(5*time.Second))
	if traffic.UploadBytes != 165 || traffic.DownloadBytes != 276 || traffic.Revision != 5 {
		t.Fatalf("aggregated traffic = %+v", traffic)
	}
	if err := store.ApplyCounters("io.relayward.alpha", []*nodepluginv1.TrafficCounter{{
		AuthorizationId: testAuthorizationID, ServiceId: "main", CounterEpoch: "overflow",
		UploadBytes: math.MaxInt64 + 1,
	}}, now.Add(6*time.Second)); err == nil {
		t.Fatal("ApplyCounters() accepted bytes above durable ledger capacity")
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	persisted := pendingTraffic(t, store, now.Add(6*time.Second))
	if persisted.AuthorizationID != traffic.AuthorizationID || persisted.Period.ID != traffic.Period.ID ||
		persisted.Revision != traffic.Revision || persisted.UploadBytes != traffic.UploadBytes || persisted.DownloadBytes != traffic.DownloadBytes {
		t.Fatalf("persisted traffic = %+v, want %+v", persisted, traffic)
	}
	periods, err := store.PendingTrafficSnapshots(now.Add(24 * time.Hour))
	if err != nil || len(periods) != 2 {
		t.Fatalf("period rollover snapshots = %+v, %v", periods, err)
	}
	if !sameTrafficSnapshot(periods[0], traffic) {
		t.Fatalf("pending previous period = %+v, want %+v", periods[0], traffic)
	}
	nextPeriod := periods[1]
	if nextPeriod.Period.ID == traffic.Period.ID || nextPeriod.UploadBytes != 0 || nextPeriod.DownloadBytes != 0 || nextPeriod.Revision != 1 {
		t.Fatalf("next period traffic = %+v", nextPeriod)
	}
}

func TestStoreSoftIPSlotsBlocksAndRestartReapply(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	softLimit := uint32(2)
	command := testPolicyCommand(t, now, nil, &softLimit, []agentv1.ServiceBinding{
		{PluginID: "io.relayward.alpha", ServiceID: "main"},
		{PluginID: "io.relayward.alpha", ServiceID: "secondary"},
	})
	if _, err := store.Reconcile(command); err != nil {
		t.Fatal(err)
	}
	for index, address := range []string{"192.0.2.1", "192.0.2.2"} {
		blocked, err := store.ObserveActivity(testAuthorizationID, address, now.Add(time.Duration(index)*time.Second))
		if err != nil || blocked {
			t.Fatalf("allowed activity %s = %v, %v", address, blocked, err)
		}
	}
	blocked, err := store.ObserveActivity(testAuthorizationID, "192.0.2.3", now.Add(2*time.Second))
	if err != nil || !blocked {
		t.Fatalf("third activity = %v, %v", blocked, err)
	}
	services, blocks, err := store.Desired(now.Add(3 * time.Second))
	if err != nil || len(services) != 2 || len(blocks) != 1 || len(blocks[0].Request.Blocks) != 2 {
		t.Fatalf("Desired() services=%d blocks=%+v error=%v", len(services), blocks, err)
	}
	if blocks[0].Request.Blocks[0].SourceIp != "192.0.2.3" {
		t.Fatalf("blocked source = %+v", blocks[0].Request.Blocks)
	}
	needs, err := store.BlocksNeedApply(blocks[0], "process-1")
	if err != nil || !needs {
		t.Fatalf("BlocksNeedApply() = %v, %v", needs, err)
	}
	if err := store.MarkBlocksApplied(blocks[0], "process-1"); err != nil {
		t.Fatal(err)
	}
	if err := store.RefreshStatuses(now.Add(3*time.Second), map[string]string{"io.relayward.alpha": "process-1"}); err != nil {
		t.Fatal(err)
	}
	if statuses, err := store.PendingStatuses(); err != nil || len(statuses) != 0 {
		t.Fatalf("unapplied service status = %+v, %v", statuses, err)
	}
	for _, service := range services {
		if err := store.MarkServiceApplied(service, "process-1"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.RefreshStatuses(now.Add(3*time.Second), map[string]string{"io.relayward.alpha": "process-1"}); err != nil {
		t.Fatal(err)
	}
	needs, _ = store.BlocksNeedApply(blocks[0], "process-1")
	if needs {
		t.Fatal("same process unexpectedly needs block reapply")
	}
	needs, _ = store.BlocksNeedApply(blocks[0], "process-2")
	if !needs {
		t.Fatal("new process did not require block reapply")
	}
	statuses, err := store.PendingStatuses()
	if err != nil || len(statuses) != 1 || statuses[0].ActiveIPCount != 2 || statuses[0].BlockedIPCount != 1 {
		t.Fatalf("policy statuses = %+v, %v", statuses, err)
	}
	_, expiredBlocks, err := store.Desired(now.Add(31 * time.Minute))
	if err != nil || len(expiredBlocks) != 1 || len(expiredBlocks[0].Request.Blocks) != 0 {
		t.Fatalf("expired block set = %+v, %v", expiredBlocks, err)
	}
}

func TestStoreReaddedBindingCancelsPendingOrphan(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	binding := agentv1.ServiceBinding{PluginID: "io.relayward.alpha", ServiceID: "main"}
	command := testPolicyCommand(t, now, nil, nil, []agentv1.ServiceBinding{binding})
	if _, err := store.Reconcile(command); err != nil {
		t.Fatal(err)
	}
	withoutBinding := command
	withoutBinding.Generation++
	withoutBinding.Authorizations = append([]agentv1.AuthorizationPolicy(nil), command.Authorizations...)
	withoutBinding.Authorizations[0].Bindings = nil
	if _, err := store.Reconcile(withoutBinding); err != nil {
		t.Fatal(err)
	}
	readded := command
	readded.Generation = withoutBinding.Generation + 1
	if _, err := store.Reconcile(readded); err != nil {
		t.Fatal(err)
	}
	services, _, err := store.Desired(now)
	if err != nil || len(services) != 1 || services[0].Orphan || !services[0].Request.Enabled {
		t.Fatalf("readded binding desired state = %+v, %v", services, err)
	}
}

func TestStoreRemovalPreservesUnqueuedTraffic(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	command := testPolicyCommand(t, now, nil, nil, []agentv1.ServiceBinding{{PluginID: "io.relayward.alpha", ServiceID: "main"}})
	if _, err := store.Reconcile(command); err != nil {
		t.Fatal(err)
	}
	applyCounter(t, store, "io.relayward.alpha", "epoch", 10, 20, now)
	removed := command
	removed.Generation++
	removed.Authorizations = nil
	if _, err := store.Reconcile(removed); err != nil {
		t.Fatal(err)
	}
	values, err := store.PendingTrafficSnapshots(now)
	if err != nil || len(values) != 1 || values[0].UploadBytes != 10 || values[0].DownloadBytes != 20 {
		t.Fatalf("removed authorization traffic = %+v, %v", values, err)
	}
	if err := store.MarkTrafficQueued(values[0]); err != nil {
		t.Fatal(err)
	}
	if values, err = store.PendingTrafficSnapshots(now); err != nil || len(values) != 0 {
		t.Fatalf("queued removed traffic remains = %+v, %v", values, err)
	}
}

func TestStoreOutOfOrderActivityDoesNotRegressSlot(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	softLimit := uint32(1)
	command := testPolicyCommand(t, now, nil, &softLimit, nil)
	if _, err := store.Reconcile(command); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ObserveActivity(testAuthorizationID, "192.0.2.1", now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ObserveActivity(testAuthorizationID, "192.0.2.1", now.Add(-time.Minute)); err != nil {
		t.Fatal(err)
	}
	if blocked, err := store.ObserveActivity(testAuthorizationID, "192.0.2.2", now.Add(9*time.Minute+30*time.Second)); err != nil || !blocked {
		t.Fatalf("out-of-order slot activity = %v, %v", blocked, err)
	}
}

func TestStoreServiceTransitionsOrphansAndTelemetryStreams(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "policy.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 2, 12, 0, 0, 0, time.UTC)
	limit := uint64(10)
	command := testPolicyCommand(t, now, &limit, nil, []agentv1.ServiceBinding{{PluginID: "io.relayward.alpha", ServiceID: "main"}})
	if _, err := store.Reconcile(command); err != nil {
		t.Fatal(err)
	}
	applyCounter(t, store, "io.relayward.alpha", "epoch", 4, 6, now)
	services, _, err := store.Desired(now)
	if err != nil || len(services) != 1 || services[0].Request.Enabled ||
		services[0].Request.Reason != nodepluginv1.ServiceStateReason_SERVICE_STATE_REASON_QUOTA_EXCEEDED {
		t.Fatalf("quota desired service = %+v, %v", services, err)
	}
	if err := store.MarkServiceApplied(services[0], "process-1"); err != nil {
		t.Fatal(err)
	}
	needs, _ := store.ServiceNeedsApply(services[0], "process-1")
	if needs {
		t.Fatal("same process unexpectedly needs service reapply")
	}
	needs, _ = store.ServiceNeedsApply(services[0], "process-2")
	if !needs {
		t.Fatal("new process did not require service reapply")
	}
	next := command
	next.Generation++
	next.Authorizations = nil
	if _, err := store.Reconcile(next); err != nil {
		t.Fatal(err)
	}
	orphans, _, err := store.Desired(now)
	if err != nil || len(orphans) != 1 || !orphans[0].Orphan || orphans[0].Request.Enabled {
		t.Fatalf("orphan service = %+v, %v", orphans, err)
	}
	if err := store.MarkServiceApplied(orphans[0], "process-2"); err != nil {
		t.Fatal(err)
	}
	orphans, _, _ = store.Desired(now)
	if len(orphans) != 0 {
		t.Fatalf("applied orphan remains = %+v", orphans)
	}

	streamOne := "0123456789abcdef0123456789abcdef"
	streamTwo := "1123456789abcdef0123456789abcdef"
	if cursor, _ := store.TelemetryCursor("io.relayward.alpha", streamOne); cursor != 0 {
		t.Fatalf("initial cursor = %d", cursor)
	}
	if err := store.AdvanceTelemetryCursor("io.relayward.alpha", streamOne, 0, 7); err != nil {
		t.Fatal(err)
	}
	if cursor, _ := store.TelemetryCursor("io.relayward.alpha", streamOne); cursor != 7 {
		t.Fatalf("persisted cursor = %d", cursor)
	}
	if cursor, _ := store.TelemetryCursor("io.relayward.alpha", streamTwo); cursor != 0 {
		t.Fatalf("new stream cursor = %d", cursor)
	}
	if err := store.AdvanceTelemetryCursor("io.relayward.alpha", streamTwo, 0, 1); err != nil {
		t.Fatal(err)
	}
}

func testPolicyCommand(t *testing.T, now time.Time, limit *uint64, softLimit *uint32, bindings []agentv1.ServiceBinding) agentv1.PolicyReconcileCommand {
	t.Helper()
	started := now.Add(-12 * time.Hour)
	rule := policyv1.ResetRule{Kind: policyv1.ResetDaily, Timezone: "UTC"}
	period, err := policyv1.CurrentPeriod(rule, started, now)
	if err != nil {
		t.Fatal(err)
	}
	return agentv1.PolicyReconcileCommand{Generation: 1, Authorizations: []agentv1.AuthorizationPolicy{{
		AuthorizationID: testAuthorizationID, StartedAt: started, Enabled: true,
		TrafficLimitBytes: limit, Reset: rule, CurrentPeriod: period, SoftIPLimit: softLimit,
		ActivityWindowSeconds: 600, BlockDurationSeconds: 1800, Bindings: bindings,
	}}}
}

func applyCounter(t *testing.T, store *Store, pluginID, epoch string, upload, download uint64, now time.Time) {
	t.Helper()
	err := store.ApplyCounters(pluginID, []*nodepluginv1.TrafficCounter{{
		AuthorizationId: testAuthorizationID, ServiceId: "main", CounterEpoch: epoch,
		UploadBytes: upload, DownloadBytes: download,
	}}, now)
	if err != nil {
		t.Fatalf("ApplyCounters() error = %v", err)
	}
}

func pendingTraffic(t *testing.T, store *Store, now time.Time) agentv1.TrafficSnapshotEvent {
	t.Helper()
	values, err := store.PendingTrafficSnapshots(now)
	if err != nil || len(values) != 1 {
		t.Fatalf("PendingTrafficSnapshots() = %+v, %v", values, err)
	}
	return values[0]
}
