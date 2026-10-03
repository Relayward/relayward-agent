package policy

import (
	"context"
	"github.com/Relayward/relayward-agent/internal/plugin"
	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	node "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"log/slog"
	"path/filepath"
	"testing"
	"time"
)

func TestCollectionStatusIsIndependentOfAccessCount(t *testing.T) {
	host := &fakeRuntimeHost{telemetry: map[string]*node.CollectTelemetryResponse{"io.relayward.alpha": {CollectionStatus: "disabled", ObservedAtUnixNano: time.Now().UnixNano()}}}
	engine, err := NewEngine(filepath.Join(t.TempDir(), "policy.db"), host, slog.Default())
	if err != nil {
		t.Fatal(err)
	}
	defer engine.Close()
	sink := &memorySink{}
	engine.SetEventSink(sink)
	runtime := plugin.RuntimeInfo{PluginID: "io.relayward.alpha"}
	if err = engine.collectRuntime(context.Background(), runtime); err != nil {
		t.Fatal(err)
	}
	if countEvents(sink, agentv1.EventAccess) != 0 || countEvents(sink, agentv1.EventCollection) != 1 {
		t.Fatal("collection status changed access count")
	}
	if sink.events[0].payload.(agentv1.CollectionEvent).Status != "disabled" {
		t.Fatal("collection status lost")
	}
	runtime.Capabilities = []string{node.CapabilityRecentActivity}
	if err = engine.collectRuntime(context.Background(), runtime); err == nil {
		t.Fatal("invalid telemetry succeeded")
	}
	if sink.events[len(sink.events)-1].payload.(agentv1.CollectionEvent).Status != "incomplete" {
		t.Fatal("failure did not produce incomplete status")
	}
}
