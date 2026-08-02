package plugin

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
)

type memoryEventSink struct {
	mu     sync.Mutex
	events []agentv1.PluginStatusEvent
}

func (sink *memoryEventSink) Enqueue(kind string, _ time.Time, payload any) (agentv1.Event, error) {
	if kind != agentv1.EventPluginStatus {
		return agentv1.Event{}, nil
	}
	value := payload.(agentv1.PluginStatusEvent)
	sink.mu.Lock()
	sink.events = append(sink.events, value)
	sink.mu.Unlock()
	return agentv1.Event{}, nil
}

func TestSupervisorReconcilesRunningRollbackStoppedAndAbsent(t *testing.T) {
	executable, err := os.ReadFile(copyTestExecutable(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executable)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(executable)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)

	stateDirectory := shortTempDir(t)
	supervisor, err := NewSupervisor(stateDirectory, nil)
	if err != nil {
		t.Fatal(err)
	}
	supervisor.installer = newInstaller(supervisor.store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != serverURL.Host {
			return context.Canceled
		}
		return nil
	})
	sink := &memoryEventSink{}
	supervisor.SetEventSink(sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}

	running := testReconcileCommand(1, agentv1.PluginStateRunning, server.URL, int64(len(executable)), hex.EncodeToString(digest[:]), json.RawMessage(`{"enabled":true}`))
	execution := executeReconcile(t, supervisor, running)
	if execution.Problem != nil {
		t.Fatalf("running reconcile problem = %+v", execution.Problem)
	}
	output, err := agentv1.DecodePluginReconcileOutput(execution.Output)
	if err != nil || output.State != agentv1.PluginStateRunning || output.Generation != 1 {
		t.Fatalf("running output = %+v, error = %v", output, err)
	}
	actor := supervisor.actor(running.PluginID)
	actor.mu.Lock()
	crashed := actor.process
	actor.mu.Unlock()
	if crashed == nil {
		t.Fatal("running plugin process is missing")
	}
	if err := syscall.Kill(-crashed.command.Process.Pid, syscall.SIGKILL); err != nil {
		t.Fatalf("kill plugin process: %v", err)
	}
	eventually(t, 5*time.Second, func() bool {
		actor.mu.Lock()
		defer actor.mu.Unlock()
		return actor.process != nil && actor.process != crashed && !actor.process.exited()
	})
	_, restartCount, err := supervisor.store.current(running.PluginID)
	if err != nil || restartCount != 1 {
		t.Fatalf("restart count = %d, error = %v", restartCount, err)
	}

	closeContext, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	if err := supervisor.Close(closeContext); err != nil {
		t.Fatalf("first Close() error = %v", err)
	}
	closeCancel()
	cancel()
	supervisor, err = NewSupervisor(stateDirectory, nil)
	if err != nil {
		t.Fatalf("reopen supervisor: %v", err)
	}
	supervisor.installer = newInstaller(supervisor.store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != serverURL.Host {
			return context.Canceled
		}
		return nil
	})
	supervisor.SetEventSink(sink)
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatalf("restart supervisor: %v", err)
	}
	actor = supervisor.actor(running.PluginID)
	actor.mu.Lock()
	recovered := actor.process != nil && !actor.process.exited()
	actor.mu.Unlock()
	if !recovered {
		t.Fatal("durable running plugin was not recovered after supervisor restart")
	}

	rejected := testReconcileCommand(2, agentv1.PluginStateRunning, server.URL, int64(len(executable)), hex.EncodeToString(digest[:]), json.RawMessage(`{"reject":true}`))
	execution = executeReconcile(t, supervisor, rejected)
	if execution.Problem == nil {
		t.Fatal("rejected reconcile unexpectedly succeeded")
	}
	current, _, err := supervisor.store.current(running.PluginID)
	if err != nil || current == nil || current.Generation != 1 || current.State != agentv1.PluginStateRunning {
		t.Fatalf("current state after rollback = %+v, error = %v", current, err)
	}
	actor = supervisor.actor(running.PluginID)
	actor.mu.Lock()
	rolledBack := actor.process != nil && !actor.process.exited()
	actor.mu.Unlock()
	if !rolledBack {
		t.Fatal("previous running process was not restored")
	}
	sink.mu.Lock()
	lastAfterRollback := sink.events[len(sink.events)-1]
	sink.mu.Unlock()
	if lastAfterRollback.State != agentv1.PluginStateRunning || lastAfterRollback.Generation != 1 {
		t.Fatalf("status after rollback = %+v", lastAfterRollback)
	}

	stopped := testReconcileCommand(3, agentv1.PluginStateStopped, server.URL, int64(len(executable)), hex.EncodeToString(digest[:]), json.RawMessage(`{"enabled":false}`))
	if execution = executeReconcile(t, supervisor, stopped); execution.Problem != nil {
		t.Fatalf("stopped reconcile problem = %+v", execution.Problem)
	}
	absent := agentv1.PluginReconcileCommand{PluginID: running.PluginID, Generation: 4, DesiredState: agentv1.PluginStateAbsent}
	if execution = executeReconcile(t, supervisor, absent); execution.Problem != nil {
		t.Fatalf("absent reconcile problem = %+v", execution.Problem)
	}
	current, _, _ = supervisor.store.current(running.PluginID)
	if current == nil || current.State != agentv1.PluginStateAbsent || current.Generation != 4 {
		t.Fatalf("final current state = %+v", current)
	}
	if _, err := os.Stat(supervisor.store.dataPath(running.PluginID)); !os.IsNotExist(err) {
		t.Fatalf("plugin data remains after absent reconcile: %v", err)
	}
	sink.mu.Lock()
	if len(sink.events) < 4 {
		t.Errorf("status events = %d, want at least 4", len(sink.events))
	}
	sink.mu.Unlock()
	closeContext, closeCancel = context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := supervisor.Close(closeContext); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func TestSupervisorRestartsPluginAfterRepeatedUnhealthyStatus(t *testing.T) {
	executable, err := os.ReadFile(copyTestExecutable(t, t.TempDir()))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(executable)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(executable)
	}))
	defer server.Close()
	serverURL, _ := url.Parse(server.URL)
	supervisor, err := NewSupervisor(shortTempDir(t), nil)
	if err != nil {
		t.Fatal(err)
	}
	supervisor.healthCheckInterval = 20 * time.Millisecond
	supervisor.installer = newInstaller(supervisor.store, server.Client(), func(candidate *url.URL) error {
		if candidate.Host != serverURL.Host {
			return context.Canceled
		}
		return nil
	})
	sink := &memoryEventSink{}
	supervisor.SetEventSink(sink)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := supervisor.Start(ctx); err != nil {
		t.Fatal(err)
	}
	running := testReconcileCommand(1, agentv1.PluginStateRunning, server.URL, int64(len(executable)), hex.EncodeToString(digest[:]), json.RawMessage(`{"degrade":true}`))
	if execution := executeReconcile(t, supervisor, running); execution.Problem != nil {
		t.Fatalf("running reconcile problem = %+v", execution.Problem)
	}
	eventually(t, 3*time.Second, func() bool {
		_, restartCount, _ := supervisor.store.current(running.PluginID)
		return restartCount >= 1
	})
	sink.mu.Lock()
	foundFailure := false
	for _, event := range sink.events {
		if event.State == agentv1.PluginStateFailed && event.Reason == "plugin health checks failed" {
			foundFailure = true
		}
	}
	sink.mu.Unlock()
	if !foundFailure {
		t.Fatal("repeated unhealthy status did not emit a failed plugin status")
	}
	closeContext, closeCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer closeCancel()
	if err := supervisor.Close(closeContext); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
}

func eventually(t *testing.T, timeout time.Duration, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("condition was not satisfied before the deadline")
}

func executeReconcile(t *testing.T, supervisor *Supervisor, value agentv1.PluginReconcileCommand) commandstate.Execution {
	t.Helper()
	now := time.Now().UTC()
	command, err := agentv1.NewPluginReconcileCommand(value, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return supervisor.Execute(ctx, "test-command", command)
}

func testReconcileCommand(generation uint64, state, downloadURL string, size int64, digest string, configuration json.RawMessage) agentv1.PluginReconcileCommand {
	return agentv1.PluginReconcileCommand{
		PluginID: "io.relayward.test", Generation: generation, DesiredState: state, Version: "1.2.3",
		Artifact: &agentv1.PluginArtifact{DownloadURL: downloadURL, Size: size, SHA256: digest}, Configuration: configuration,
	}
}
