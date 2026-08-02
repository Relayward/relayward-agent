package update

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
)

func TestExecutorCompletesOnlyAfterCandidateHealthConfirmation(t *testing.T) {
	manager, stateDirectory := testReleaseManager(t, "0.2.0", []byte("candidate"))
	now := time.Now().UTC()
	command, err := agentv1.NewAgentUpdateCommand("0.2.0", now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("NewAgentUpdateCommand() error = %v", err)
	}
	envelope, err := agentv1.NewCommandEnvelope("command-update", command)
	if err != nil {
		t.Fatalf("NewCommandEnvelope() error = %v", err)
	}
	store, err := commandstate.OpenStore(stateDirectory)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	oldProcessor := commandstate.NewProcessor(store, NewExecutor(manager, "0.1.0"))
	if err := oldProcessor.Accept(envelope, now); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := oldProcessor.Run(context.Background()); !errors.Is(err, commandstate.ErrRestartRequired) {
		t.Fatalf("old Processor.Run() error = %v", err)
	}
	if _, err := oldProcessor.NextResult(); !errors.Is(err, commandstate.ErrNotFound) {
		t.Fatalf("old NextResult() error = %v", err)
	}

	newManager, err := newManager(stateDirectory, manager.runtimeAssetsPath, manager.baseURL, manager.repository, true, manager.httpClient)
	if err != nil {
		t.Fatalf("newManager() candidate error = %v", err)
	}
	newProcessor := commandstate.NewProcessor(store, NewExecutor(newManager, "0.2.0"))
	done := make(chan error, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { done <- newProcessor.Run(ctx) }()
	select {
	case <-newProcessor.Results():
		t.Fatal("candidate completed update before health confirmation")
	case <-time.After(50 * time.Millisecond):
	}
	if confirmed, err := newManager.Confirm("0.2.0"); err != nil || !confirmed {
		t.Fatalf("Confirm() = %v, %v", confirmed, err)
	}
	select {
	case <-newProcessor.Results():
	case <-time.After(time.Second):
		t.Fatal("candidate did not complete update after health confirmation")
	}
	result, err := newProcessor.NextResult()
	if err != nil || result.Status != agentv1.CommandStatusSucceeded {
		t.Fatalf("NextResult() = %+v, %v", result, err)
	}
	output, err := agentv1.DecodeAgentUpdateOutput(result.Output)
	if err != nil || output.Version != "0.2.0" || output.State != agentv1.AgentUpdateStateActivated {
		t.Fatalf("update output = %+v, %v", output, err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("candidate Processor.Run() error = %v", err)
	}

	reopened, err := commandstate.OpenStore(stateDirectory)
	if err != nil {
		t.Fatalf("OpenStore() after completion error = %v", err)
	}
	if result, err := reopened.NextResult(); err != nil || result.CommandID != "command-update" {
		t.Fatalf("durable update result = %+v, %v", result, err)
	}
}

func TestExecutorReportsLauncherRollback(t *testing.T) {
	manager, stateDirectory := testReleaseManager(t, "0.2.0", []byte("candidate"))
	if _, err := manager.Prepare(context.Background(), "command-update", "0.2.0", "0.1.0"); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	if err := os.Rename(
		filepath.Join(stateDirectory, pendingFilename),
		filepath.Join(stateDirectory, failedFilename),
	); err != nil {
		t.Fatalf("record failed state: %v", err)
	}
	now := time.Now().UTC()
	command, _ := agentv1.NewAgentUpdateCommand("0.2.0", now, now.Add(time.Hour))
	execution := NewExecutor(manager, "0.1.0").Execute(context.Background(), "command-update", command)
	if execution.Problem == nil || execution.Problem.Retryable || execution.Restart {
		t.Fatalf("rollback execution = %+v", execution)
	}
}

func TestExecutorLeavesCandidateCommandPendingWhenInterrupted(t *testing.T) {
	manager, _ := testReleaseManager(t, "0.2.0", []byte("candidate"))
	if _, err := manager.Prepare(context.Background(), "command-update", "0.2.0", "0.1.0"); err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	now := time.Now().UTC()
	command, _ := agentv1.NewAgentUpdateCommand("0.2.0", now, now.Add(time.Hour))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	execution := NewExecutor(manager, "0.2.0").Execute(ctx, "command-update", command)
	if !execution.Restart || execution.Problem != nil || execution.Output != nil {
		t.Fatalf("interrupted activation execution = %+v", execution)
	}
}
