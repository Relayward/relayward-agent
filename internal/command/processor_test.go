package command

import (
	"context"
	"encoding/json"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

func TestProcessorExecutesDuplicateCommandOnceAndReplaysResult(t *testing.T) {
	directory := t.TempDir()
	store, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	now := time.Now().UTC()
	var executions atomic.Int32
	processor := NewProcessor(store, ExecutorFunc(func(_ context.Context, commandID string, value agentv1.Command) Execution {
		executions.Add(1)
		return Execution{Output: json.RawMessage(`{"command_id":"` + commandID + `"}`)}
	}))
	processor.now = func() time.Time { return now.Add(time.Minute) }
	envelope, err := agentv1.NewCommandEnvelope("command-1", testCommand(now))
	if err != nil {
		t.Fatalf("NewCommandEnvelope() error = %v", err)
	}
	if err := processor.Accept(envelope, now); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := processor.Accept(envelope, now.Add(time.Second)); err != nil {
		t.Fatalf("duplicate Accept() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- processor.Run(ctx) }()
	select {
	case <-processor.Results():
	case <-time.After(time.Second):
		t.Fatal("processor did not produce a result")
	}
	result, err := processor.NextResult()
	if err != nil || result.Status != agentv1.CommandStatusSucceeded {
		t.Fatalf("NextResult() = %+v, %v", result, err)
	}
	if executions.Load() != 1 {
		t.Fatalf("executor calls = %d, want 1", executions.Load())
	}
	if err := processor.Accept(envelope, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("post-completion Accept() error = %v", err)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("Run() error = %v", err)
	}

	reopened, err := OpenStore(directory)
	if err != nil {
		t.Fatalf("OpenStore() for replay error = %v", err)
	}
	restarted := NewProcessor(reopened, nil)
	restarted.now = processor.now
	restartCtx, restartCancel := context.WithCancel(context.Background())
	restartDone := make(chan error, 1)
	go func() { restartDone <- restarted.Run(restartCtx) }()
	select {
	case <-restarted.Results():
	case <-time.After(time.Second):
		t.Fatal("restarted processor did not expose the unacknowledged result")
	}
	replayed, err := restarted.NextResult()
	if err != nil || !commandResultsEqual(replayed, result) {
		t.Fatalf("replayed result = %+v, %v", replayed, err)
	}
	ack := agentv1.CommandResultAck{
		CommandID: result.CommandID, RequestSHA256: result.RequestSHA256, ServerTime: now.Add(2 * time.Minute),
	}
	if err := restarted.Acknowledge(ack, now.Add(2*time.Minute)); err != nil {
		t.Fatalf("Acknowledge() error = %v", err)
	}
	restartCancel()
	if err := <-restartDone; err != nil {
		t.Fatalf("restarted Run() error = %v", err)
	}
}

func TestProcessorDoesNotExecuteExpiredCommand(t *testing.T) {
	store, err := OpenStore(t.TempDir())
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	now := time.Date(2026, time.August, 2, 8, 0, 0, 0, time.UTC)
	var executions atomic.Int32
	processor := NewProcessor(store, ExecutorFunc(func(context.Context, string, agentv1.Command) Execution {
		executions.Add(1)
		return Execution{}
	}))
	processor.now = func() time.Time { return now.Add(2 * time.Hour) }
	envelope, _ := agentv1.NewCommandEnvelope("command-expired", testCommand(now))
	if err := processor.Accept(envelope, now); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- processor.Run(ctx) }()
	select {
	case <-processor.Results():
	case <-time.After(time.Second):
		t.Fatal("processor did not produce an expiry result")
	}
	result, err := processor.NextResult()
	if err != nil || result.Status != agentv1.CommandStatusFailed || result.Problem == nil || result.Problem.Message != "command expired before execution" {
		t.Fatalf("expired result = %+v, %v", result, err)
	}
	if executions.Load() != 0 {
		t.Fatalf("expired command executor calls = %d", executions.Load())
	}
	cancel()
	if err := <-done; err != nil && !errors.Is(err, context.Canceled) {
		t.Fatalf("Run() error = %v", err)
	}
}

func TestProcessorLeavesRestartingCommandPending(t *testing.T) {
	stateDirectory := t.TempDir()
	store, err := OpenStore(stateDirectory)
	if err != nil {
		t.Fatalf("OpenStore() error = %v", err)
	}
	now := time.Now().UTC()
	processor := NewProcessor(store, ExecutorFunc(func(context.Context, string, agentv1.Command) Execution {
		return Execution{Restart: true}
	}))
	processor.now = func() time.Time { return now }
	envelope, err := agentv1.NewCommandEnvelope("command-restart", testCommand(now))
	if err != nil {
		t.Fatalf("NewCommandEnvelope() error = %v", err)
	}
	if err := processor.Accept(envelope, now); err != nil {
		t.Fatalf("Accept() error = %v", err)
	}
	if err := processor.Run(context.Background()); !errors.Is(err, ErrRestartRequired) {
		t.Fatalf("Run() restart error = %v", err)
	}
	if _, err := processor.NextResult(); !errors.Is(err, ErrNotFound) {
		t.Fatalf("NextResult() after restart = %v", err)
	}
	reopened, err := OpenStore(stateDirectory)
	if err != nil {
		t.Fatalf("OpenStore() after restart error = %v", err)
	}
	if _, err := reopened.NextPending(); err != nil {
		t.Fatalf("NextPending() after restart error = %v", err)
	}
}
