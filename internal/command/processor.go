package command

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"
)

const cleanupInterval = time.Hour

type Executor interface {
	Execute(context.Context, string, agentv1.Command) (json.RawMessage, *protocol.Problem)
}

type ExecutorFunc func(context.Context, string, agentv1.Command) (json.RawMessage, *protocol.Problem)

func (function ExecutorFunc) Execute(ctx context.Context, commandID string, value agentv1.Command) (json.RawMessage, *protocol.Problem) {
	return function(ctx, commandID, value)
}

type UnsupportedExecutor struct{}

func (UnsupportedExecutor) Execute(_ context.Context, _ string, _ agentv1.Command) (json.RawMessage, *protocol.Problem) {
	return nil, &protocol.Problem{Code: protocol.ErrorUnsupported, Message: "unsupported command", Retryable: false}
}

type Processor struct {
	store       *Store
	executor    Executor
	now         func() time.Time
	wake        chan struct{}
	resultReady chan struct{}
}

func NewProcessor(store *Store, executor Executor) *Processor {
	if executor == nil {
		executor = UnsupportedExecutor{}
	}
	return &Processor{
		store: store, executor: executor, now: func() time.Time { return time.Now().UTC() },
		wake: make(chan struct{}, 1), resultReady: make(chan struct{}, 1),
	}
}

func (processor *Processor) Accept(envelope protocol.Envelope, receivedAt time.Time) error {
	if envelope.Type != agentv1.MessageCenterCommand {
		return errors.New("control envelope is not a command")
	}
	value, err := agentv1.DecodeEnvelopePayload[agentv1.Command](envelope)
	if err != nil {
		return err
	}
	created, err := processor.store.Accept(envelope.IdempotencyKey, value, receivedAt)
	if err != nil {
		return err
	}
	if created {
		processor.signal(processor.wake)
	}
	return nil
}

func (processor *Processor) Run(ctx context.Context) error {
	if err := processor.store.Cleanup(processor.now()); err != nil {
		return err
	}
	if _, err := processor.store.NextResult(); err == nil {
		processor.signal(processor.resultReady)
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	cleanup := time.NewTicker(cleanupInterval)
	defer cleanup.Stop()
	for {
		record, err := processor.store.NextPending()
		if errors.Is(err, ErrNotFound) {
			select {
			case <-ctx.Done():
				return nil
			case <-cleanup.C:
				if err := processor.store.Cleanup(processor.now()); err != nil {
					return err
				}
				continue
			case <-processor.wake:
				continue
			}
		}
		if err != nil {
			return err
		}
		result := processor.execute(ctx, record)
		if err := processor.store.Complete(record.CommandID, record.RequestSHA256, result, processor.now()); err != nil {
			return fmt.Errorf("persist command result: %w", err)
		}
		processor.signal(processor.resultReady)
	}
}

func (processor *Processor) execute(parent context.Context, record record) agentv1.CommandResult {
	now := processor.now()
	result := agentv1.CommandResult{
		CommandID: record.CommandID, RequestSHA256: record.RequestSHA256, CompletedAt: now,
	}
	if !now.Before(record.Command.ExpiresAt) {
		result.Status = agentv1.CommandStatusFailed
		result.Problem = &protocol.Problem{Code: protocol.ErrorUnavailable, Message: "command expired before execution", Retryable: false}
		return result
	}
	deadline := now.Add(agentv1.MaximumCommandExecution)
	if record.Command.ExpiresAt.Before(deadline) {
		deadline = record.Command.ExpiresAt
	}
	ctx, cancel := context.WithDeadline(parent, deadline)
	defer cancel()
	output, problem := processor.executor.Execute(ctx, record.CommandID, record.Command)
	result.CompletedAt = processor.now()
	result.Output = output
	if ctx.Err() != nil && problem == nil {
		problem = &protocol.Problem{Code: protocol.ErrorUnavailable, Message: "command execution timed out", Retryable: false}
	}
	if problem == nil {
		result.Status = agentv1.CommandStatusSucceeded
	} else {
		result.Status = agentv1.CommandStatusFailed
		result.Problem = problem
	}
	return result
}

func (processor *Processor) NextResult() (agentv1.CommandResult, error) {
	return processor.store.NextResult()
}

func (processor *Processor) Acknowledge(value agentv1.CommandResultAck, acknowledgedAt time.Time) error {
	if err := agentv1.ValidateCommandResultAck(value); err != nil {
		return err
	}
	return processor.store.Acknowledge(value.CommandID, value.RequestSHA256, acknowledgedAt)
}

func (processor *Processor) Results() <-chan struct{} {
	return processor.resultReady
}

func (processor *Processor) signal(channel chan struct{}) {
	select {
	case channel <- struct{}{}:
	default:
	}
}
