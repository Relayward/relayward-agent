package update

import (
	"context"
	"errors"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
	"github.com/Relayward/relayward-sdk/protocol"

	commandstate "github.com/Relayward/relayward-agent/internal/command"
)

type Executor struct {
	manager        *Manager
	runningVersion string
}

func NewExecutor(manager *Manager, runningVersion string) *Executor {
	return &Executor{manager: manager, runningVersion: runningVersion}
}

func (executor *Executor) Execute(ctx context.Context, commandID string, command agentv1.Command) commandstate.Execution {
	if command.Kind != agentv1.CommandAgentUpdate {
		return commandstate.UnsupportedExecutor{}.Execute(ctx, commandID, command)
	}
	payload, err := agentv1.DecodeAgentUpdateCommand(command)
	if err != nil {
		return failed(protocol.ErrorInvalidArgument, "invalid Agent update command", false)
	}
	for {
		switch observed := executor.manager.Observe(commandID, payload.Version, executor.runningVersion); {
		case observed == nil:
			output, err := activatedOutput(payload.Version)
			if err != nil {
				return failed(protocol.ErrorInternal, "encode Agent update result", false)
			}
			return commandstate.Execution{Output: output}
		case errors.Is(observed, ErrActivationFailed):
			return failed(protocol.ErrorUnavailable, "Agent update failed health validation and was rolled back", false)
		case errors.Is(observed, ErrActivationPending):
			if executor.runningVersion != payload.Version {
				return commandstate.Execution{Restart: true}
			}
			if err := executor.manager.WaitForStateChange(ctx); err != nil {
				return commandstate.Execution{Restart: true}
			}
			continue
		case errors.Is(observed, ErrUpdateStateConflict):
			return failed(protocol.ErrorConflict, "Agent update conflicts with durable state", false)
		case errors.Is(observed, ErrStateNotFound):
			prepared, err := executor.manager.Prepare(ctx, commandID, payload.Version, executor.runningVersion)
			if err != nil {
				return failed(protocol.ErrorUnavailable, "Agent update preparation failed", true)
			}
			if prepared.Restart {
				return commandstate.Execution{Restart: true}
			}
			if prepared.Activated {
				continue
			}
		default:
			return failed(protocol.ErrorInternal, "read Agent update state", false)
		}
	}
}

func failed(code protocol.ErrorCode, message string, retryable bool) commandstate.Execution {
	return commandstate.Execution{Problem: &protocol.Problem{Code: code, Message: message, Retryable: retryable}}
}
