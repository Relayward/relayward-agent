package command

import (
	"context"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

type Router map[string]Executor

func (router Router) Execute(ctx context.Context, commandID string, value agentv1.Command) Execution {
	executor := router[value.Kind]
	if executor == nil {
		return UnsupportedExecutor{}.Execute(ctx, commandID, value)
	}
	return executor.Execute(ctx, commandID, value)
}

var _ Executor = Router{}
