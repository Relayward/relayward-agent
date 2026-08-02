package plugin

import (
	"bytes"
	"context"
	"net"
	"os"
	"sync"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/Relayward/relayward-sdk/contract"
	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
)

func TestMain(m *testing.M) {
	if os.Getenv(nodepluginv1.EnvironmentSocketPath) != "" {
		os.Exit(runTestNodePlugin())
	}
	os.Exit(m.Run())
}

type testNodePlugin struct {
	nodepluginv1.UnimplementedNodePluginServer
	pluginID string

	mu          sync.Mutex
	generation  uint64
	digest      string
	degrade     bool
	statusCalls uint64
}

func runTestNodePlugin() int {
	if os.Getenv("RELAYWARD_REGISTRATION_TOKEN") != "" {
		return 41
	}
	socketPath := os.Getenv(nodepluginv1.EnvironmentSocketPath)
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return 42
	}
	defer listener.Close()
	if err := os.Chmod(socketPath, 0o600); err != nil {
		return 43
	}
	server := grpc.NewServer()
	nodepluginv1.RegisterNodePluginServer(server, &testNodePlugin{pluginID: os.Getenv(nodepluginv1.EnvironmentPluginID)})
	if err := server.Serve(listener); err != nil {
		return 44
	}
	return 0
}

func (plugin *testNodePlugin) GetInfo(context.Context, *nodepluginv1.GetInfoRequest) (*nodepluginv1.GetInfoResponse, error) {
	return &nodepluginv1.GetInfoResponse{ApiVersion: contract.NodePluginAPIVersion, PluginId: plugin.pluginID, Version: "1.2.3"}, nil
}

func (plugin *testNodePlugin) ValidateConfiguration(_ context.Context, request *nodepluginv1.ConfigurationRequest) (*nodepluginv1.ConfigurationValidated, error) {
	if err := nodepluginv1.ValidateConfigurationRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration")
	}
	if bytes.Contains(request.Json, []byte(`"reject":true`)) {
		return nil, status.Error(codes.InvalidArgument, "configuration rejected")
	}
	return &nodepluginv1.ConfigurationValidated{Generation: request.Generation, Sha256: request.Sha256}, nil
}

func (plugin *testNodePlugin) ApplyConfiguration(_ context.Context, request *nodepluginv1.ConfigurationRequest) (*nodepluginv1.ConfigurationApplied, error) {
	if err := nodepluginv1.ValidateConfigurationRequest(request); err != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid configuration")
	}
	plugin.mu.Lock()
	plugin.generation = request.Generation
	plugin.digest = request.Sha256
	plugin.degrade = bytes.Contains(request.Json, []byte(`"degrade":true`))
	plugin.statusCalls = 0
	plugin.mu.Unlock()
	return &nodepluginv1.ConfigurationApplied{Generation: request.Generation, Sha256: request.Sha256}, nil
}

func (plugin *testNodePlugin) GetStatus(context.Context, *nodepluginv1.GetStatusRequest) (*nodepluginv1.GetStatusResponse, error) {
	plugin.mu.Lock()
	defer plugin.mu.Unlock()
	health := nodepluginv1.Health_HEALTH_STARTING
	if plugin.generation != 0 {
		health = nodepluginv1.Health_HEALTH_HEALTHY
		if plugin.degrade && plugin.statusCalls > 0 {
			health = nodepluginv1.Health_HEALTH_UNHEALTHY
		}
		plugin.statusCalls++
	}
	return &nodepluginv1.GetStatusResponse{
		Generation: plugin.generation, ConfigurationSha256: plugin.digest, Health: health,
	}, nil
}
