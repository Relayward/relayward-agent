package plugin

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
)

const (
	pluginStartupTimeout          = 15 * time.Second
	pluginRPCTimeout              = 15 * time.Second
	pluginConfigurationRPCTimeout = 5 * time.Minute
	pluginHealthTimeout           = 30 * time.Second
	pluginStopTimeout             = 10 * time.Second
)

var (
	ErrConfigurationRejected  = errors.New("plugin configuration rejected")
	ErrPluginIdentityMismatch = errors.New("plugin identity does not match the artifact metadata")
)

type managedProcess struct {
	pluginID   string
	command    *exec.Cmd
	socketPath string
	client     *processClient
	done       chan struct{}
	waitError  error
	startedAt  time.Time
	ready      bool
}

type processClient struct {
	connection        *grpc.ClientConn
	client            nodepluginv1.NodePluginClient
	capabilities      []string
	telemetryStreamID string
	closeOnce         sync.Once
}

type processRuntime struct {
	store *stateStore
}

func (runtime *processRuntime) start(ctx context.Context, pluginID, version, executable string) (*managedProcess, *processClient, error) {
	dataDirectory := runtime.store.dataPath(pluginID)
	runtimeDirectory := runtime.store.runtimePath(pluginID)
	for _, directory := range []string{dataDirectory, runtimeDirectory} {
		if err := os.MkdirAll(directory, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create plugin private directory: %w", err)
		}
		if err := os.Chmod(directory, 0o700); err != nil {
			return nil, nil, fmt.Errorf("protect plugin private directory: %w", err)
		}
		if err := syncDirectory(filepath.Dir(directory)); err != nil {
			return nil, nil, fmt.Errorf("sync plugin private directory parent: %w", err)
		}
	}
	socketPath := runtime.store.socketPath(pluginID)
	if len(socketPath) >= 108 {
		return nil, nil, errors.New("Agent state directory is too long for a Unix socket")
	}
	if err := removeStaleSocket(socketPath); err != nil {
		return nil, nil, err
	}
	launcher, err := os.Executable()
	if err != nil {
		return nil, nil, fmt.Errorf("resolve plugin launcher: %w", err)
	}
	command := exec.Command(launcher, "plugin-exec", executable)
	command.Dir = dataDirectory
	command.Env = []string{
		"HOME=" + dataDirectory,
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TMPDIR=" + runtimeDirectory,
		nodepluginv1.EnvironmentSocketPath + "=" + socketPath,
		nodepluginv1.EnvironmentDataDirectory + "=" + dataDirectory,
		nodepluginv1.EnvironmentPluginID + "=" + pluginID,
	}
	command.Stdout = io.Discard
	command.Stderr = io.Discard
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGTERM}
	if err := command.Start(); err != nil {
		return nil, nil, fmt.Errorf("start plugin process: %w", err)
	}
	process := &managedProcess{pluginID: pluginID, command: command, socketPath: socketPath, done: make(chan struct{}), startedAt: time.Now().UTC()}
	go func() {
		process.waitError = command.Wait()
		close(process.done)
	}()
	client, err := connectPlugin(ctx, process, pluginID, version)
	if err != nil {
		stopContext, cancel := context.WithTimeout(context.Background(), pluginStopTimeout)
		defer cancel()
		_ = process.stop(stopContext)
		return nil, nil, err
	}
	process.client = client
	return process, client, nil
}

func connectPlugin(parent context.Context, process *managedProcess, pluginID, version string) (*processClient, error) {
	ctx, cancel := context.WithTimeout(parent, pluginStartupTimeout)
	defer cancel()
	exitCancel := make(chan struct{})
	go func() {
		select {
		case <-process.done:
			cancel()
		case <-exitCancel:
		}
	}()
	defer close(exitCancel)
	connection, err := grpc.DialContext(ctx, "unix://"+process.socketPath,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "unix", process.socketPath)
		}),
		grpc.WithBlock(),
	)
	if err != nil {
		if process.exited() {
			return nil, fmt.Errorf("plugin process exited before opening its control socket: %v", process.waitError)
		}
		return nil, errors.New("plugin control socket did not become ready")
	}
	if err := validateSocket(process.socketPath); err != nil {
		connection.Close()
		return nil, err
	}
	client := &processClient{connection: connection, client: nodepluginv1.NewNodePluginClient(connection)}
	rpcContext, rpcCancel := context.WithTimeout(parent, pluginRPCTimeout)
	defer rpcCancel()
	info, err := client.client.GetInfo(rpcContext, &nodepluginv1.GetInfoRequest{})
	if err != nil {
		connection.Close()
		return nil, errors.New("plugin identity RPC failed")
	}
	if err := nodepluginv1.ValidateInfoResponse(info, pluginID, version); err != nil {
		connection.Close()
		return nil, fmt.Errorf("%w: %v", ErrPluginIdentityMismatch, err)
	}
	client.capabilities = append([]string(nil), info.Capabilities...)
	client.telemetryStreamID = info.TelemetryStreamId
	return client, nil
}

func (client *processClient) close() {
	if client != nil && client.connection != nil {
		client.closeOnce.Do(func() { _ = client.connection.Close() })
	}
}

func (client *processClient) validate(ctx context.Context, desired desiredState) error {
	request := configurationRequest(desired)
	rpcContext, cancel := context.WithTimeout(ctx, pluginConfigurationRPCTimeout)
	defer cancel()
	response, err := client.client.ValidateConfiguration(rpcContext, request)
	if err != nil {
		if status.Code(err) == codes.InvalidArgument {
			return ErrConfigurationRejected
		}
		return errors.New("plugin configuration validation RPC failed")
	}
	if err := nodepluginv1.ValidateConfigurationValidated(request, response); err != nil {
		return fmt.Errorf("validate plugin configuration response: %w", err)
	}
	return nil
}

func (client *processClient) apply(ctx context.Context, desired desiredState) error {
	request := configurationRequest(desired)
	rpcContext, cancel := context.WithTimeout(ctx, pluginConfigurationRPCTimeout)
	response, err := client.client.ApplyConfiguration(rpcContext, request)
	cancel()
	if err != nil {
		return errors.New("plugin failed to apply configuration")
	}
	if err := nodepluginv1.ValidateConfigurationApplied(request, response); err != nil {
		return fmt.Errorf("validate plugin apply response: %w", err)
	}
	healthContext, healthCancel := context.WithTimeout(ctx, pluginHealthTimeout)
	defer healthCancel()
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, err := client.getStatus(healthContext)
		if err != nil {
			return err
		}
		if status.Generation != desired.Generation || status.ConfigurationSha256 != desired.ConfigurationSHA256 {
			return errors.New("plugin health reports a different configuration")
		}
		switch status.Health {
		case nodepluginv1.Health_HEALTH_HEALTHY:
			return nil
		case nodepluginv1.Health_HEALTH_UNHEALTHY:
			return errors.New("plugin reports unhealthy state")
		}
		select {
		case <-healthContext.Done():
			return errors.New("plugin did not become healthy before the deadline")
		case <-ticker.C:
		}
	}
}

func (client *processClient) checkHealthy(ctx context.Context, generation uint64, digest string) error {
	status, err := client.getStatus(ctx)
	if err != nil {
		return err
	}
	if status.Generation != generation || status.ConfigurationSha256 != digest {
		return errors.New("plugin health reports a different configuration")
	}
	if status.Health != nodepluginv1.Health_HEALTH_HEALTHY {
		return errors.New("plugin does not report healthy state")
	}
	return nil
}

func (client *processClient) getStatus(ctx context.Context) (*nodepluginv1.GetStatusResponse, error) {
	statusContext, cancel := context.WithTimeout(ctx, pluginRPCTimeout)
	defer cancel()
	status, err := client.client.GetStatus(statusContext, &nodepluginv1.GetStatusRequest{})
	if err != nil {
		return nil, errors.New("plugin health RPC failed")
	}
	if err := nodepluginv1.ValidateStatusResponse(status); err != nil {
		return nil, fmt.Errorf("validate plugin health response: %w", err)
	}
	return status, nil
}

func (client *processClient) collectTelemetry(ctx context.Context, afterSequence uint64) (*nodepluginv1.CollectTelemetryResponse, error) {
	request := &nodepluginv1.CollectTelemetryRequest{AfterSequence: afterSequence, MaximumEvents: nodepluginv1.MaximumTelemetryEvents}
	rpcContext, cancel := context.WithTimeout(ctx, pluginRPCTimeout)
	defer cancel()
	response, err := client.client.CollectTelemetry(rpcContext, request)
	if err != nil {
		return nil, errors.New("plugin telemetry RPC failed")
	}
	if err := nodepluginv1.ValidateCollectTelemetryResponse(request, response); err != nil {
		return nil, fmt.Errorf("validate plugin telemetry response: %w", err)
	}
	return response, nil
}

func (client *processClient) setServiceState(ctx context.Context, request *nodepluginv1.SetServiceStateRequest) error {
	if err := nodepluginv1.ValidateSetServiceStateRequest(request); err != nil {
		return err
	}
	rpcContext, cancel := context.WithTimeout(ctx, pluginRPCTimeout)
	defer cancel()
	response, err := client.client.SetServiceState(rpcContext, request)
	if err != nil {
		return errors.New("plugin service state RPC failed")
	}
	if err := nodepluginv1.ValidateSetServiceStateResponse(request, response); err != nil {
		return fmt.Errorf("validate plugin service state response: %w", err)
	}
	return nil
}

func (client *processClient) replaceDynamicBlocks(ctx context.Context, request *nodepluginv1.ReplaceDynamicBlocksRequest) error {
	if err := nodepluginv1.ValidateReplaceDynamicBlocksRequest(request); err != nil {
		return err
	}
	rpcContext, cancel := context.WithTimeout(ctx, pluginRPCTimeout)
	defer cancel()
	response, err := client.client.ReplaceDynamicBlocks(rpcContext, request)
	if err != nil {
		return errors.New("plugin dynamic block RPC failed")
	}
	if err := nodepluginv1.ValidateReplaceDynamicBlocksResponse(request, response); err != nil {
		return fmt.Errorf("validate plugin dynamic block response: %w", err)
	}
	return nil
}

func configurationRequest(desired desiredState) *nodepluginv1.ConfigurationRequest {
	return &nodepluginv1.ConfigurationRequest{
		Generation: desired.Generation,
		Sha256:     desired.ConfigurationSHA256,
		Json:       desired.Configuration,
	}
}

func (process *managedProcess) exited() bool {
	select {
	case <-process.done:
		return true
	default:
		return false
	}
}

func (process *managedProcess) stop(ctx context.Context) error {
	if process == nil || process.command == nil || process.command.Process == nil {
		return nil
	}
	if process.exited() {
		process.client.close()
		return removeStaleSocket(process.socketPath)
	}
	process.client.close()
	_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGTERM)
	timer := time.NewTimer(pluginStopTimeout)
	defer timer.Stop()
	select {
	case <-process.done:
		return removeStaleSocket(process.socketPath)
	case <-ctx.Done():
	case <-timer.C:
	}
	_ = syscall.Kill(-process.command.Process.Pid, syscall.SIGKILL)
	select {
	case <-process.done:
		return removeStaleSocket(process.socketPath)
	case <-time.After(time.Second):
		return errors.New("plugin process did not exit after SIGKILL")
	}
}

func removeStaleSocket(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect plugin control socket: %w", err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("plugin control socket path is occupied by a non-socket file")
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale plugin control socket: %w", err)
	}
	return syncDirectory(filepath.Dir(path))
}

func validateSocket(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return errors.New("plugin control socket is missing")
	}
	if info.Mode()&os.ModeSocket == 0 || info.Mode().Perm()&0o077 != 0 {
		return errors.New("plugin control socket must be a private Unix socket")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("plugin control socket is not owned by the Agent user")
	}
	return nil
}
