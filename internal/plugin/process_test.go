package plugin

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	agentv1 "github.com/Relayward/relayward-sdk/agent/v1"
)

func TestProcessRuntimeUsesPrivateEnvironmentAndAppliesConfiguration(t *testing.T) {
	store, err := openStateStore(filepath.Join(shortTempDir(t), "state"))
	if err != nil {
		t.Fatal(err)
	}
	executable := copyTestExecutable(t, t.TempDir())
	t.Setenv("RELAYWARD_REGISTRATION_TOKEN", "must-not-be-inherited")
	runtime := &processRuntime{store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	process, client, err := runtime.start(ctx, "io.relayward.test", "1.2.3", executable)
	if err != nil {
		t.Fatalf("start() error = %v", err)
	}
	desired, err := normalizeDesired(testDesiredCommand(1, agentv1.PluginStateRunning, json.RawMessage(`{"enabled":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	if err := client.validate(ctx, desired); err != nil {
		t.Fatalf("validate() error = %v", err)
	}
	if err := client.apply(ctx, desired); err != nil {
		t.Fatalf("apply() error = %v", err)
	}
	client.close()
	info, err := os.Stat(process.socketPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %v, error = %v", info.Mode().Perm(), err)
	}
	stopContext, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer stopCancel()
	if err := process.stop(stopContext); err != nil {
		t.Fatalf("stop() error = %v", err)
	}
}

func TestPluginConfigurationTimeoutFitsCommandBudget(t *testing.T) {
	if pluginConfigurationRPCTimeout <= pluginRPCTimeout {
		t.Fatalf("configuration RPC timeout = %s, regular RPC timeout = %s", pluginConfigurationRPCTimeout, pluginRPCTimeout)
	}
	if pluginConfigurationRPCTimeout >= agentv1.MaximumCommandExecution {
		t.Fatalf("configuration RPC timeout = %s, command execution limit = %s", pluginConfigurationRPCTimeout, agentv1.MaximumCommandExecution)
	}
}

func copyTestExecutable(t *testing.T, directory string) string {
	t.Helper()
	source, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}
	destination := filepath.Join(directory, "plugin")
	if err := os.WriteFile(destination, raw, 0o700); err != nil {
		t.Fatal(err)
	}
	return destination
}

func shortTempDir(t *testing.T) string {
	t.Helper()
	directory, err := os.MkdirTemp("", "rwp-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(directory) })
	return directory
}
