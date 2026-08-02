package plugin

import (
	"fmt"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"

	nodepluginv1 "github.com/Relayward/relayward-sdk/nodeplugin/v1"
	"github.com/Relayward/relayward-sdk/pluginfixture"
)

func TestMain(m *testing.M) {
	if len(os.Args) > 1 && os.Args[1] == "plugin-exec" {
		if err := RunLimitedPlugin(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	if os.Getenv("RELAYWARD_PLUGIN_LIMIT_PROBE") == "1" {
		for _, expected := range []struct {
			resource int
			value    uint64
		}{
			{unix.RLIMIT_DATA, pluginMemoryLimit},
			{unix.RLIMIT_NOFILE, pluginOpenFilesLimit},
			{unix.RLIMIT_NPROC, pluginProcessLimit},
			{unix.RLIMIT_CORE, 0},
		} {
			var actual unix.Rlimit
			if unix.Getrlimit(expected.resource, &actual) != nil || actual.Cur != expected.value || actual.Max != expected.value {
				os.Exit(42)
			}
		}
		os.Exit(0)
	}
	if os.Getenv(nodepluginv1.EnvironmentSocketPath) != "" {
		os.Exit(pluginfixture.Run("1.2.3"))
	}
	os.Exit(m.Run())
}

func TestRunLimitedPluginAppliesHardLimits(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "plugin-exec", executable)
	command.Env = append(os.Environ(), "RELAYWARD_PLUGIN_LIMIT_PROBE=1")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("limited plugin probe failed: %v, output=%s", err, output)
	}
}
