package update

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLauncherRollsBackFailedCandidate(t *testing.T) {
	state := t.TempDir()
	writeFakeAgent(t, state, "old", "#!/bin/sh\nexit 0\n")
	writeFakeAgent(t, state, "new", "#!/bin/sh\nexit 1\n")
	symlink(t, "versions/new/relayward-agent", filepath.Join(state, "current"))
	symlink(t, "versions/old/relayward-agent", filepath.Join(state, "previous"))
	if err := os.WriteFile(filepath.Join(state, pendingFilename), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write pending state: %v", err)
	}
	command := launcherCommand(state)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("launcher error = %v\n%s", err, output)
	}
	current, err := os.Readlink(filepath.Join(state, "current"))
	if err != nil || current != "versions/old/relayward-agent" {
		t.Fatalf("current target = %q, %v", current, err)
	}
	if _, err := os.Stat(filepath.Join(state, failedFilename)); err != nil {
		t.Fatalf("failed state is missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(state, pendingFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("pending state still exists: %v", err)
	}
}

func TestLauncherRunsSwitchedCandidateAfterRestartExit(t *testing.T) {
	state := t.TempDir()
	oldScript := "#!/bin/sh\nrm -f \"$RELAYWARD_AGENT_STATE_DIRECTORY/current\"\nln -s versions/new/relayward-agent \"$RELAYWARD_AGENT_STATE_DIRECTORY/current\"\nexit 75\n"
	newScript := "#!/bin/sh\nrm -f \"$RELAYWARD_AGENT_STATE_DIRECTORY/update-pending.json\"\nexit 0\n"
	writeFakeAgent(t, state, "old", oldScript)
	writeFakeAgent(t, state, "new", newScript)
	symlink(t, "versions/old/relayward-agent", filepath.Join(state, "current"))
	symlink(t, "versions/old/relayward-agent", filepath.Join(state, "previous"))
	if err := os.WriteFile(filepath.Join(state, pendingFilename), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write pending state: %v", err)
	}
	command := launcherCommand(state)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("launcher error = %v\n%s", err, output)
	}
	current, err := os.Readlink(filepath.Join(state, "current"))
	if err != nil || current != "versions/new/relayward-agent" {
		t.Fatalf("current target = %q, %v", current, err)
	}
	if _, err := os.Stat(filepath.Join(state, failedFilename)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unexpected failed state: %v", err)
	}
}

func TestLauncherForwardsTermination(t *testing.T) {
	state := t.TempDir()
	childPIDFile := filepath.Join(state, "child.pid")
	terminatedFile := filepath.Join(state, "terminated")
	script := "#!/bin/sh\nprintf '%s\\n' \"$$\" > \"$RELAYWARD_AGENT_CHILD_PID_FILE\"\ntrap 'printf terminated > \"$RELAYWARD_AGENT_TERMINATED_FILE\"; exit 0' TERM\nwhile :; do sleep 1; done\n"
	writeFakeAgent(t, state, "current", script)
	symlink(t, "versions/current/relayward-agent", filepath.Join(state, "current"))
	command := launcherCommand(state)
	command.Env = append(command.Env,
		"RELAYWARD_AGENT_CHILD_PID_FILE="+childPIDFile,
		"RELAYWARD_AGENT_TERMINATED_FILE="+terminatedFile,
	)
	if err := command.Start(); err != nil {
		t.Fatalf("start launcher: %v", err)
	}
	launcherExited := false
	childPID := 0
	t.Cleanup(func() {
		if !launcherExited {
			_ = command.Process.Kill()
			_ = command.Wait()
		}
		if childPID > 0 {
			_ = syscall.Kill(childPID, syscall.SIGKILL)
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(childPIDFile)
		if err == nil {
			childPID, err = strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil {
				t.Fatalf("parse child PID: %v", err)
			}
			break
		}
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("read child PID: %v", err)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if childPID == 0 {
		t.Fatal("launcher did not start the Agent")
	}
	if err := command.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("terminate launcher: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		launcherExited = true
		if err != nil {
			t.Fatalf("launcher exit: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("launcher did not exit after SIGTERM")
	}
	if _, err := os.Stat(terminatedFile); err != nil {
		t.Fatalf("Agent did not receive SIGTERM: %v", err)
	}
	if err := syscall.Kill(childPID, 0); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("Agent process %d still exists: %v", childPID, err)
	}
}

func launcherCommand(state string) *exec.Cmd {
	command := exec.Command("sh", filepath.Join("..", "..", "deploy", "relayward-agent-launcher"))
	command.Env = append(os.Environ(),
		"RELAYWARD_AGENT_STATE_DIRECTORY="+state,
		"RELAYWARD_AGENT_CONFIG_PATH=/unused",
	)
	return command
}

func writeFakeAgent(t *testing.T, state, version, script string) {
	t.Helper()
	directory := filepath.Join(state, "versions", version)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatalf("create version directory: %v", err)
	}
	if err := os.WriteFile(filepath.Join(directory, "relayward-agent"), []byte(script), 0o755); err != nil {
		t.Fatalf("write fake Agent: %v", err)
	}
}

func symlink(t *testing.T, target, path string) {
	t.Helper()
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("create symlink: %v", err)
	}
}
