package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Relayward/relayward-agent/internal/buildinfo"
	commandstate "github.com/Relayward/relayward-agent/internal/command"
)

func TestRunVersion(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run returned %d, stderr = %q", code, stderr.String())
	}
	var got buildinfo.Info
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("decode version: %v", err)
	}
	if got != buildinfo.Current() {
		t.Fatalf("version = %+v, want %+v", got, buildinfo.Current())
	}
}

func TestRunVersionShort(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if code := run([]string{"version", "--short"}, &stdout, &stderr); code != 0 {
		t.Fatalf("run returned %d, stderr = %q", code, stderr.String())
	}
	if got := strings.TrimSpace(stdout.String()); got != buildinfo.Version {
		t.Fatalf("short version = %q, want %q", got, buildinfo.Version)
	}
}

func TestAgentRunExitCode(t *testing.T) {
	if got := agentRunExitCode(errors.New("ordinary failure")); got != 1 {
		t.Fatalf("ordinary failure exit code = %d", got)
	}
	if got := agentRunExitCode(errors.Join(errors.New("worker failed"), commandstate.ErrRestartRequired)); got != restartExitCode {
		t.Fatalf("restart failure exit code = %d", got)
	}
}

func TestRunRejectsUnknownCommand(t *testing.T) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	if code := run([]string{"start"}, &stdout, &stderr); code != 2 {
		t.Fatalf("run returned %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "usage:") {
		t.Fatalf("stderr = %q, want usage", stderr.String())
	}
}
