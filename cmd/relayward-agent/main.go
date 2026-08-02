package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/Relayward/relayward-agent/internal/agent"
	"github.com/Relayward/relayward-agent/internal/buildinfo"
	commandstate "github.com/Relayward/relayward-agent/internal/command"
	"github.com/Relayward/relayward-agent/internal/config"
)

const restartExitCode = 75

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		printUsage(stderr)
		return 2
	}

	switch args[0] {
	case "version":
		if len(args) == 2 && args[1] == "--short" {
			fmt.Fprintln(stdout, buildinfo.Version)
			return 0
		}
		if len(args) != 1 {
			printUsage(stderr)
			return 2
		}
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(buildinfo.Current()); err != nil {
			fmt.Fprintf(stderr, "write version: %v\n", err)
			return 1
		}
		return 0
	case "init-config":
		return initializeConfig(args[1:], stderr)
	case "enroll":
		return enroll(args[1:], stdout, stderr)
	case "run":
		return runAgent(args[1:], stderr)
	default:
		printUsage(stderr)
		return 2
	}
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, "usage: relayward-agent version [--short]")
	fmt.Fprintln(writer, "       relayward-agent init-config --server-url URL [options]")
	fmt.Fprintln(writer, "       relayward-agent enroll [-config PATH]")
	fmt.Fprintln(writer, "       relayward-agent run [-config PATH]")
}

func initializeConfig(args []string, stderr io.Writer) int {
	flags := flag.NewFlagSet("init-config", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/relayward-agent/config.json", "configuration path")
	serverURL := flags.String("server-url", "", "Relayward center URL")
	stateDirectory := flags.String("state-directory", "/var/lib/relayward-agent", "state directory")
	allowInsecure := flags.Bool("allow-insecure", false, "allow plain HTTP for local tests")
	certificatePin := flags.String("server-cert-sha256", "", "center certificate SHA-256")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return 2
	}
	if err := config.Save(*path, config.Config{
		ServerURL: *serverURL, StateDirectory: *stateDirectory, AllowInsecure: *allowInsecure,
		ServerCertSHA256: *certificatePin,
	}); err != nil {
		fmt.Fprintf(stderr, "initialize config: %v\n", err)
		return 1
	}
	return 0
}

func enroll(args []string, stdout, stderr io.Writer) int {
	client, code := loadClient(args, stderr)
	if code != 0 {
		return code
	}
	token := strings.TrimSpace(os.Getenv(agent.RegistrationTokenEnv))
	if token == "" {
		fmt.Fprintf(stderr, "%s is required\n", agent.RegistrationTokenEnv)
		return 2
	}
	identity, err := client.Register(context.Background(), token)
	if err != nil {
		fmt.Fprintf(stderr, "register Agent: %v\n", err)
		return 1
	}
	_ = os.Unsetenv(agent.RegistrationTokenEnv)
	if err := json.NewEncoder(stdout).Encode(map[string]string{"node_id": identity.NodeID, "node_name": identity.NodeName}); err != nil {
		fmt.Fprintf(stderr, "write enrollment result: %v\n", err)
		return 1
	}
	return 0
}

func runAgent(args []string, stderr io.Writer) int {
	client, code := loadClient(args, stderr)
	if code != 0 {
		return code
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := client.Run(ctx); err != nil {
		fmt.Fprintf(stderr, "run Agent: %v\n", err)
		return agentRunExitCode(err)
	}
	return 0
}

func agentRunExitCode(err error) int {
	if errors.Is(err, commandstate.ErrRestartRequired) {
		return restartExitCode
	}
	return 1
}

func loadClient(args []string, stderr io.Writer) (*agent.Client, int) {
	flags := flag.NewFlagSet("Agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/relayward-agent/config.json", "configuration path")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 {
		return nil, 2
	}
	value, err := config.Load(*path)
	if err != nil {
		fmt.Fprintf(stderr, "load config: %v\n", err)
		return nil, 1
	}
	logger := slog.New(slog.NewJSONHandler(stderr, nil))
	client, err := agent.NewClient(value, buildinfo.Version, logger)
	if err != nil {
		fmt.Fprintf(stderr, "initialize Agent: %v\n", err)
		return nil, 1
	}
	return client, 0
}
