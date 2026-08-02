# Relayward Agent AGENTS.md

## Project Role

This repository contains the native Relayward node Agent for Debian/systemd and Alpine/OpenRC. It owns registration, the outbound control connection, durable command and event handling, plugin supervision, local policy enforcement, and self-update behavior.

The Agent must not contain proxy-core-specific configuration or lifecycle logic. That behavior belongs in runtime plugins using versioned contracts from `Relayward/relayward-sdk`.

## Platform Scope

- Build and release only static Linux AMD64 binaries.
- Support Debian with systemd and Alpine with OpenRC without requiring Docker.
- Keep resource use suitable for small LXC nodes.
- Do not add ARM, Windows, macOS, container-only deployment, or compatibility with the retired xui-agent runtime or data.

## Security

- Treat registration tokens, node credentials, commands, plugin artifacts, and local state as untrusted at their boundaries.
- Never log node credentials, registration tokens, proxy credentials, source IP data, or complete access events at informational level.
- Persist credentials and policy state with restrictive permissions.
- Verify downloaded release artifacts against metadata supplied by the control plane before activation.

## Engineering Conventions

- Prefer the Go standard library unless a dependency removes substantial complexity.
- Keep transport, persistence, command execution, plugin supervision, and init-system integration behind focused packages.
- Version shared wire contracts in `Relayward/relayward-sdk` before depending on them here.
- Let startup and validation failures surface explicitly; do not report mock success or silently bypass required behavior.

## Validation

Run the checks relevant to the change:

- `go test ./...`
- `go vet ./...`
- `go test -race ./...` for concurrency, sessions, queues, or persistence changes
- `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/relayward-agent`

Changes involving shared contracts must also pass the SDK conformance tests and affected control-plane tests.
