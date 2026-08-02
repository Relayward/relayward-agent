# Relayward Agent

Relayward Agent is the native node-side component of Relayward. It maintains an outbound control connection, supervises runtime plugins, enforces local policy while the center is unavailable, and delivers durable telemetry.

The supported targets are Debian/systemd and Alpine/OpenRC on Linux AMD64. The Agent does not require Docker and does not embed Xray, sing-box, or any other proxy core.

The initial repository establishes a static executable and CI boundary. Registration, transport, durable state, plugin supervision, and update behavior are added as their shared contracts are implemented and verified.

## Local Checks

```bash
go test ./...
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/relayward-agent
```

Print build information:

```bash
go run ./cmd/relayward-agent version
```

Releases use semantic `vMAJOR.MINOR.PATCH` Git tags and publish only Linux AMD64 assets.
