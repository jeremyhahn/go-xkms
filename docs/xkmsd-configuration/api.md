# xkmsd Configuration — API

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-09

No network API surface: configuration is resolved at process start and on
SIGHUP reload, and is not readable or writable over REST, gRPC, MCP or the
Unix socket. The Go surface is `pkg/config` (`Load`, `Defaults`), documented
in [engineering.md](engineering.md).

Library consumers that open their own listener take the host from the
listener's options struct, populated from `config.Server.Host`:

| Package | Field | Consumed by |
|---|---|---|
| `pkg/api/rest` | `Config.Host` | `net.JoinHostPort(cfg.Host, port)` in `NewServer` |
| `pkg/api/grpc` | `ServerConfig.Host` | `net.JoinHostPort(host, port)` in `Start` |
| `go-qrdb/sdk/go` | `DaemonConfig.Server.Host` | the embedded node's unified API server (`pkg/server/qrdb_node.go`) |
