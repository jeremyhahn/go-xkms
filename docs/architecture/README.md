# Go-xKMS Architecture Documentation

> **Status: REFERENCE** · Last verified: 2026-10-12
> Index of the cross-cutting architecture documents; feature folders under `docs/<feature>/` are normative.

## Documents in this directory

| Document | Contents |
|---|---|
| [overview.md](./overview.md) | System overview: transports, layers, backends |
| [quick-reference.md](./quick-reference.md) | One-page cheat sheet: binaries, Make targets, configuration keys |
| [api-specifications.md](./api-specifications.md) | REST routes, gRPC services and the CLI, checked against the code |
| [adapter-framework.md](./adapter-framework.md) | The auth, logging and adapter seams |
| [trusted-service-plane.md](./trusted-service-plane.md) | The trusted service plane: attested-caller gate, trust roots, image signing, workload identity, transparency log, moves |

## Absorbed documents

Earlier documents in this directory were folded into feature folders
(go-xkms#1433):

- Server architecture → [host-embedding](../host-embedding/engineering.md) and
  [xkmsd-configuration](../xkmsd-configuration/engineering.md)
- Storage and object storage → [datastore](../datastore/engineering.md)
- RBAC → [rbac](../rbac/architecture.md)
- Key ID format →
  [key-management](../key-management/engineering.md#key-id-format--pkgxkmskeyidgo)
- Hardware certificate storage →
  [certificate-authority](../certificate-authority/engineering.md#hardware-certificate-storage--pkgstoragehardware)
- Correlation IDs → [host-embedding](../host-embedding/engineering.md)
- Post-quantum cryptography → [post-quantum](../post-quantum/architecture.md)
- Symmetric encryption → [symmetric-aead](../symmetric-aead/)

## Transports at a glance

`xkmsd` binds every network listener on `server.host`
(`ServerConfig`, `pkg/config/config.go:310`); each transport is switched on under
`protocols:` (`config.go:351-358`). The shipped `configs/xkmsd.yaml` uses:

| Transport | Port key | Shipped value | Notes |
|---|---|---|---|
| Unix socket | `unix.*` | — | On by default for local IPC |
| REST (HTTP/1.1, HTTP/2) | `server.rest_port` | 8443 | |
| QUIC (HTTP/3) | — | rest port | HTTP/3 is served on `rest_port` (`pkg/server/server.go:2433`) |
| gRPC | `server.grpc_port` | 9443 | |
| MCP | `server.mcp_port` | 8445 | Served by the embedded qrdb node (`pkg/server/qrdb_node.go:85-86`) |
| Metrics | `metrics.port` | 9090 | Path `/metrics` |

Health routes are public on REST: `/health`, `/health/live`,
`/health/ready`, `/health/startup` (`pkg/api/rest/routes.go:124-128`).

## Repository layout

```
cmd/       xkmsd, xkmsctl, pkcs11-module, cgo, acme-client
pkg/api/   rest, grpc, unix, mcp, transport, apierrors, tenantgate
pkg/xkms/  the composite service and the Backend contract (keystore.go)
pkg/server/ xkmsd composition root
pkg/config/ xkmsd configuration
test/integration/  integration suites, one directory per feature
```

## Make targets

`make build`, `make build-server`, `make build-cli`, `make test`,
`make integration-test`, `make security`, `make deps-check`, `make bench`,
`make coverage`, `make proto`, `make docker-build`, `make docker-run`,
`make docker-test`. CI runs the five stage targets (`build`, `test`,
`integration-test`, `security`, `deps-check`) in images built from
`build/docker/devcontainer/Dockerfile`.
Per-package
targets follow `test-<pkg>`, `integration-test-<pkg>`, `bench-<pkg>` and
`coverage-<pkg>`.
