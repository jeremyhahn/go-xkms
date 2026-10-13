# Go-xKMS Server - Quick Reference Card

> **Status: REFERENCE** · Last verified: 2026-10-12
> One-page developer cheat sheet; [xkmsd-configuration](../xkmsd-configuration/engineering.md) is normative for configuration keys.

## Binaries

| Binary | Purpose | Flags |
|---|---|---|
| `xkmsd` | Server | `-config`/`-c` (default `/etc/xkms/xkmsd.yaml`), `-daemon`/`-d`, `-pid-file`, `-version` (`cmd/xkmsd/main.go:105-110`) |
| `xkmsctl` | CLI client | Global flags in `cmd/xkmsctl/root.go:116-153`: `--config`, `--backend` (default `software`), `--key-dir`, `-o/--output`, `-v/--verbose`, `--transport`, `-s/--server`, `--tls-cert`, `--tls-key`, `--tls-ca`, `--token`, `--spki-pin` |

## Ports

`xkmsd` has no port flags; it binds what the YAML names. The shipped column
is `configs/xkmsd.yaml`. The library fallback is what a package substitutes
when it is embedded with a zero port or no address.

| Protocol | Config key | Shipped | Library fallback |
|---|---|---|---|
| REST | `server.rest_port` | 8443 | 8443 (`pkg/api/rest/server.go:281`) |
| HTTP/3 (QUIC) | — | on `rest_port` | — |
| gRPC | `server.grpc_port` | 9443 | none |
| MCP | `server.mcp_port` | 8445 | SDK dials `localhost:9444` (`sdk/go/options.go:33`) |
| Noise | `server.noise_port` (`pkg/config/config.go:320`) | 8447 in `configs/xkmsd-local.yaml:10` | 8445 (`DefaultNoisePort`, `pkg/trust/bootstrap/bootstrap.go:103`) |
| Metrics | `metrics.port` | 9090 | none |

The SDK's MCP default (9444) differs from the shipped `mcp_port` (8445):
point the client at the configured port.

## API surfaces

- **REST** — the route table is `pkg/api/rest/routes.go`. Most routes live
  under `/api/v1`; WebAuthn, invites, users and SSH have their own prefixes.
  See [api-specifications.md](./api-specifications.md#rest-api).
- **gRPC** — `xkms.v1.KeystoreService`
  (`pkg/api/grpc/proto/xkmsv1/xkms.proto:15`).
- **MCP** — each xkms method is an MCP tool named `xkms_<method>`, with dots
  turned into underscores. It takes one optional `params_json` string
  argument (`pkg/mcptool/client.go:82-89`, `:405-422`).

## Common CLI verbs

```bash
xkmsctl version
xkmsctl backends list
xkmsctl backends info <backend>
xkmsctl key generate <key-id> --key-type signing
xkmsctl key list
xkmsctl key get <key-id>
xkmsctl key sign <key-id> <data> --hash sha256
xkmsctl key verify <key-id> <data> <signature>
xkmsctl key delete <key-id>
```

`--key-type` takes `tls` (the default), `signing`, `encryption` or
`symmetric` (`cmd/xkmsctl/key.go:1909`). `--hash` defaults to `sha256`
(`key.go:1932`). The key verbs are documented in [key-management → CLI](../key-management/cli.md).

## Configuration skeleton

Ports live under `server:` as `*_port` integers, and protocols are switched
on under `protocols:` (`ServerConfig`, `pkg/config/config.go:309`;
`ProtocolsConfig`, `config.go:351`).

```yaml
server:
  host: "127.0.0.1"
  rest_port: 8443
  grpc_port: 9443
  mcp_port: 8445

protocols:
  unix: true
  rest: true
  grpc: true
  mcp: true

auth:
  enabled: true
  type: composite  # mtls, jwt, composite; "adaptive" was removed (pkg/server/server.go:1257)
  jwt:
    public_key_file: /etc/xkms/jwt-public.pem   # config.go:583

metrics:
  enabled: true
  path: /metrics
  port: 9090

backends:          # a struct keyed by backend name (BackendsConfig, config.go:1114)
  software:
    enabled: true
    path: "xkms-data/keys/software"
```

Every key can also be set from the environment as `XKMS_<PATH>`, with nesting
joined by underscores. For example, `logging.level` becomes
`XKMS_LOGGING_LEVEL` (`pkg/config/load.go:38`, `:201`).

## Build and test

```bash
make build            # all binaries
make build-server     # xkmsd
make build-cli        # xkmsctl
make test             # unit tests; make test-<pkg> for one package
make integration-test # devcontainer; make integration-test-<area> per area
make coverage
make proto            # regenerate gRPC stubs
```

## Health

`GET /health`, `/health/live`, `/health/ready` and `/health/startup` are
public (`pkg/api/rest/routes.go:124-128`).

## Resources

- [Architecture index](./README.md)
- [overview.md](./overview.md)
- [api-specifications.md](./api-specifications.md)
- [host-embedding](../host-embedding/engineering.md)
- [Build toggles](../crypto-backends/engineering.md#build-toggles)
- [Getting started](../../xkey/docs/usage/getting-started.md)
