# xkmsd Configuration — CLI

> **Status: NORMATIVE** · Feature: `xkmsd-configuration` · Repo: `go-xkms` · Last verified: 2026-09-09

Binary: `xkmsd` (`cmd/xkmsd/main.go`, flags in `cmd/xkmsd/flags.go`). The
daemon uses the standard-library `flag` package: a flag is written `-host`
or `--host`, both forms are accepted.

## Global flags

| Flag | Type | Default | Purpose |
|---|---|---|---|
| `--config`, `-c` | path | `/etc/xkms/xkmsd.yaml` | configuration file. `XKMS_CONFIG` overrides it (a known divergence from the precedence order, tracked separately) |
| `--host` | string | *(unset)* | bind host for every network listener. Sets `server.host`; wins over `XKMS_SERVER_HOST` and the file. Applied only when given, so `--host ""` explicitly selects every interface |
| `--daemon`, `-d` | bool | `false` | run as daemon |
| `--pid-file` | path | `""` | write the PID file |
| `--version` | bool | `false` | print version and exit |

`--seal-passphrase` was removed (go-xkms#653): there is no config-, flag-, or
env-sourced boot-time barrier secret any more, matching go-qrdb's own
`SealConfig`. Unseal a software-strategy barrier with `xkmsctl barrier
unseal` (or `unseal-shares`) after every restart, or configure a hardware
seal strategy (`barrier.strategy: "tpm2"`/`"pkcs11"`) for unattended
auto-unseal.

## Examples

Pin the listeners to one address for this run, whatever the file says:

```sh
xkmsd --config /etc/xkms/xkmsd.yaml --host 10.0.0.5
```

Serve on every interface although the file pins a host:

```sh
xkmsd --config /etc/xkms/xkmsd.yaml --host ""
```

Set the host from the environment instead (a unit file, a container spec):

```sh
XKMS_SERVER_HOST=10.0.0.5 xkmsd --config /etc/xkms/xkmsd.yaml
```

`xkmsd init` has its own flag set; see
[`../init-ceremony/cli.md`](../init-ceremony/cli.md).
