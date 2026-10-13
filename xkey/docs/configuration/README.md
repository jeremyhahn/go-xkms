# xkey Configuration Guide

> **Status: REFERENCE** · Last verified: 2026-10-13
> Index of where xkey is configured; per-feature flags live in the normative feature folders linked below.

xkey takes its settings from three places, highest precedence first:

1. **Command-line flags.** Flags bound to a config key override it, such as
   `--log-level` → `log.level` and `--log-file` → `log.file`
   (`xkey/cmd/xkey/cmd/root.go:247-248`), or `xkey fido2 --storage` →
   `fido2.storage` (`xkey/cmd/xkey/cmd/fido2.go:439`).
2. **`XKEY_` environment variables**, one per config key.
3. **The `xkey.yaml` file**, merged key by key over the built-in defaults.
   `--config` names a different file (`root.go:220`).

The file schema, defaults, environment mapping and validation rules are in
[app-configuration.md](app-configuration.md).

## Global Flags

Every command accepts these (`xkey/cmd/xkey/cmd/root.go:220-242`):

| Flag | Default | Description |
|------|---------|-------------|
| `--config` | `~/.config/xkey/xkey.yaml` | Config file path |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-file` | stderr | Log output file |
| `--xkmsd-url` | | xkmsd server URL; enables server mode for all commands |
| `--backend` | | xkmsd backend to use (`software`, `tpm2`, `pkcs11`) |
| `--socket` | derived | IPC socket of the xkey instance to talk to |

## Where Each Area Is Configured

| Area | Normative documentation |
|------|-------------------------|
| `xkey.yaml` keys, defaults, `XKEY_` variables | [app-configuration.md](app-configuration.md) |
| Home and data directory (`XKEY_HOME`, `XKEY_DATA_DIR`, `--data-dir`) | [architecture/xhome.md](../architecture/xhome.md) |
| FIDO2 daemon flags: storage, PIN, interactive mode, key backend, attestation | [virtual-authenticator/cli.md](../virtual-authenticator/cli.md), [fido2/cli.md](../fido2/cli.md) |
| SO PIN, retry limits, CTAP vendor commands | [fido2/engineering.md](../fido2/engineering.md) |
| Barrier and TPM auto-unseal | [seal](../seal/) |
| LUKS2 container (`xkey luks2 seal`, `unseal`, `lock`, `migrate`, `wipe`, `import-data`) and wipe standards | [luks/cli.md](../luks/cli.md) |
| SSH agent | [ssh/cli.md](../ssh/cli.md) |
| OIDC and AWS login, token and session stores | [oidc](../oidc/) |
| Enterprise policy and its HMAC | [enterprise-mode.md](enterprise-mode.md), [enterprise-setup.md](enterprise-setup.md) |
| First-run setup | [setup-wizard](../setup-wizard/) |

## FIDO2 Credential Storage

`xkey fido2 --storage` selects where credentials live
(`xkey/cmd/xkey/cmd/fido2.go:377-380`):

| Value | Description |
|-------|-------------|
| `memory` | Default (`fido2.go:194`); credentials are lost on exit |
| `file` | Persistent; `--storage-path` overrides the directory (default `<data dir>/fido2`) |
| `barrier` | Persistent and barrier-encrypted |

```bash
sudo xkey fido2 --storage file
```

The LUKS2 commands are registered under `xkey luks2`
(`seal.go:88`, `unseal.go:65`, `lock.go:58`, `migrate.go:101`, `wipe.go:88`,
`import_data.go:82`); their flags and defaults are in
[luks/cli.md](../luks/cli.md).
