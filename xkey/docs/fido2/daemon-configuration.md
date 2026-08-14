# FIDO2 Daemon Configuration

Every `xkey fido2` setting can come from three places. Flags win over
environment variables, which win over the config file:

```
--flag  >  XKEY_FIDO2_*  >  config file
```

The environment variable and config key for a flag are its name with dashes
turned into underscores: `--storage-path` is `XKEY_FIDO2_STORAGE_PATH` and
`fido2.storage_path`.

The flags below are **local to `xkey fido2`** rather than persistent, so they
are not available on `policy` or `profile`. `xkey fido2 start` is an alias for
the bare form and accepts all of them — it copies the daemon's flag set when it
registers itself, so an existing invocation can move to the named verb without
change.

## Storage

| Flag | Default | Description |
|------|---------|-------------|
| `--storage` | `memory` | `memory`, `file` or `barrier` |
| `--storage-path` | `./data` | Path for file storage |
| `--barrier-password` | (none) | Barrier password for the credential store |
| `--barrier-password-file` | (none) | File to read the barrier password from |

`memory` loses every credential on exit, which is what you want for tests and
not what you want anywhere else. Use `--storage file` for anything persistent,
or `--storage barrier` to keep the store encrypted at rest. Any other value is
rejected; `file` requires `--storage-path` and `barrier` requires one of
`--barrier-password` / `--barrier-password-file`.

## Device identity

| Flag | Default | Description |
|------|---------|-------------|
| `--name` | `xKey (go-xkms)` | Device name visible to the OS |
| `--serial` | (auto-generated) | Device serial number (16-char hex) |

## PIN

| Flag | Default | Description |
|------|---------|-------------|
| `--pin` | `true` | Enable PIN support (required for FIDO 2.1 credential management) |
| `--set-pin` | (none) | Set the initial PIN (requires `--pin`) |
| `--unified-pin` | `true` | Synchronize the PIN across FIDO2, PKCS#11, and file PIN systems |

The Security Officer PIN is not set here — it belongs to the `xkey pin` command
group (`xkey pin set-so`, `xkey pin change-so`, `xkey pin status`,
`xkey pin reset-lockout`).

## User presence

| Flag | Default | Description |
|------|---------|-------------|
| `--require-touch` | `true` | Require touch even after PIN verification |
| `--auto-uv` | `false` | Report built-in user verification so Chrome skips its PIN dialog |
| `--interactive` | `false` | Prompt on the terminal for each request |
| `--timeout` | `30s` | How long a user presence request waits before failing |

Presence is required by default. For unattended operation either set
`--require-touch=false --auto-uv`, or leave the default and have a script call
`xkey touch` when a request is pending.

## Key backend

| Flag | Default | Description |
|------|---------|-------------|
| `--backend` | `software` | `software`, `tpm2`, or `phone` |
| `--tpm-device` | `/dev/tpmrm0` | TPM device path (when `--backend tpm2`) |
| `--phone-device` | (default paired phone) | Phone name or address (when `--backend phone`) |
| `--attestation` | `none` | `none`, `packed`, or `tpm` |

Any other `--backend` value fails with "fido2: invalid backend type". `tpm`
attestation requires the `tpm2` backend.

## Chrome DevTools bridge

| Flag | Default | Description |
|------|---------|-------------|
| `--cdp` | `false` | Drive Chrome's virtual authenticator instead of creating a UHID device |
| `--cdp-host` | `localhost` | Chrome DevTools host |
| `--cdp-port` | `9222` | Chrome DevTools debugging port |

This is the configuration that avoids `/dev/uhid`, and therefore `sudo`
entirely. The trade-off is that it only works against a Chrome started with
remote debugging on that port.

## IPC and notifications

| Flag | Default | Description |
|------|---------|-------------|
| `--socket` | (auto) | IPC socket path |
| `--notify` | `dialog` | `dialog` (interactive), `passive` (desktop notification), `log`, or `none` |
| `--notify-command` | (none) | Custom notification command, overriding the built-in notifiers |
| `--password-store` | `./data/staticpw` | Static password store path |
| `--default-password` | (none) | Password name typed on a bare `xkey touch` |

The socket defaults to `$XDG_RUNTIME_DIR/xkey/xkey.sock`, falling back to
`/tmp/xkey-$UID/xkey.sock` when `XDG_RUNTIME_DIR` is unset. Use `--notify log`
on headless hosts, where a D-Bus dialog has nobody to show itself to.

## Examples

```bash
# Development: ephemeral, prompts on the terminal
sudo xkey fido2 --interactive

# Service: persistent storage, TPM keys, desktop notification + xkey touch
sudo xkey fido2 \
  --backend tpm2 \
  --storage file --storage-path /var/lib/xkey \
  --notify dialog

# CI: nothing to approve, nothing to click
sudo xkey fido2 --require-touch=false --auto-uv --storage memory

# Headless host: log instead of a dialog nobody can see
sudo xkey fido2 --storage file --storage-path /var/lib/xkey --notify log
```

## See Also

- [Daemon Overview](overview.md)
- [Daemon Architecture](daemon-architecture.md)
- [FIDO2 README](README.md) -- full flag reference in context
- [Authenticator Configuration](authenticator-config.md) -- configuring the CTAP2 library directly
