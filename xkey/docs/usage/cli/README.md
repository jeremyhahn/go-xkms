# xkey CLI

`xkey` is the desktop CLI. The same binary serves the GUI and the CLI; it
dispatches on whether a subcommand was given, so `xkey <command>` runs the CLI
and a bare `xkey` starts the GUI — provided the binary was built with a GUI
build tag and a graphical session is present. See Building, below.

This page indexes the command groups. Run `xkey <command> --help` for the
authoritative flag list — the tree below is derived from the cobra
registrations in `xkey/cmd/xkey/cmd/`.

> **Not to be confused with `xkmsctl`**, which is the *server* admin CLI for
> `xkmsd` — key and certificate management, tenants, cluster, backends. Most
> files in this directory document `xkmsctl` rather than `xkey`, and each now
> carries a scope banner saying so: `admin.md`, `backends.md`, `barrier.md`,
> `bootstrap.md`, `ca.md`, `cert.md`, `fido2.md`, `frost.md`, `key.md`,
> `migrate.md`, `noise.md`, `pin.md`, `piv.md`, `tls.md`, `user.md`. (On
> `noise.md`: the top-level `xkmsctl noise` group was removed, and what
> survives is `xkmsctl bootstrap noise`, so that page documents the command
> under its current path. `xkey` itself has no `noise` command.)
> The xkey-scoped pages are this one, `auth.md`, `share.md` and `extension.md`.
>
> Watch out for the overlapping names: `xkmsctl` and `xkey` both have `barrier`,
> `ca`, `cert`, `pin`, `piv` and `fido2` command groups, with **different**
> surfaces on each side.

## Building

```bash
cd xkey && go build -o xkey ./cmd/xkey
```

That produces a **CLI-only** binary. The GUI half needs one of the Wails build
tags (`production`, `dev`, `bindings`); without one, a bare `xkey` prints build
instructions and exits 2 rather than opening a window. `make build` (docker) or
`make build-local` in `xkey/` supply the tags — along with `ble` — and write
the result to `build/bin/xkey`.

Some commands sit behind build tags — notably the phone/BLE commands under
`xkey device`, which need the `ble` tag. Without the tag the binary carries a
stub that reports the feature is unavailable rather than omitting the command.

Two meta-flags are consumed before cobra sees the arguments, so they appear in
no `--help` output: `--gui` forces the GUI even when a subcommand was given,
and `--no-gui` forces the CLI even with none. Otherwise any subcommand (or
`--help` / `-h`) selects the CLI, and no subcommand plus a graphical session
(`DISPLAY` or `WAYLAND_DISPLAY` on Linux) selects the GUI.

## Automation primitives

These three are what make xkey drivable without a human present.

```bash
# Unlock a running instance (stdin > XKEY_PIN > --pin)
printf '%s' "$PIN" | xkey unlock --pin-stdin
XKEY_PIN="$PIN" xkey unlock
xkey unlock --pin "$PIN"          # visible in the process list; avoid

# Approve a pending user-presence request, or type a stored password
xkey touch
xkey touch --password DatabaseProd

# Run the authenticator so a PIN-verified ceremony never blocks on a touch;
# a ceremony with no PIN still waits for `xkey touch`
sudo xkey fido2 --require-touch=false --notify none
```

`unlock` reports what it released, for example `Unlocked: app lock, barrier`,
confirms that state against the daemon's own view of its lock, and exits
non-zero when the daemon rejected the PIN, when a subsystem it governs is
still locked, or when the daemon still reports itself locked. A script may
gate on its exit status: an unlock that reported success while the barrier
stayed sealed would surface much later as an unrelated `operation denied`
from the authenticator, which reads as a declined touch.

Both `unlock` and `touch` accept `--socket` to override IPC socket
auto-detection.

## Command groups

### Authentication and identity

| Command | Subcommands |
|---------|-------------|
| `xkey auth` | `register`, `login`, `status`, `token` |
| `xkey oidc` | `login`, `token`, `refresh`, `logout`, `status`, `stop`, `providers`, `aws` |
| `xkey pin` | `set-so`, `set-user`, `change-so`, `change-user`, `verify`, `status`, `reset-lockout` |
| `xkey unlock` | (unlock a running instance) |

`xkey auth register` and `xkey auth login` run the WebAuthn ceremony against a
local CTAP2 authenticator with no browser involved — a real security key, or
`xkey fido2` running. They fail rather than fabricating a credential.

The server is verified against the system roots, the xKey trust store, and any
`--tls-ca` bundle; `--spki-pin` pins the key directly for a server whose CA is
nowhere on this host and is recorded on the server entry for reuse. See
[auth.md](auth.md#server-trust).

```bash
xkey auth register --server https://xkms.example.com:8443 --email alice@example.com
xkey auth register --server https://xkms.example.com:8443 --email alice@example.com --spki-pin abc123
xkey auth register --server https://xkms.example.com:8443 --email alice@example.com --setup-token TOKEN
xkey auth login --server https://xkms.example.com:8443 --email alice@example.com
xkey auth token --server https://xkms.example.com:8443
```

`xkey oidc providers` takes `list`, `add` and `remove`.

### FIDO2 / WebAuthn

| Command | Subcommands |
|---------|-------------|
| `xkey fido2` | `start`, `status`, `policy`, `profile` |
| `xkey touch` | (approve presence / type a password) |
| `xkey uhid` | `setup` |

The bare `xkey fido2` *is* the daemon; `start` is a named alias for it and
accepts the same flags. The daemon flags are local rather than persistent, so
they are not available on `policy` or `profile`. `policy` takes
`list`/`set`/`get`/`delete` per relying party; `profile` takes
`set`/`show`. `status` takes `--socket`. See
[../../fido2/daemon-configuration.md](../../fido2/daemon-configuration.md).
(`fido2.md` in this directory describes a different thing — `xkmsctl fido2`,
which drives *external* FIDO2 hardware keys.)

### Secrets

| Command | Subcommands |
|---------|-------------|
| `xkey password` | `add`, `list`, `get`, `remove`, `type`, `unlock`, `lock`, `status`, `access-mode` |
| `xkey oath` | `add`, `list`, `generate`, `remove`, `scan`, `sync`, `push`, `pull` |
| `xkey platform-store` | `put`, `get`, `delete`, `list`, `reseal`, `status` |
| `xkey share` | `list`, `receive`, `import`, `export`, `unseal`, `delete` |

```bash
xkey oath add --name GitHub --issuer GitHub --secret BASE32SECRET
xkey oath add --uri 'otpauth://totp/...'
xkey oath generate GitHub     # the current TOTP code
xkey oath scan                # read a QR code off the screen
```

`xkey oath sync`, `push` and `pull` move credentials to and from a paired
phone. Note the removal verb is `remove`, not `delete`, for both `password`
and `oath`.

### Certificates and trust

| Command | Subcommands |
|---------|-------------|
| `xkey ca` | `info`, `issue`, `sign-csr`, `revoke`, `crl`, `check-revocation`, `bundle` |
| `xkey cert` | `request`, `show`, `export` |
| `xkey trust` | `list`, `add`, `remove`, `show`, `bootstrap`, `classify`, `install`, `uninstall`, `fetch`, `import-platform` |
| `xkey policy` | `create`, `list`, `get`, `delete`, `set-auto-unseal`, `clear-auto-unseal`, `refresh`, `verify`, `export` |

### Hardware

| Command | Subcommands |
|---------|-------------|
| `xkey tpm` | `status`, `info`, `pcrs`, `quote`, `ek`, `iak`, `idevid`, `provision`, `install`, `clear` |
| `xkey piv` | `list`, `show`, `store`, `import`, `export`, `delete`, `generate`, `csr`, `status`, `phone-*` |
| `xkey usb` | `create`, `status`, `update`, `device` |

```bash
xkey tpm pcrs            # PCR values
xkey tpm ek show         # endorsement key
xkey tpm quote           # signed quote
```

`xkey tpm ek` takes `show`, `export`, `backup` and `restore`; `iak` and
`idevid` take `show`/`create`/`export`/`csr`. Under `idevid`, `cert` has the
single subcommand `import` (a CA-signed IDevID certificate; self-signed is
refused), and the PEM-format CSR export is a subcommand of `csr` --
`xkey tpm idevid csr export`, alongside the bare `csr` that emits TCG-CSR-IDEVID.
`xkey usb device` takes `start`/`stop`/`status`.

### Phones

`xkey device` covers paired Android devices: `list`, `status`, `pair`,
`unpair`, `scan`, `enroll`, `enroll-phone`, `connect`, `listen`, `relay`,
`attest`, `attest-device`, `device-info`, `share`, `share-policy`, `import`,
`sync`, `sync-status`, `sync-push`, `sync-pull`.

```bash
xkey device pair --device "John's Pixel"
xkey device relay --qr          # show a pairing QR for the phone to scan
xkey device list
```

`xkey device pair` takes `--device`, `--timeout` and `--force`. QR *generation*
is `xkey device relay --qr`; there is no CLI command that scans a pairing QR —
the phone does that. See
[../../device/cli.md#device-relay-and-qr-pairing](../../device/cli.md#device-relay-and-qr-pairing).

### SSH

`xkey ssh` covers `keys`, `host-keys`, `authorized-keys`, `connect`, `console`,
`profile`, `local` and `sessions`. `keys` takes
`generate`/`import`/`list`/`get`/`delete`/`export`; `host-keys` and
`authorized-keys` take `add`/`list`/`remove`; `profile` takes
`add`/`list`/`get`/`remove`/`mv`.

### Disk encryption

`xkey luks2` covers `seal`, `unseal`, `lock`, `wipe`, `migrate` and
`import-data`.

### Barrier and backup

| Command | Subcommands |
|---------|-------------|
| `xkey barrier` | `init`, `seal`, `unseal`, `status` |
| `xkey backup` | `create`, `restore`, `list`, `contents`, `to-device`, `from-device` |

### Browser integration

| Command | Subcommands |
|---------|-------------|
| `xkey extension` | `install`, `uninstall`, `status`, `serve`, `host`, `unpair`, `pair-status` |
| `xkey browser` | `launch [url]` |

`install` and `uninstall` accept `chrome`, `firefox` or `all`. See
[extension.md](extension.md).

### Miscellaneous

| Command | Subcommands |
|---------|-------------|
| `xkey agent` | `start`, `stop`, `status` |
| `xkey config` | `show`, `init`, `path` |
| `xkey version` | (version info) |

## See Also

- [xkey auth](auth.md) -- server authentication in detail
- [xkey share](share.md) -- key share management
- [Browser Extension](extension.md)
- [FIDO2 Daemon Overview](../../fido2/overview.md)
- [FIDO2 Daemon Configuration](../../fido2/daemon-configuration.md)
- [QR Pairing](../../device/cli.md#device-relay-and-qr-pairing)
