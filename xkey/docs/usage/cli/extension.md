# Browser Extension

> **Status: REFERENCE** · Last verified: 2026-10-13
> Scope: the `xkey extension` command group (`xkey/cmd/xkey/cmd/extension.go`, `extension_serve.go`); the normative reference is [`../../autofill/`](../../autofill/architecture.md).

The xKey browser extension fills passwords and TOTP codes into web forms. It
talks to a running xKey instance — the desktop app, or the headless
`xkey extension serve` — through a native messaging host and the instance's
Unix socket IPC.

## Architecture

```
Browser extension  <-->  Native messaging host  <-->  xKey IPC server (GUI or serve)
   (MV3)                 (stdin/stdout)               (Unix socket)
```

The browser launches the xkey binary as its native messaging host. Chrome
passes `chrome-extension://<id>/` and Firefox passes the manifest path; xkey
detects either and runs the hidden `xkey extension host` command
(`xkey/cmd/xkey/main.go:274`). The host name is `com.automatethethings.xkey`
and messages are limited to 1 MB (`xkey/pkg/nativemsg/protocol.go:24`).

| Layer | Mechanism |
|-------|-----------|
| Channel | X25519 ECDH handshake, HKDF-SHA256 directional keys, AES-256-GCM |
| Replay protection | Per-direction counter nonce; a nonce not above the last accepted one is rejected |
| Extension identity | Ed25519 key per browser profile, pinned per extension origin |
| Pairing | 6-digit code, valid 5 minutes, entered in the extension |
| Browser binding | Parent process check via `/proc/$PPID/exe` (Linux) |

The handshake, pairing and message formats are specified in
[autofill architecture](../../autofill/architecture.md) and
[autofill engineering](../../autofill/engineering.md).

### Pairing

On first contact the host asks for pairing and sends a 6-digit code to the
IPC server, which shows it in the GUI or, under `extension serve`, on the
terminal. The user types it into the extension popup. The host then stores the
extension's Ed25519 public key keyed by origin, so several extensions can be
paired at once. Later connections sign
`SHA-256(ephemeral X25519 key || origin || "xkey-ext-v1")`; a different key or
origin is rejected.

Pairing state lives in `extension/pairing.json` under the xKey data directory
(`~/.xkey/data` by default; `xkey/cmd/xkey/cmd/extension.go:437`). The failure
counters live beside it in `pairing-limits.json`, so relaunching the host does
not reset a lockout (`xkey/pkg/nativemsg/pairing_limits.go:27`).

### Autofill actions

After the handshake the extension sends encrypted IPC requests with one of
these actions (`xkey/pkg/ipc/autofill_types.go:20`):

| Action | Purpose | Fields |
|--------|---------|--------|
| `search` | Credentials for a domain | `domain` |
| `get` | A credential and its password | `id`, `challenge` |
| `totp` | TOTP code for a domain | `domain` |
| `totp_by_id` | TOTP code for an account | `id` |
| `status` | Lock state and policy | none |
| `policy` | Current policy | none |
| `save` | Save a credential from a form submission | `domain`, `username`, `password`, `title` |
| `ignore_domain` | Never offer to save for a domain | `domain` |
| `focus` | Bring the GUI window to the front | none |

With CTAP2 authentication on, `get` needs `challenge` (base64, 32 random bytes)
and the response carries an assertion (authenticator data, signature,
credential ID) the extension can verify.

## Commands

```
xkey extension
├── install [chrome|firefox|all]     # Write native messaging manifests
├── uninstall [chrome|firefox|all]   # Remove them
├── status                           # Manifest status per browser
├── serve                            # Headless autofill IPC server
├── unpair                           # Remove every paired extension identity
└── pair-status                      # Show paired extensions
```

### install and uninstall

`chrome` covers every Chromium-based browser found (Chrome, Brave, Chromium,
Edge, Opera, Vivaldi); `firefox` covers Firefox-family browsers; `all` is the
default.

| Flag | Command | Description |
|------|---------|-------------|
| `--allowed-origin` | `install` | Override the Chrome extension origin (for an unpacked extension) |
| `--profile-dir` | both | Pair one Chrome profile's user-data directory with this xkey instance; requires `chrome` |

```bash
xkey extension install
xkey extension install chrome --allowed-origin "chrome-extension://your_extension_id/"
xkey extension install chrome --profile-dir ~/agents/agent-a/chrome-profile
xkey extension uninstall chrome --profile-dir ~/agents/agent-a/chrome-profile
xkey extension uninstall firefox
```

`--profile-dir` writes a manifest that launches a small generated script
pinning the host to this instance's socket and data, so two xkey instances
run by the same OS user can each pair with their own Chrome profile.

Manifest locations on Linux and macOS (`xkey/pkg/nativemsg/manifest.go:128`):

| Browser | Linux | macOS |
|---------|-------|-------|
| Chrome | `~/.config/google-chrome/NativeMessagingHosts/` | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/` |
| Firefox | `~/.mozilla/native-messaging-hosts/` | `~/Library/Application Support/Mozilla/NativeMessagingHosts/` |

The file is `com.automatethethings.xkey.json` in each.

### status

Prints one row per browser, each Chromium derivative separately:

```
BROWSER    INSTALLED  PATH
Chrome     yes        <home>/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json
Firefox    no         <home>/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json
```

### unpair and pair-status

`unpair` deletes every stored extension identity; each extension must pair
again. `pair-status` prints `Status: Not paired`, or the paired extensions
with their origins and pairing times.

### serve

Runs the autofill pipeline without a desktop session. It opens the IPC socket
only when local app access is on and refuses to start otherwise; enable it
with `xkey app-access enable`.

| Flag | Default | Description |
|------|---------|-------------|
| `--barrier-password-stdin` | `false` | Read the barrier password from stdin |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--so-pin-stdin` | `false` | Read the SO PIN from stdin, to verify a sealed enterprise policy |
| `--tpm-device` | `$TPM_DEVICE_PATH` or `/dev/tpmrm0` | TPM for the `tpm2` and `pkcs11` strategies |
| `--tpm-simulator` | `false` | Use the in-process TPM simulator (simulator builds only) |
| `--auto-lock-minutes` | `15` | Inactivity lock timeout; `0` disables it |
| `--pin-state` | `<data dir>/pin` | PIN state directory |
| `--log-level` | `info` | `debug`, `info`, `warn` or `error` |
| `--log-file` | stderr | Log file |
| `--no-barrier` | `false` | Use plain file stores (development only) |
| `--no-auth` | `false` | Return credentials without CTAP2 PIN or touch (development only) |
| `--no-pairing` | `false` | Skip extension identity verification (testing only) |

The socket is the global `--socket`, which defaults as described below.

```bash
xkey extension serve --barrier-password-stdin < password.txt
XKEY_BARRIER_PASSWORD=secret xkey extension serve
xkey extension serve --barrier-password-file /run/secrets/barrier
xkey extension serve --tpm-device /dev/tpm0
xkey extension serve --no-barrier --no-pairing --log-level debug
```

The barrier password is taken from, in order, `--barrier-password-stdin`,
`--barrier-password-file`, `XKEY_BARRIER_PASSWORD`, and a no-echo prompt when
stdin is a terminal (`xkey/cmd/xkey/cmd/extension_serve.go:694`). There is no
`--barrier-password` value flag.

The barrier strategy is read from the stored root key and unsealed
headlessly where possible (`xkey/cmd/xkey/cmd/extension_serve.go:242`):

- `software` (Argon2id passphrase) uses the barrier password. With no barrier
  initialized yet, `serve` initializes one with this strategy.
- `tpm2` tries the TPM auto-unseal policy first, then a direct TPM unseal.
- `pkcs11` releases the token PIN that `xkey barrier init` sealed under the
  TPM platform policy, so no one types it.
- `aws_kms`, `gcp_kms`, `azure_kv` and `vault` rebuild the backend from the
  configuration `xkey barrier init` saved and use the provider's credentials;
  see [seal/cli.md](../../seal/cli.md).
- `shamir` is refused with `ErrServeShamirStrategyUnavailable`: a quorum of
  operator shares cannot be collected headlessly. Unseal with
  `xkey barrier unseal`.

In an enterprise deployment with a sealed config directory, the SO policy is
honoured only after it verifies with the SO PIN (`--so-pin-stdin` or
`XKEY_SO_PIN`). Without the PIN the command fails closed.

### Default socket path

`--socket` defaults to `$XKEY_HOME/run/xkey.sock` when `XKEY_HOME` is set,
otherwise `$XDG_RUNTIME_DIR/xkey/xkey.sock`. Without `XDG_RUNTIME_DIR` it uses a
per-user directory: `/run/user/$SUDO_UID` under sudo, `$TMPDIR` on macOS,
`~/.xkey/run` elsewhere. It never falls back to a shared directory such as
`/tmp` (`xkey/pkg/ipc/socket.go:78`).

## Security notes

| Attack | Mitigation |
|--------|------------|
| Rogue extension or local process | No matching Ed25519 identity: rejected |
| Reinstalled extension | New identity key: must pair again |
| Replayed handshake | Identity signature covers the ephemeral X25519 key |
| Replayed or tampered messages | Counter nonces and AES-GCM authentication |
| Pairing code guessing | 3 failures: 15-minute lockout; codes expire after 5 minutes |
| Identity verification flooding | 5 failures: 5-minute lockout |

The constants are in `xkey/pkg/nativemsg/pairing.go:35`. The extension
manifest declares no `externally_connectable`, so other extensions and web
pages cannot message the host.

On Linux the host accepts only these parent binaries
(`xkey/pkg/nativemsg/pairing.go:365`): `chrome`, `chromium`, `google-chrome`,
`google-chrome-stable`, `chromium-browser`, `brave-browser`, `vivaldi-bin`,
`opera`, `microsoft-edge`, `firefox`, `firefox-esr`, `firefox-bin`. Where
`/proc` cannot be read the check is skipped; it is defence in depth, not the
only control.

## Data storage

| Path (under `~/.xkey/data`) | Contents | Protection |
|------|----------|-----------|
| `extension/pairing.json` | Paired extension public keys and origins | Public keys only |
| `extension/pairing-limits.json` | Pairing and verification failure counters | Mode 0600 |
| Barrier store | Static passwords and OATH accounts | Barrier encryption |
| `staticpw/`, `oath.json` | The same stores under `--no-barrier` | None |
| `pin/` | PIN state | Lockout metadata |

## Deployment

### systemd

```ini
[Unit]
Description=xkey extension server
After=network.target

[Service]
Type=simple
User=xkey
ExecStart=/usr/local/bin/xkey extension serve \
    --barrier-password-file /etc/xkey/barrier-pw \
    --log-file /var/log/xkey/extension.log \
    --auto-lock-minutes 0
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Run `xkey app-access enable` as the service user first.

### SSH socket forwarding

Forward a remote instance's socket to the path the local host resolves:

```bash
ssh -L "$XDG_RUNTIME_DIR/xkey/xkey.sock:/run/user/1000/xkey/xkey.sock" remote-host
```

## Integration tests

```bash
cd xkey && make integration-test-extension
```

The tests talk to the IPC socket directly, with no browser.

## Troubleshooting

**The extension cannot connect.** Check `xkey extension status`, that the GUI
or `xkey extension serve` is running, that local app access is on
(`xkey app-access status`), and that the socket exists at the path above.

**Pairing is required again after an update.** Reinstalling the extension or
clearing its storage creates a new identity key. Pair again.

**`extension serve: barrier password required`.** Supply it with
`--barrier-password-stdin`, `--barrier-password-file` or
`XKEY_BARRIER_PASSWORD`, or use a strategy that unseals headlessly.

**`nativemsg: identity verification locked due to too many failures`.** Wait
5 minutes (15 after three failed pairing codes). Restarting the host does not
clear the lockout.

## See Also

- [Autofill feature folder](../../autofill/user.md)
- [FIDO2 CLI Commands](./fido2.md)
- [Getting Started Guide](../getting-started.md)
- [WebAuthn Documentation](../webauthn.md)
- [Chrome Native Messaging](https://developer.chrome.com/docs/extensions/develop/concepts/native-messaging)
