# Browser Extension AutoFill — CLI

> **Status: NORMATIVE** · Feature: `autofill` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

Every flag below is read from `cmd/xkey/cmd/extension.go`/`extension_serve.go`'s
`init()` and matches `xkey extension <verb> --help` built from this
checkout. See [architecture.md](architecture.md) for the native-messaging
and pairing concepts these verbs manage.

## `xkey extension install [chrome|firefox|all]`

Installs the native messaging manifest so a browser can launch the host.
For `chrome`, installs to every detected Chromium-based browser (Chrome,
Brave, Chromium, Edge).

| Flag | Default | Description |
|---|---|---|
| `--allowed-origin` | | Override the Chrome extension origin (e.g. for an unpacked dev build's generated ID) |

```bash
xkey extension install
xkey extension install chrome
xkey extension install firefox
xkey extension install chrome --allowed-origin "chrome-extension://your_extension_id/"
```

## `xkey extension uninstall [chrome|firefox|all]`

Removes the manifest(s). A missing manifest is reported, not an error.

```bash
xkey extension uninstall
xkey extension uninstall chrome
```

## `xkey extension status`

Table of manifest installation status per browser (Chromium derivatives
listed individually).

```bash
xkey extension status
# BROWSER    INSTALLED  PATH
# chrome     yes        ~/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json
# firefox    no         ~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json
```

## `xkey extension host` (hidden; invoked by the browser)

Runs the native messaging host process for one browser-launched connection.
Not intended to be run manually.

| Flag | Default | Description |
|---|---|---|
| `--socket` | auto-detect | IPC socket path |
| `--no-pairing` | `false` | Skip extension identity verification (development only) |

## `xkey extension unpair`

Removes the paired browser-extension Ed25519 identity, requiring a fresh
pairing ceremony before the extension can reconnect. No flags.

```bash
xkey extension unpair
```

## `xkey extension pair-status`

Shows whether any extension is paired, and each paired origin's pairing
timestamp. No flags.

```bash
xkey extension pair-status
```

## `xkey extension serve`

Runs a production-grade headless autofill IPC server — the non-GUI
equivalent of the desktop app's extension-facing side, for servers and SSH
sessions with no desktop environment.

| Flag | Default | Description |
|---|---|---|
| `--socket` | auto-detect | IPC Unix socket path |
| `--log-level` | `info` | `debug`, `info`, `warn`, `error` |
| `--log-file` | stderr | Log file path |
| `--barrier-password` | | Barrier password |
| `--barrier-password-file` | | Read the barrier password from a file (first line) |
| `--no-barrier` | `false` | Plain file storage, no encryption (testing/development) |
| `--auto-lock-minutes` | `15` | Inactivity lock timeout (`0` disables) |
| `--pin-state` | | PIN state directory path |
| `--no-auth` | `false` | Disable CTAP2 authentication for autofill (credentials returned without PIN/touch) |
| `--no-pairing` | `false` | Disable extension identity verification (testing only) |
| `--so-pin-stdin` | `false` | Read the SO PIN from stdin, to verify a sealed enterprise policy (no `--so-pin` value flag exists, deliberately — see `xkey pin --help`) |
| `--tpm-device` | `$TPM_DEVICE_PATH` or `/dev/tpmrm0` | TPM device for the `tpm2` barrier strategy |
| `--tpm-simulator` | `false` | In-process TPM simulator (requires a simulator build) |

A `pkcs11`, `shamir`, or cloud-KMS barrier strategy is refused at startup
with a typed error naming why a headless process cannot drive it — see
[engineering.md](engineering.md)'s error table.

```bash
# Production: barrier-encrypted
xkey extension serve --barrier-password "my-secret"
XKEY_BARRIER_PASSWORD=secret xkey extension serve

# Honor a sealed enterprise policy
XKEY_SO_PIN=... xkey extension serve

# Development: no barrier, no CTAP2 auth, no pairing verification
xkey extension serve --no-barrier --no-auth --no-pairing

# Unseal a tpm2-strategy barrier
xkey extension serve --tpm-device /dev/tpm0
xkey extension serve --tpm-simulator

# Custom socket and log level
xkey extension serve --socket /tmp/xkey.sock --log-level debug
```

## Native messaging host manifest

Name: `com.automatethethings.xkey`. Chrome manifests use `allowed_origins`
(default `chrome-extension://ogbhdplieldlomhnokdapcopejmkelkl/`, overridable
with `--allowed-origin`); Firefox manifests use `allowed_extensions`
(`xkey@automatethethings.com`). Manifest directories are created mode
`0755`, files mode `0644`.

| Browser | Linux path |
|---|---|
| Chrome (and Chromium derivatives) | `~/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json` (per derivative) |
| Firefox | `~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json` |
