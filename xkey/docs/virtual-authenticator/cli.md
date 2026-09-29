# Virtual FIDO2 Authenticator — CLI

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-29

Binary: `xkey`. Groups: `fido2` (the daemon, token lifecycle, and per-RP
policy) and `uhid` (device setup). Sources: `xkey/cmd/xkey/cmd/fido2.go`,
`fido2_init_token.go`, `fido2_provision_attestation.go`, `fido2_policy.go`,
`uhid.go`.

## `xkey fido2` — run the authenticator

Starting it creates a UHID device that the OS presents as a USB security key.
Browsers and every other WebAuthn consumer then see it as hardware.

```
xkey fido2 --storage file --storage-path ~/.local/share/xkey --pin --require-touch
```

### Storage

| Flag | Default | Notes |
|---|---|---|
| `--storage` | `memory` | `memory`, `file`, `barrier` |
| `--storage-path` | `~/.xkey/data/fido2` | for `file`; resolved through the shared xkey data-directory chain (`XKEY_HOME`/`XKEY_DATA_DIR`), never the working directory (go-xkms#929) |
| `--barrier-password-stdin` | `false` | read the barrier password from standard input, for `barrier` |
| `--barrier-password-file` | `""` | first line of a file |

**The default is `memory`, and credentials do not survive a restart.** That is
fine for a first look and wrong for daily use — pick `file` or `barrier` before
you register anything you care about.

**`file` is plaintext at rest; `barrier` is the only encrypted option.**
go-qrdb's seal barrier is the one at-rest encryption xkey has — there is no
separate per-credential wrap. Every time `--storage file` opens its store the
daemon logs one warning naming the exposure and pointing at `xkey barrier
init`; this is a disclosure, not a refusal, since a plaintext store is a
legitimate choice for a host that has no barrier password to manage.
`--storage memory` never writes to disk and never carries the warning.

### Where the keys live

| Flag | Default | Notes |
|---|---|---|
| `--backend` | `software` | `software`, `tpm2`, `phone` |
| `--tpm-device` | `/dev/tpmrm0` | for `tpm2` |
| `--phone-device` | `""` | a specific paired phone; default is your default phone |
| `--attestation` | `none` | `none`, `packed`, `tpm` |

A relying party cannot tell these apart over CTAP2. If you tell someone your
credentials are hardware-backed, `--backend` is the flag that makes that true.

### Configuration sources

Of every `xkey fido2` flag, only four are also settable outside the command
line, because only these four are declared on `xkeyconfig.FIDO2Config`
(`pkg/config/config.go:72-82`): `--storage`, `--storage-path`, `--name` and
`--attestation`. Every other flag on this page (`--backend`, `--tpm-device`,
`--pin`, `--interactive`, `--notify*`, `--cdp*`, the phone and password
settings, …) is CLI-only. `buildFIDO2Config`
(`cmd/xkey/cmd/fido2.go:553-596`) resolves the four in flag-beats-
environment-beats-config-file order:

| Flag | Config key | Environment variable |
|---|---|---|
| `--storage` | `fido2.storage` | `XKEY_FIDO2_STORAGE` |
| `--storage-path` | `fido2.storage_path` | `XKEY_FIDO2_STORAGE_PATH` |
| `--name` | `fido2.device_name` | `XKEY_FIDO2_DEVICE_NAME` |
| `--attestation` | `fido2.attestation` | `XKEY_FIDO2_ATTESTATION` |

**The effective default for `--attestation` is `packed`, not the `none`
its own flag declares.** `xkeyconfig.DefaultConfig()` bakes in
`FIDO2.Attestation: "packed"` (`pkg/config/config.go`), and
`buildFIDO2Config` installs that as the flag's own default whenever no flag,
environment variable or config file names one -- the same three call sites
that read `FIDO2.Attestation` from the unified config
(`cmd/xkey/cmd/fido2.go`, `extension_serve.go`, `pkg/gui/app.go`) already
agreed on `packed` before go-xkms#871; it only extended the same mechanism to
`--storage`/`--storage-path`/`--name`. Those three have no such baked
override -- `xkeyconfig.DefaultConfig().FIDO2.Storage`/`.DeviceName` are
empty precisely so an unconfigured `xkey fido2` keeps behaving as this page's
"The default is `memory`" says, and only an explicit
`XKEY_FIDO2_STORAGE`/config-file/flag value changes it.

### Presence and PIN

| Flag | Default | Notes |
|---|---|---|
| `--pin` | `true` | require a PIN |
| `--set-pin-stdin` | `false` | read the initial PIN to establish from standard input (needs `--pin`; refused if a PIN is already set) |
| `--require-touch` | `true` | **require a touch even after a verified PIN** |
| `--unified-pin` | `true` | propagate the host PIN service's user PIN to this authenticator's CTAP2 PIN hash — not a separate PKCS#11/file sync; see [the setup-wizard doc on the one governing PIN backend](../setup-wizard/engineering.md#shared-governing-pin-strategy-go-xkms307) |
| `--timeout` | `30s` | how long to wait for presence |

`--set-pin-stdin` is a first-PIN operation. It runs the authenticator's
`SetInitialPIN`, the in-process counterpart of the CTAP `setPIN` ceremony,
and refuses to start when the store already holds a PIN:

```
fido2: --set-pin-stdin refused: a PIN is already configured in this store; drop --set-pin-stdin or change the PIN through the FIDO2 client
```

With `--storage memory` every start is a first start. With `--storage file`
or `--storage barrier`, pass `--set-pin-stdin` once; on later starts drop it, and
change the PIN through any FIDO2 client (`changePIN`), which proves the
current PIN before replacing it.

`--require-touch=false` is what makes this usable by an agent or a CI job,
where there is no human to touch anything but the job can send the PIN with
the ceremony. On a workstation it removes the deliberate act that proves you
are there. Use it where you mean it. There is no flag that reports user
verification the authenticator did not perform; a ceremony with no PIN still
waits for a touch, which `xkey touch` can supply.

### Identity and notifications

| Flag | Default |
|---|---|
| `--name` | `xKey (go-xkms)` — the device name the OS shows |
| `--serial` | generated when empty |
| `--notify` | `dialog` — `dialog`, `passive`, `log`, `none` |
| `--notify-command` | `""` — custom command, overrides built-in notifications |
| `--socket` | `$XDG_RUNTIME_DIR/xkey/xkey.sock` |
| `--interactive` | `false` |

`--notify-command` is split into argv and run exactly as given — never
through a shell. Request data (operation, RP ID, RP name, user name) reaches
it only via the `XKEY_OPERATION`/`XKEY_RP_ID`/`XKEY_RP_NAME`/`XKEY_USER_NAME`
environment variables, since RP name and user name come from the calling web
page: `--notify-command 'sh -c "notify-send xkey \"$XKEY_RP_ID\""'`.

**`--notify none` with `--require-touch true` is the configuration that looks
broken**: the authenticator waits for a touch nobody was prompted for, and the
browser hangs until the timeout.

### Password typing on touch

| Flag | Default |
|---|---|
| `--password-store` | `~/.xkey/data/staticpw` — the same store `xkey password` uses |
| `--default-password` | `""` — password name typed on a bare touch |

### Browser testing without the bus

| Flag | Default |
|---|---|
| `--cdp` | `false` — Chrome DevTools virtual-authenticator bridge |
| `--cdp-host` | `localhost` |
| `--cdp-port` | `9222` |

Anything that can reach that debugging port can drive the authenticator.

## `xkey fido2 start` / `status`

```
xkey fido2 status
```

## The token lifecycle — `init-token`, `change-so-pin`, and `provision-attestation`

The authenticator has two credentials with different jobs. The **user PIN**
authorises ceremonies; the **Security Officer PIN** authorises administration —
provisioning the attestation identity, replacing the attestation key, resetting
a forgotten user PIN, writing per-relying-party policy. These are xKey's
`C_InitToken` and `C_SetPIN` as SO (PKCS#11 v3.0 §5.6).

A device is **uninitialized** until it has an SO PIN, and an uninitialized
device refuses every SO-gated operation. "No Security Officer PIN" is a
refusal, never a waiver.

| Verb | Purpose | Requires |
|---|---|---|
| `fido2 init-token` | Establish the SO PIN. Runs once. | nothing — the token has no SO yet |
| `fido2 change-so-pin` | Replace the SO PIN. | the current SO PIN |
| `fido2 provision-attestation` | Provision (or rotate) the device's FIDO2 attestation identity. | the SO PIN |

```
xkey fido2 init-token
xkey fido2 change-so-pin
xkey fido2 provision-attestation
```

Both write the persisted device state `fido2.storage` and `fido2.storage_path`
name — the same state the daemon reads — so both refuse while the daemon is
running (it owns that state and would overwrite the change) and on `memory`
storage (nothing would survive the process). `--socket` names the socket used
for the liveness check; there are no other flags, because the storage comes from
configuration, not from a flag the daemon would not see.

`init-token` establishes and never replaces: a device that already has an SO
PIN is refused, before you are asked to choose one. After initialization the SO
PIN changes only through `change-so-pin`, which proves the current PIN and
spends a persisted retry when it is wrong; `authenticatorReset` is the only way
back to uninitialized.

**`xkey pin set-so` is a different subject.** It sets the *host* PIN service's
SO PIN, a separate credential under the data directory. Changing one does not
change the other.

### `provision-attestation`

Provisions or rotates the device's FIDO2 attestation identity through the
xkms enterprise CA: the device generates an attestation key on-device, the
command submits the resulting CSR, and the issued chain is installed back
onto the device. This is SO-gated — it prompts for the SO PIN — and, like
`init-token`/`change-so-pin`, refuses while the daemon is running.

| Flag | Default | Notes |
|---|---|---|
| `--rotate` | `false` | replace an existing attestation identity (invalidates statements issued under the old key) |
| `--profile` | `""` | CA certificate profile to issue under (default: the CA's own default) |
| `--validity-days` | `0` | certificate validity in days (default: the CA's own default) |
| `--socket` | `""` | FIDO2 daemon IPC socket path used for the liveness check (default: auto-detect) |
| `--tls-ca` | `""` | CA bundle used to verify TLS transports to xkmsd |

```
xkey fido2 provision-attestation
xkey fido2 provision-attestation --profile attestation --validity-days 730
xkey fido2 provision-attestation --rotate
```

Set `fido2.attestation` to `packed` so the daemon presents the installed
identity once provisioning finishes; the command reports when that setting
would leave it unused.

### What actually authorises the first one

The first SO PIN cannot be authenticated against anything — there is no
Security Officer yet. Over CTAP that window is bounded the way CTAP 2.1 §6.9
bounds `authenticatorReset`: only within ten seconds of power-up, and only with
user presence. **Neither bound constrains a local operator here**, because the
command starts the authenticator itself and the presence prompt asks the same
person who just typed the PIN. The control that applies is the file permissions
on the device's state directory, and `init-token` says so rather than implying
a check that did not fire.

Record the SO PIN somewhere outside the device. It is not kept in xKey's
password store — that store is unlocked by the *user* PIN, and the SO PIN is
what recovers a forgotten user PIN — so nothing can show it to you again.

## `xkey uhid` — device setup

| Verb | Purpose |
|---|---|
| `uhid setup` (hidden; no flags) | Configure `/dev/uhid` permissions (requires root; invoked via privilege escalation, e.g. the GUI's polkit/pkexec helper, not normally run directly) |

```
xkey uhid setup
```

## `xkey fido2 policy` / `xkey fido2 profile` — per-relying-party policy

| Verb | Flags | Purpose |
|---|---|---|
| `fido2 policy list` | — | List relying-party policies |
| `fido2 policy set` | `--rpid` (required), `--attestation` (`''`, `none`, `indirect`, `direct`, `enterprise`), `--blocked` (bool, default `false`), `--enterprise` (bool, default `false`), `--up` (`true`, `false`, `''`), `--uv` (`''`, `required`, `preferred`, `discouraged`) | Create or update a policy |
| `fido2 policy get` | `--rpid` (required) | Show a policy |
| `fido2 policy delete` | `--rpid` (required) | Remove a policy |
| `fido2 profile set` | `--enterprise-attestation` (bool, default `false`), `--transports` (comma-separated: `usb`, `nfc`, `ble`, `internal`, `hybrid`) | Set the device profile |
| `fido2 profile show` (alias `get`) | — | Show the persisted device profile |

`policy set` applies only the flags given on the command line. A flag left
unset keeps the stored value; an explicit zero (`--blocked=false`, `--uv ""`)
takes effect. Blocking a relying party therefore survives later writes that
do not mention `--blocked`.

```
xkey uhid setup
xkey fido2 policy list
xkey fido2 policy set --rpid example.com --uv required --enterprise
xkey fido2 policy get --rpid example.com
xkey fido2 policy delete --rpid example.com
xkey fido2 profile set --transports usb,internal
xkey fido2 profile show
```

## A working starting point

```
xkey fido2 \
    --storage file --storage-path "$XDG_DATA_HOME/xkey" \
    --backend tpm2 --attestation tpm \
    --pin --require-touch \
    --notify dialog
```

Persistent storage, keys in the TPM, honest attestation, a PIN, a touch, and a
prompt the human actually sees.

For an agent or CI, the same but with `--require-touch=false` and
`--notify none`, and the PIN sent with each ceremony — because there is nobody
there, which is the point.

## Exit codes

`0` on clean shutdown. Non-zero if the UHID device cannot be created (usually
permissions on `/dev/uhid`), the backend is unavailable, or storage cannot be
opened.

## Parity coverage

The multiprotocol parity runner in `go-xkms` covers `xkmsctl`, not `xkey`.
Coverage here is the `xkey/pkg/authenticator` unit suites, the Playwright
browser specs via the CDP bridge, and
`go-xkms/test/integration/{webauthn-browser,logins}`.
