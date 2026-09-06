# Virtual FIDO2 Authenticator — CLI

> **Status: NORMATIVE** · Feature: `virtual-authenticator` · Module: `go-xkms/xkey` · Last verified: 2026-09-06

Binary: `xkey`. Groups: `fido2` (the daemon) and `uhid` (device setup and
policy). Sources: `xkey/cmd/xkey/cmd/fido2.go`, `uhid.go`.

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
| `--storage-path` | `./data` | for `file` |
| `--barrier-password` | `""` | for `barrier` |
| `--barrier-password-file` | `""` | first line of a file |

**The default is `memory`, and credentials do not survive a restart.** That is
fine for a first look and wrong for daily use — pick `file` or `barrier` before
you register anything you care about.

### Where the keys live

| Flag | Default | Notes |
|---|---|---|
| `--backend` | `software` | `software`, `tpm2`, `phone` |
| `--tpm-device` | `/dev/tpmrm0` | for `tpm2` |
| `--phone-device` | `""` | a specific paired phone; default is your default phone |
| `--attestation` | `none` | `none`, `packed`, `tpm` |

A relying party cannot tell these apart over CTAP2. If you tell someone your
credentials are hardware-backed, `--backend` is the flag that makes that true.

### Presence and PIN

| Flag | Default | Notes |
|---|---|---|
| `--pin` | `true` | require a PIN |
| `--set-pin` | `""` | establish the initial PIN when the store has none (needs `--pin`; refused if a PIN is already set) |
| `--require-touch` | `true` | **require a touch even after a verified PIN** |
| `--unified-pin` | `true` | one PIN across xkey's subsystems |
| `--timeout` | `30s` | how long to wait for presence |

`--set-pin` is a first-PIN operation. It runs the authenticator's
`SetInitialPIN`, the in-process counterpart of the CTAP `setPIN` ceremony,
and refuses to start when the store already holds a PIN:

```
fido2: --set-pin refused: a PIN is already configured in this store; drop --set-pin or change the PIN through the FIDO2 client
```

With `--storage memory` every start is a first start. With `--storage file`
or `--storage barrier`, pass `--set-pin` once; on later starts drop it, and
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

**`--notify none` with `--require-touch true` is the configuration that looks
broken**: the authenticator waits for a touch nobody was prompted for, and the
browser hangs until the timeout.

### Password typing on touch

| Flag | Default |
|---|---|
| `--password-store` | `./data/staticpw` |
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

## The token lifecycle — `init-token` and `change-so-pin`

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

```
xkey fido2 init-token
xkey fido2 change-so-pin
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

## `xkey uhid`

Device-level setup and per-relying-party policy.

| Verb | Purpose |
|---|---|
| `uhid setup` | Set up the UHID device |
| `uhid policy list` | List relying-party policies |
| `uhid policy set` | Set a policy |
| `uhid policy get` | Show a policy |
| `uhid policy delete` | Remove a policy |
| `uhid profile set` | Set the device profile |
| `uhid profile show` | Show the device profile |

`policy set` applies only the flags given on the command line. A flag left
unset keeps the stored value; an explicit zero (`--blocked=false`, `--uv ""`)
takes effect. Blocking a relying party therefore survives later writes that
do not mention `--blocked`.

```
xkey uhid setup
xkey uhid policy list
xkey uhid profile show
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
