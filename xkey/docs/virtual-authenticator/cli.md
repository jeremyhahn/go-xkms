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
