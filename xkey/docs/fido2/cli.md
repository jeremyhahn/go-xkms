# FIDO2 Daemon and GUI Device Host — CLI

> **Status: NORMATIVE** · Feature: `fido2` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

Binary: `xkey`. This page covers the verbs this folder owns: `xkey touch`,
`xkey unlock`, `xkey fido2 status` and `xkey fido2 provision-attestation`.

The full `xkey fido2` flag reference (`--storage`, `--backend`,
`--require-touch`, `--pin`, `--notify`, `--cdp`, …), `xkey fido2 policy` /
`profile` / `init-token` / `change-so-pin`, and `xkey uhid` are documented in
[`virtual-authenticator/cli.md`](../virtual-authenticator/cli.md). `xkey auth
register` / `login` are [`headless-webauthn/cli.md`](../headless-webauthn/cli.md).

## `xkey touch`

Approves a pending user-presence request over IPC, or types a stored
password via the virtual keyboard (`touch.go`).

| Flag | Default | Notes |
|---|---|---|
| `--password` | `""` | Name of a stored password to type instead of approving presence |
| `--socket` | auto-detect | IPC socket path |

Behavior: with no pending WebAuthn request and no `--password`, it types the
daemon's `--default-password` if one is configured, otherwise reports "No
pending request". A daemon that is not running fails with
`ErrTouchDaemonNotRunning` rather than a generic connection error.

```bash
xkey touch
xkey touch --password "DatabaseProd"
xkey touch --socket "$XDG_RUNTIME_DIR/xkey/xkey.sock"
```

## `xkey unlock`

Unlocks a running instance by sending its user PIN over IPC (`unlock.go`).
A locked instance refuses CTAP2 operations with "operation denied", which
names no lock at all — `unlock` is what to reach for when an enrollment or
ceremony is denied by a daemon that is otherwise running.

The PIN is supplied the same two ways as every PIN-accepting command in
xkey, resolved by `resolvePINInput`
(`xkey/cmd/xkey/cmd/pin_input.go:159-161,181`), in precedence order — there
is no `--pin` value flag, because a value on the command line is visible to
every other process on the host via `ps` (go-xkms#272):

| Source | Notes |
|---|---|
| `--pin-stdin` | Read the PIN from standard input (preferred) |
| `XKEY_PIN` | Environment variable |

| Flag | Default | Notes |
|---|---|---|
| `--socket` | auto-detect | IPC socket path |

```bash
printf '%s' "$PIN" | xkey unlock --pin-stdin
XKEY_PIN="$PIN" xkey unlock
```

On success the command names the subsystems it released — for example
`Unlocked: app lock, barrier` — and re-confirms that state against the
daemon's own status query rather than trusting the unlock response alone.
It exits non-zero when:

- the daemon rejects the PIN (`ErrUnlockFailed`);
- the unlock opened some subsystems but left others locked
  (`ErrUnlockIncomplete`, naming both sets);
- the daemon still reports itself locked after a reported-successful unlock
  (`ErrUnlockStillLocked`) — reporting success here would let every
  automated flow that follows proceed on a false premise.

A wrong PIN over this verb spends one of a budget of 8 attempts, counted
independently of and in addition to any retry counter the PIN backend keeps
itself. The rejection reports attempts remaining; at zero the daemon refuses
outright, without evaluating the PIN, until a Security Officer runs `xkey pin
reset-lockout` or `xkey pin set-user` against the daemon's data directory.

## `xkey fido2 status`

Reports whether the daemon is up and what it is storing (`fido2_status.go`).

| Flag | Default | Notes |
|---|---|---|
| `--socket` | auto-detect | IPC socket path |

```console
$ xkey fido2 status
FIDO2 daemon: running (daemon_ready)
Socket:       /run/user/1000/xkey/xkey.sock
Store:        file
Store path:   /var/lib/xkey
Store prefix: xkey/
At rest:      NOT encrypted — credential records, including passkey
              private keys, are readable with your file permissions
```

`Store`/`Store path`/`Store prefix` are omitted only if a daemon predating
this report is running (`Store: unknown (daemon did not report it)`). Under
`--storage barrier` the last line reads `At rest: encrypted by the barrier`;
under `--storage memory` it reads `At rest: nothing stored — credentials are
lost when the daemon exits`. Exits non-zero when no daemon is listening
(`ErrFIDO2StatusDaemonNotRunning`).

## `xkey fido2 provision-attestation`

Provisions the device's attestation identity so registrations stop reporting
`fmt: none` and start carrying a WebAuthn Level 2 packed statement with an
x5c chain. This is a Security Officer operation: the SO PIN gates
provisioning the identity, not using it, and the command prompts for it
interactively.

| Flag | Default | Notes |
|---|---|---|
| `--rotate` | `false` | Replace an existing identity (invalidates every statement issued under the old key) |
| `--profile` | `""` | CA certificate profile to issue under (default: the CA's own default) |
| `--validity-days` | `0` | Certificate validity in days (default: the CA's own default) |
| `--socket` | auto-detect | IPC socket used only for the daemon-liveness check |
| `--tls-ca` | `""` | CA bundle used to verify TLS transports to xkmsd |

```bash
xkey fido2 provision-attestation
xkey fido2 provision-attestation --profile attestation --validity-days 730
xkey fido2 provision-attestation --rotate
```

The device generates its attestation key and a PKCS#10 request on-device;
only the request is sent to the xkms enterprise CA, and the issued chain is
installed back onto the device — the private key never leaves it. The
daemon owns the device state while it runs, so `provision-attestation`
refuses while `xkey fido2 status` reports one listening, and refuses on
`--storage memory` (`ErrAttestProvisionVolatileStorage`), where a
provisioned identity cannot survive the process exiting. Set
`fido2.attestation` to `packed` so the running daemon actually presents the
identity once installed — the command names this when the current setting
would leave it unused.

An unreachable CA (`ErrAttestProvisionCAUnreachable`) or a refused request
(`ErrAttestProvisionCARefused`) leaves the device exactly as it was: nothing
is provisioned before the chain is verified and installed.

## Exit codes

`0` on success. Non-zero on any of the sentinel errors above, or when the
IPC socket cannot be reached at all.
