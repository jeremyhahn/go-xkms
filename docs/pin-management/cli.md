# PIN Management — CLI

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-08-19

Binary: `xkmsctl`, group `pin` (`cmd/xkmsctl/pin.go`). Global flags:
[`../key-management/cli.md`](../key-management/cli.md).

## How PIN values are supplied

Every PIN flag accepts three forms, and the order matters:

1. **omitted** — `xkmsctl` prompts, and the PIN is never on the command line.
   This is the right form for a human.
2. **`-`** — read from stdin. This is the right form for automation:
   `printf '%s' "$PIN" | xkmsctl pin user-verify --pin -`
3. **a literal value** — goes into shell history, `ps` output and any command
   log. Available, but the last resort.

## Security-officer PIN

| Verb | Flags |
|---|---|
| `pin so-set` | `--current-pin` (required when an SO PIN is already set), `--new-pin` |
| `pin so-change` | `--current-pin`, `--new-pin` |
| `pin so-verify` | `--pin` |

```
xkmsctl pin so-set --new-pin -
xkmsctl pin so-change --current-pin - --new-pin -
xkmsctl pin so-verify --pin -
```

**On the TPM2 backend these all fail with "PIN not set", by design.** The TPM
has no SO PIN — its administrative authorization is the platform's hierarchy
passwords. If you are on TPM2 and reaching for `so-*`, the operation you want is
at the platform level, not here. See
[`architecture.md`](architecture.md) §"The TPM2 backend is deliberately
asymmetric".

## User PIN

| Verb | Flags |
|---|---|
| `pin user-set` | `--so-pin` (authorizes the operation), `--new-pin` |
| `pin user-change` | `--current-pin`, `--new-pin` |
| `pin user-verify` | `--pin` |

```
xkmsctl pin user-set --so-pin - --new-pin -
xkmsctl pin user-change --current-pin - --new-pin -
xkmsctl pin user-verify --pin -
```

Setting a user PIN is authorized by the SO PIN; changing it is authorized by the
current user PIN. On a backend with no SO PIN, `user-set` behaves according to
that backend's rules.

## Lockout

| Verb | Flags | Purpose |
|---|---|---|
| `pin lockout` | — | Report the device's lockout state |
| `pin lockout-reset` | `--so-pin` | Clear the lockout |

```
xkmsctl pin lockout -o json
xkmsctl pin lockout-reset --so-pin -
```

**Check `pin lockout` before troubleshooting a PIN problem.** A device
approaching its retry limit and a device already locked out look the same from
the outside — a failed operation — but only one of them is recoverable by
retrying. On a PKCS#11 token, exhausting the counter is permanent: the token
becomes unusable, and no PIN recovers it.

`lockout-reset` on the TPM2 backend uses the TPM's **lockout authorization**,
which is a different and stronger credential than the user PIN. The `--so-pin`
flag carries it on this verb.

## Which backend am I actually talking to?

Selection happens at server start, and the server logs one line:
`PIN backend selected  strategy=tpm2|pkcs11|software`. There is no CLI verb to
query it, and a deployment that expected a TPM and silently got software has a
far weaker PIN store — so that log line is worth checking after any change to
hardware or configuration.

## Exit codes

`0` on success; non-zero on wrong PIN, lockout, an unprovisioned platform, or an
absent device. A wrong PIN and a locked-out device are both failures but need
different responses — read the message, and check `pin lockout`.

## Parity coverage

**Defect: no `pin` verb has a `CommandDefinition` in
`test/integration/api/commands/commands.go`.** The eight PIN routes exist on
REST, gRPC, QUIC and Unix (see [`api.md`](api.md)), and the handlers have their
own suites, but the CLI verbs are absent from the table-driven multiprotocol
parity runner.
