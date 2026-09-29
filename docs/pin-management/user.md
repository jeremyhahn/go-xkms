# PIN Management — User Guide

> **Status: NORMATIVE** · Feature: `pin-management` · Repo: `go-xkms` · Last verified: 2026-09-29

## Two PINs, two jobs

- **Security-officer (SO) PIN** — the administrative credential. It authorizes
  setting the user PIN and resetting a lockout.
- **User PIN** — the everyday credential that unlocks key operations.

Which of them exists depends on the hardware. **On a TPM there is no SO PIN**:
the TPM's administrative authorization is its hierarchy passwords, held by the
platform, not something the KMS sets. Every `pin so-*` command against a TPM
backend reports "PIN not set", and that is the correct answer, not a
misconfiguration.

## Never put a PIN on the command line

Every PIN flag supports three forms:

```
xkmsctl pin user-verify                        # prompts — use this
printf '%s' "$PIN" | xkmsctl pin user-verify --pin -   # stdin — use this in scripts
xkmsctl pin user-verify --pin 123456           # in your shell history forever
```

The third form exists. It should not be the one you reach for.

## Setting up a fresh token

Order matters: the SO PIN first, because it authorizes the user PIN.

```
xkmsctl pin so-set --new-pin -
xkmsctl pin user-set --so-pin - --new-pin -
```

Check it worked:

```
xkmsctl pin user-verify --pin -
```

## Changing PINs

```
xkmsctl pin so-change   --current-pin - --new-pin -
xkmsctl pin user-change --current-pin - --new-pin -
```

## Lockout — read this before you retry

Hardware counts failed attempts, and the counter survives restarts and
reconnections.

```
xkmsctl pin lockout -o json
```

**On a PKCS#11 token, exhausting the retry counter is permanent.** The token
becomes unusable and no PIN, reset or reinstall recovers it. If a PIN is not
working, check the lockout state *before* trying again — the check costs
nothing, and the retry might cost the token.

To clear a lockout:

```
xkmsctl pin lockout-reset --so-pin -
```

On TPM2 this uses the TPM's **lockout authorization**, which is a separate,
stronger credential than the user PIN. If you do not have it, you cannot clear
the lockout, and the TPM will clear it itself only after its own recovery
interval.

## Which PIN store am I actually using?

This is worth knowing, because the three stores are not equally strong. xkmsd
and xKey choose the store the same way, and the first choice is recorded in
`pin/strategy` beside the PIN state. After that, every start uses the recorded
store.

On xkmsd, set it with `pin.strategy`:

```yaml
pin:
  enabled: true
  strategy: tpm2      # auto (default) | software | tpm2
backends:
  tpm2:
    enabled: true     # required for strategy: tpm2
```

- `tpm2` keeps your PIN in the TPM as the auth value of the Platform SRK. The
  TPM checks the PIN and applies its own lockout. If no TPM is available, the
  server refuses to start instead of falling back to software.
- `auto` uses a TPM only if the PIN on it is already confirmed. Otherwise it
  records `software`.
- Changing the setting after a store is recorded is refused, because it would
  orphan every PIN in the old store. To switch, reset PIN state deliberately.

The server logs the store it uses at startup:

```
PIN manager initialized  strategy=tpm2
```

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| "PIN not set" on every `so-*` command | you are on the TPM2 backend, which has no SO PIN | expected; the equivalent operation is at the platform level |
| wrong PIN, and it used to work | check the lockout state before retrying | `xkmsctl pin lockout` |
| device locked out | the retry counter is exhausted | `pin lockout-reset --so-pin -`; on PKCS#11 this may be unrecoverable |
| "not provisioned" | the TPM platform store is not set up | provision the platform first |
| device unavailable | the TPM or token is not reachable from the server | check the hardware, then restart and read the selection line |
| everything works but feels too easy | you may be on the software backend | check the selection log line |

## Where to go next

- The barrier the PIN protects: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- TPM specifics: [`../tpm2/user.md`](../tpm2/user.md)
- PKCS#11 tokens: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- PINs as an authentication factor: [`../auth-factors/user.md`](../auth-factors/user.md)
