# TPM 2.0 — User Guide

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-08-19

## What a TPM gives you that software cannot

Three things, and they are worth separating because people conflate them:

1. **Keys that cannot be copied.** A key marked fixed to the TPM cannot be
   exported by anyone, including you.
2. **Data that only unlocks on this machine, in this state.** Sealing binds data
   to PCR values — the measurements of firmware and boot.
3. **Evidence.** Attestation lets a remote party check what this machine is
   before trusting it, and the answer comes from the chip rather than from
   software that could be lying.

## There is no `xkmsctl tpm` group

You reach the TPM by choosing it:

```
xkmsctl --backend tpm2 key generate node-key --key-algorithm ecdsa --curve P-256
xkmsctl seal "secret" --backend tpm2
xkmsctl barrier init --barrier-strategy tpm2 --user-pin -
xkmsctl key attest node-key --backend tpm2 --output evidence.json
```

## Check three things on any TPM deployment

A healthy TPM, a simulator standing in for one, and a TPM sitting in lockout all
behave identically until an operation fails.

```
xkmsctl backends get tpm2 -o json   # configured? HardwareBacked? Attestation?
xkmsctl pin lockout -o json         # in dictionary-attack lockout?
```

and, in the server's startup log, which device or simulator it actually opened.

## Sealing: choosing what to bind to

Sealing to PCRs means the data unseals only when the machine measures the same.
That is the feature, and it is also the outage:

- Bind to **firmware and boot PCRs** and the data survives ordinary kernel
  updates.
- Bind to PCRs that change on every update and the data stops unsealing after
  the next one.

Neither is wrong. Decide which you meant, and keep a recovery path either way —
a sealed blob is bound to that TPM and cannot be moved.

## Attestation: what it actually proves

```
xkmsctl key attest node-key --backend tpm2 --output evidence.json
```

The evidence proves the key was generated inside a TPM whose endorsement key
chains to a manufacturer you trust. Two caveats that matter:

- **A quote needs a fresh nonce.** Evidence you did not just request proves
  nothing about now.
- **Storing evidence is not verifying it.** The CA can import an attestation and
  verify it separately; make sure whoever consumes it does the second part.

Enrolling a whole machine by its TPM is the ACME `enroll-01` path — the server
encrypts a secret to the TPM's endorsement key and only the real chip can
recover it. See [`../acme-issuance/user.md`](../acme-issuance/user.md).

## The lockout counter

Failed authorizations advance a counter that survives reboots. When it fills,
the TPM refuses authorizations until either the lockout authorization clears it
or its own recovery interval elapses.

```
xkmsctl pin lockout -o json
xkmsctl pin lockout-reset --so-pin -
```

**Check before retrying.** A wrong PIN entered five more times is how a
development machine becomes unusable for hours.

## Development without hardware

The simulator covers the whole surface. Two things surprise people:

- It is configured as **`simulator_host` / `simulator_port`** (default `2321`),
  **not** as `device_path`. A `tcp://host:port` in `device_path` names a file
  that does not exist.
- It serves **one client at a time**. A second connection blocks rather than
  being refused, which looks exactly like a hang.

## Troubleshooting

| What you see | What it means | What to do |
|---|---|---|
| TPM unavailable | no device, wrong path, or permissions | check the server's startup log for what it opened |
| everything hangs against the simulator | another process holds the single connection | stop the other one |
| sealed data will not unseal after a firmware or kernel update | the PCRs changed | expected; use the recovery path, and reconsider the PCR selection |
| authorization keeps failing | check lockout **before** retrying | `xkmsctl pin lockout` |
| TPM refuses everything | dictionary-attack lockout | `pin lockout-reset --so-pin -`, or wait out the interval |
| NV space exhausted | too many NV indices | free some, or review the PIV NV base index |
| attestation rejected | the EK does not chain to a trusted manufacturer root | import the manufacturer chain server-side |
| the TPM "stops working" after hours of uptime | leaked sessions or object contexts | a code defect — the leak test suites exist for this |
| a node's TPM behaves oddly in ways nothing explains | firmware bugs are real | check the chip's firmware revision before the code |

## Where to go next

- Keys in the TPM: [`../crypto-backends/user.md`](../crypto-backends/user.md)
- Sealing and the barrier: [`../sealing-and-barrier/user.md`](../sealing-and-barrier/user.md)
- PINs and lockout: [`../pin-management/user.md`](../pin-management/user.md)
- Enrolling hardware: [`../acme-issuance/user.md`](../acme-issuance/user.md)
