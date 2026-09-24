# DICE Device Identity — CLI

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-09-23

**No CLI surface of its own.** There is no `xkmsctl dice` command group and
none is planned for this half of the feature.

DICE reaches the command line in two indirect ways, both of which are surfaces
that already existed:

## Issuing with the DICE profile

`dice-idevid` is a registered certificate profile, so any `xkmsctl` verb that
takes `--profile` can name it. The profile refuses a request that carries no
`tcg-dice-TcbInfo` extension, which is every request not produced by a DICE
device — so in practice this is reached by the enrollment path, not by hand.

```bash
xkmsctl certs generate --profile dice-idevid --cn avr-device-0001
# ca: request carries no tcg-dice-TcbInfo extension
```

That refusal is the expected result and is the profile working. The evidence
has to come from the device.

## Inspecting a device certificate

`certstore` knows the DICE OIDs by name, so any command that prints a
certificate renders them as `tcg-dice-TcbInfo` and `tcg-dice-Ueid` under the
TCG extensions heading rather than as bare digits.

## What is deliberately absent

A verb that drives a device to produce evidence. That belongs to the AVR
backend — the device is reached over its wire protocol, not by this package —
and adding a placeholder here would be a command that cannot complete.
