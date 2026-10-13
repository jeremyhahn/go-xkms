# DICE Device Identity — CLI

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-12

**No CLI surface of its own.** There is no `xkmsctl dice` command group and
none is planned for this half of the feature.

DICE reaches the command line in two indirect ways, both of which are surfaces
that already existed:

## Issuing with the DICE profile

`dice-idevid` is a built-in certificate profile (`pkg/ca/profiles.go:83`), so
the `xkmsctl ca` verbs that take `--profile` — `ca sign-csr` and `ca issue`
(`cmd/xkmsctl/ca.go:573-580`) — can name it. The profile refuses a request that carries no
`tcg-dice-TcbInfo` extension, which is every request not produced by a DICE
device — so in practice this is reached by the enrollment path, not by hand.

```bash
xkmsctl ca sign-csr --csr request.pem --profile dice-idevid
# ca: request carries no tcg-dice-TcbInfo extension
```

That refusal is the expected result and is the profile working. The evidence
has to come from the device.

## Inspecting a device certificate

`certstore` knows the DICE OIDs by name, so any command that prints a
certificate renders them as `tcg-dice-TcbInfo`, `tcg-dice-Ueid` and the other
`tcg-dice-*` names (`pkg/certstore/types.go:255-259`) rather than as bare
digits. A UEID stated as UCCS claim 256 sits inside the
`tcg-dice-UCCS-evidence` value and is not rendered separately; read it with
`dice.DeviceUeid` (see [`engineering.md`](engineering.md)).

## What is deliberately absent

A verb that mints or checks the ACME possession request. The device signs it
and the ACME client wraps it (`attestedKeyCSR`,
`pkg/acme/client/enrollment.go:1010`); the server checks it at finalize. Both
ends are library calls, documented in [`api.md`](api.md).

A verb that drives a device to produce evidence. That belongs to the AVR
backend — the device is reached over its wire protocol, not by this package —
and adding a placeholder here would be a command that cannot complete.
