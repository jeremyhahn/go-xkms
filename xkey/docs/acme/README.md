# ACME Client Namespace

> **Status: DESIGN** · Feature: `acme` · Module: `go-xkms/xkey` · Planned: nothing on this page is built yet
> Scope: the planned `xkey acme` namespace; the ACME client itself is [acme-issuance](../../../docs/acme-issuance/).

## Purpose

`xkey acme` will put ACME certificate issuance beside xkey's TPM, seal,
platform-trust and device verbs, in the CLI and the GUI alike. It is a front
end only: the ACME client is one library, `pkg/acme/client`, and xkey carries
no client logic of its own.

## Verbs

| Verb | Purpose |
|---|---|
| `account` | Create and manage the ACME account |
| `enroll` | Obtain a certificate through the `enroll-01` challenge |
| `endorse` | Obtain a certificate through the `endorse-01` challenge |
| `renew` | Renew an issued certificate |
| `revoke` | Revoke an issued certificate |

## Call path

```
xkey acme (CLI and GUI) -> go-xkms/sdk/go -> go-xkms/pkg/acme/client
```

xkey reaches the client only through `sdk/go`, as every xkey feature does.
The dedicated `cmd/acme-client` binary is the other front end over the same
library, for installers, the initrd and hosts without xkey.

## Status

Planned. See the `acme` row in [docs/SPEC.md](../../../docs/SPEC.md#xkey).
