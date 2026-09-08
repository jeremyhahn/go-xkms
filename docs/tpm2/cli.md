# TPM 2.0 — CLI

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-09-08

`xkmsctl` has **no `tpm` command group**. The TPM is reached through whichever
feature is using it, by selecting it as the backend or strategy:

| To do this | Use | Documented in |
|---|---|---|
| put a key in the TPM | `xkmsctl --backend tpm2 key generate …` | [`../key-management/cli.md`](../key-management/cli.md) |
| attest a TPM-resident key | `xkmsctl key attest <id> --backend tpm2` | [`../key-management/cli.md`](../key-management/cli.md) |
| seal data to platform state | `xkmsctl seal <data> --backend tpm2` | [`../sealing-and-barrier/cli.md`](../sealing-and-barrier/cli.md) |
| protect the barrier with the TPM | `xkmsctl barrier init --barrier-strategy tpm2` | [`../sealing-and-barrier/cli.md`](../sealing-and-barrier/cli.md) |
| manage the TPM-backed PIN | `xkmsctl pin …` | [`../pin-management/cli.md`](../pin-management/cli.md) |
| store PIV certificates in NV | `xkmsctl piv …` (server configured `tpm2`) | [`../piv-smartcard/cli.md`](../piv-smartcard/cli.md) |
| enroll a device by its TPM | `trusted-acme-client device enroll` | [`../acme-issuance/cli.md`](../acme-issuance/cli.md) |
| issue EK/AK certificates | the `ca tcg` API surface | [`../certificate-authority/api.md`](../certificate-authority/api.md) |

The desktop companion does have a group — `xkey tpm` — covering PCR policies
and TPM state from the client side. See the xkey documentation.

## Device identity enrollment: no flags changed, the ceremony did

`xkmsctl ca tcg sign` (`cmd/xkmsctl/ca_tcg.go`) is the CA side: it signs a
packed `TCG_CSR_IDEVID` to issue the IAK and IDevID certificates. Its flags
are unchanged. What changed is the device side that produced the CSR: the
`TPM2_Certify` proving the IDevID lives in the same TPM as the IAK now runs
under the IDevID's ADMIN-role policy as the Privacy Administrator, which
requires the endorsement hierarchy authorization (`ek.hierarchy-auth`) at
provisioning time. A device whose provisioning config lacks it cannot produce
a certifiable IDevID, and says so (`ErrDevIDPolicySession`) rather than
emitting an unverifiable CSR. See `user.md`, "Identity keys".

Two further changes on the device side that a CA operator will see: the
packed CSR's first four bytes are now `01 00 01 00` (§13.1's structure
version for an IDevID CSR) instead of `00 00 01 00` — `xkmsctl ca tcg sign`
and the ACME `enroll-01` path accept both — and a device whose EK certificate
is missing no longer produces a CSR at all; its `xkmsd` install stops with
`ErrDevIDProvisionEKCert`. See `user.md`, "Provisioning either completes or
refuses".

The identity keys themselves also changed shape, and no flag says so: they now
carry the `'IDEVID'` / `'IAK'` `unique` strings of TCG §7.3.1, an RSA IDevID
names no signature scheme, and `tpm.device-string` in the server configuration
appends the optional per-device string. All three are inputs to how the TPM
derives the key, so a device provisioned before this release presents a
different key to `ca tcg sign` than it did and needs its certificates
re-issued. See `user.md`, "Upgrading a device provisioned before this
release".

## Checking what you are actually talking to

Two things are worth confirming on any TPM deployment, because a healthy TPM, a
simulator and a locked-out TPM all look the same until something fails:

```
xkmsctl backends get tpm2 -o json     # is tpm2 configured, and what can it do?
xkmsctl pin lockout -o json           # is the TPM in dictionary-attack lockout?
```

## The simulator is configured differently from a device

Worth knowing before losing an afternoon to it. In the shipped configuration the
TPM simulator is addressed by **`simulator_host` / `simulator_port`** (default
`2321`), not by `device_path`. Putting a `tcp://host:port` string in
`device_path` names a file that does not exist —
`configs/xkmsd-integration.yaml` documents this at length for that reason.

The simulator also serves **exactly one client at a time**: a second connection
blocks rather than being refused, which looks like a hang.

## Parity coverage

No verbs, so no `CommandDefinition` entries. TPM coverage rides on the features
that use it — `key-generate-*`, `seal`, `unseal`, `can-seal`, `tls-cert` — plus
the large simulator suite in `pkg/tpm2` and `test/integration/tpm2`.
