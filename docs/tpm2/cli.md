# TPM 2.0 — CLI

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-08-19

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
