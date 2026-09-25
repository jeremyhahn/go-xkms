# PIV Certificate Management — API

> **Status: NORMATIVE** · Feature: `piv` · Module: `go-xkms/xkey` · Last verified: 2026-09-27

No REST/gRPC/MCP transport surface of its own — the CLI and the GUI both
call into the same go-xkms SDK types and, for remote backends, the same
xkmsd transport documented in
[docs/piv-smartcard/api.md](../../../docs/piv-smartcard/api.md). This page
only maps the two xkey-side façades to each other.

| Capability | CLI (`xkey piv ...`) | GUI (`services.PIVService`, Wails binding) |
|---|---|---|
| List slots and their certificates | `piv list` | `GetSlots()` |
| Show one certificate | `piv show <slot>` | `GetCertificate(slot)` |
| Store an existing certificate | `piv store <slot> <cert-file>` | `ImportCertificate(slot, certPEM)` |
| Generate a key + self-signed cert | `piv generate <slot>` (default `--output-format self-signed`) | `GenerateKey(slot, algorithm)` |
| Generate with full options (pin/touch policy, CA-signed, CSR-only, public-key-only) | `piv generate <slot> --pin-policy ... --output-format ...` | `GenerateKeyAdvanced(opts)` |
| Generate a CSR for an existing key | `piv csr <slot>` | `GenerateCSR(slot, subject)` |
| Export a certificate | `piv export <slot>` | `ExportCertificate(slot)` |
| Export the public key | (via `piv generate --output-format public-key`) | `ExportPublicKey(slot)` |
| Delete a certificate | `piv delete <slot>` | `DeleteCertificate(slot)` |
| Import an external certificate with verification | `piv import <slot> <cert-file>` | `ImportCertificate(slot, certPEM)` (verification is a CLI-side option, not exposed as a GUI parameter) |
| Self-sign an existing key without regenerating it | (no direct CLI equivalent) | `SelfSignExistingKey(slot, commonName, validityDays)` |
| Report whether a CA is available for a backend | `piv generate --output-format ca-signed` fails if none is | `GetCAAvailability() map[string]bool` |

Both façades call through the same `xkms.PIVCertificateStorage` (local) or
`transport.Client` (remote, xkmsd-backed) paths — see
[architecture.md](architecture.md#gui-a-localremote-split-mirroring-the-clis-backendstorage-split).
There is one capability list, not two independently maintained ones; the
table above exists to translate between the CLI verb and the GUI method a
reader coming from either side is looking for.

## SDK

`sdk/go` re-exports the PIV manager and storage types xkey depends on
(`PIVCertificateStorage`, `PIVManagerConfig`, `InitializePIV`,
`RegisterPIVStore`, `PIVSlot`, `PIVSlotName`, `PIVPrimarySlots`,
`PIVCertFormat`, `ValidatePIVSlot`, `NewFileStorageBackend`,
`PIVFileStorageConfig`, `NewPIVFileBackend`) — see
[engineering.md](engineering.md#exported-surface--sdk-types-this-feature-consumes)
for the full list and
[docs/piv-smartcard/engineering.md](../../../docs/piv-smartcard/engineering.md)
for their contract.
