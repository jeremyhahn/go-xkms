- **PIV enrollment records an attestation level, distinguishable from key
  origin** (#220, completes #207). `types.AttestLevel` (`pkg/types`, beside
  `types.KeyOrigin`) is the one shared vocabulary for "where a key lives" —
  `AttestLevelHardware`, `AttestLevelSoftware`, `AttestLevelUnattested` — that
  go-xkms and go-quicbaas's `AttestLevel` (go-quicbaas#379) now both speak,
  settling the cross-repo ownership question #220 raised: xkms owns the
  spelling. `types.KeyAttributes.AttestLevel` sits next to `KeyOrigin`, not
  merged into it — #207's own design note is explicit that the two answer
  independent questions, and an imported hardware key is the case that would
  lose meaning if they were one field.

  **Spelling note for go-quicbaas#379**: go-quicbaas's independently-drafted
  `AttestLevel` used `hardware` / `software` / `none`. xkms keeps
  `unattested` rather than adopting `none`, because `unattested` is already
  the REST `attest_level` claim value issued on live tokens (#200) and
  changing it would be a breaking wire change for every already-minted
  token. Per the ruling, go-quicbaas imports `types.AttestLevel` rather than
  keeping its own enum, so this is the one place the spelling needed to be
  reconciled, not two parallel vocabularies going forward.

  A new optional `xkms.PIVKeyGenerator` capability, `PIVAttestLevelReporter`
  (`AttestLevel(slot, cn) (types.AttestLevel, error)`), mirrors
  `PIVKeyOriginReporter`'s shape but answers a different kind of question: a
  backend's hardware backing does not vary key to key, so the answer is read
  live from `types.Capabilities.HardwareBacked` rather than from a per-key
  record, and it is always answerable rather than carrying a "not found"
  case. Both `PIVKeyGenerator` implementations in the tree satisfy it:
  `backendPIVKeyGenerator` classifies from the underlying backend's
  `Capabilities()` (hardware for TPM2/PKCS#11/cloud KMS, software for the
  PKCS#8-backed software backend), and `softwarePIVKeyGenerator` always
  reports software. `pivAttestLevel` is the fallback for a `PIVKeyGenerator`
  that implements no reporter at all — a caller-supplied generator that
  cannot back any hardware-backing claim — resolving to
  `AttestLevelUnattested` rather than a guess.

  `backendPIVKeyGenerator.GeneratePIVKey` and `.ImportPIVKey` stamp
  `attrs.AttestLevel` at the same write as `attrs.KeyOrigin`; an imported key
  on a hardware backend still records `AttestLevelHardware` — AttestLevel
  answers where the key lives, not whether it is exclusive, which
  `AttestPIVSlot`'s existing origin-based refusal already covers separately.
  `pkg/keyprovider/pkcs8` needs no metadata round trip for this field, unlike
  `KeyOrigin`: PKCS#8 storage is software cryptography by construction, so
  `ListKeys` always resolves to `AttestLevelSoftware`, correcting rather than
  trusting whatever was claimed in memory.

  The REST PIV login exchange (`POST /api/v1/auth/login/piv`) now prefers a
  recorded enrollment level over the certificate chain when one is available:
  `PIVLoginOptions.RecordedLevel` (`func(cert *x509.Certificate)
  (types.AttestLevel, bool)`) is consulted first, and only when it is nil or
  reports not-found does the pre-existing chain-derived decision run. This is
  a strict precedence, not a merge — a recorded `hardware` is never
  downgraded by a missing or failing chain (the chain is not examined once a
  recorded level is found), and a recorded `software` or `unattested` is
  never upgraded by a chain that happens to verify. `AllowUnattested` still
  gates whether a non-hardware level, recorded or chain-derived, may log in
  at all; `RecordedLevel` only decides which level that is. The existing
  `PIVAttestLevelHardware` / `PIVAttestLevelUnattested` REST constants move
  onto `types.AttestLevel` (`string(types.AttestLevelHardware)` /
  `string(types.AttestLevelUnattested)`) so there is one vocabulary rather
  than a second, independently-spelled copy — pinned by a test asserting the
  minted claim's string value is unchanged. gRPC and MCP have no parallel PIV
  login path to update: PIV login is REST-only, and the SDK's login client
  speaks to that one endpoint over mTLS.

  `RecordedLevel` is wired, not left as an unused seam: a new
  `PIVManager.AttestLevelForCertificate(ctx, cert)` (`pkg/xkms`) computes the
  login certificate's SPKI SHA-256 thumbprint with `qrdbsdk.ComputeSPKIThumbprint`
  — the one cert-binding algorithm this stack already uses for admin cert
  binding and the PIV login user lookup itself, not a second one invented
  for this — and scans the enrolled PIV slots of every backend with a
  registered PIV store for a certificate sharing that thumbprint. A match
  resolves the level through that backend's `PIVAttestLevelReporter`; no
  match reports `found=false` with no error (the certificate may simply not
  correspond to any PIV enrollment, which is the common case); a backend
  whose store cannot be listed reports the typed `ErrPIVAttestLevelLookupFailed`
  rather than being silently read as no match. `pkg/server` wires this at
  REST composition via a new `xkms.GetPIVManager()` accessor, guarded so a
  build with no PIV manager initialized leaves `RecordedLevel` nil and falls
  back to the pre-existing chain-only behavior exactly as before.

  Coverage: `types.AttestLevel` round trip, `ParseAttestLevel`'s typed error
  (`types.ErrUnknownAttestLevel`), and JSON/YAML round trip
  (`pkg/types/attest_level_test.go`); both `PIVAttestLevelReporter`
  implementations and `pivAttestLevel`'s capability/error fallback, plus
  enrollment-time stamping on both `GeneratePIVKey` and `ImportPIVKey`
  (`pkg/xkms/piv_attest_level_test.go`); `AttestLevelForCertificate` matching
  a hardware-enrolled key, a software-enrolled key, no match, a nil
  certificate, and a backend listing failure
  (`pkg/xkms/piv_attest_level_for_certificate_test.go`); the pkcs8 `ListKeys`
  override (`pkg/keyprovider/pkcs8/attest_level_test.go`); and the REST
  precedence table plus the constants' pinned string values
  (`pkg/api/rest/handlers_auth_recorded_level_test.go`).
