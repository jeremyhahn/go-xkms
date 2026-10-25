# Attestation Verifier — Engineering Contract

> **Status: NORMATIVE** · Feature: `attestation-verifier` · Module: `go-xkms` · Last verified: 2026-10-24

## Exported surface

`pkg/attestation` (root package, not its `android`/`peer`/`truststore`
subpackages — see [`architecture.md`](architecture.md)):

| Symbol | Kind | Where |
|---|---|---|
| `Verifier` | type | `verifier.go:49` |
| `NewVerifier(trustedRoots []*x509.Certificate, opts ...VerifierOption) *Verifier` | func | `verifier.go:69` |
| `(*Verifier).Verify(stmt, opts) (*Result, error)` | method | `verifier.go:91` |
| `(*Verifier).TrustAnchorCount() int` | method | `verifier.go:162` |
| `(*Verifier).VerifyChain(stmt, opts) error` | method | `verifier.go:195` |
| `(*Verifier).VerifyChainAnchored(stmt, opts) error` | method | `verifier.go:233` |
| `(*Verifier).VerifySignature(stmt, opts) error` | method | `verifier.go:335` |
| `AttestationStatement` | type | `types.go:47` |
| `(*AttestationStatement).String() string` | method | `types.go:228` |
| `(*AttestationStatement).Validate() error` | method | `types.go:241` |
| `(*AttestationStatement).Hash() ([]byte, error)` | method | `verifier.go:490` |
| `Attestation` | interface (`Verify`/`VerifyChain`/`VerifySignature`) | `types.go:100` |
| `VerifyOptions` | type | `types.go:148` |
| `(*VerifyOptions).Validate() error` | method | `types.go:270` |
| `DefaultVerifyOptions() *VerifyOptions` | func | `types.go:287` |
| `InsecureVerifyOptions() *VerifyOptions` | func | `types.go:296` |
| `Result` | type | `types.go:187` |
| `(*Result).String() string` | method | `types.go:218` |
| `Evidence` | type | `invariants.go:69` |
| `VerifyInvariants(ev *Evidence) error` | func | `invariants.go:177` |
| `KnownFormat(format string) bool` | func | `invariants.go:162` |
| `Normalize(format string) string` | func | `invariants.go:157` |
| `FormatAndroidKey`, `FormatYubiKeyPIV`, `FormatTPM2` | consts | `invariants.go:58-60` |

Plus configuration and wiring that connect the package to CSR issuance,
covered by this folder because no other converted folder documents them by
name:

| Symbol | Kind | Where |
|---|---|---|
| `AttestationConfig` | type (`pkg/config`) | `attestation.go:47` |
| `(*AttestationConfig).Verifiers() (map[string]*attestation.Verifier, error)` | method | `attestation.go:58` |
| `(*XKMSService).SetAttestationVerifiers(map[string]*attestation.Verifier) error` | method (`pkg/xkms`) | `servicer_ca.go:219` |
| `(*XKMSService).AttestationFormats() []string` | method | `servicer_ca.go:243` |
| `(*XKMSService).AllowUnboundAttestationFormats(allow bool)` | method | `servicer_ca_attestpolicy.go:56` |

## Invariants

- **`VerifyChainAnchored` fails closed with zero anchors.** It returns
  `ErrNoTrustAnchors` rather than degrading to `VerifyChain`'s structural-only
  path (`verifier.go:233-241`). `SetAttestationVerifiers` and
  `AttestationConfig.Verifiers` both additionally refuse to construct or
  register an anchorless verifier in the first place
  (`servicer_ca.go:229-231`, `attestation.go:77-79`) — the same guarantee
  enforced twice, at config load and at wiring.
- **Chain anchoring alone is not provenance.** `VerifyChain` with no anchors
  configured validates structure only; it is `VerifyChainAnchored` a caller
  must use to gate a security decision on hardware provenance
  (`verifier.go:190-194`).
- **Binding and freshness invariants are not configurable**, except one
  narrow, logged opt-in. `VerifyInvariants` enforces `ErrKeyNotBound` and
  `ErrStaleEvidence` unconditionally; only `ErrBindingUnavailable` (the
  evidence *cannot express* the binding this format needs) can be waived, via
  `AllowUnboundAttestationFormats(true)` — off by default, and every waived
  issuance is logged at `WARN` with the exact consequence stated
  (`servicer_ca_attestpolicy.go:48-60,107-118`).
- **Anchors are per format.** A verifier is registered per attestation
  format string (case-insensitive, `normalizeAttestationFormat`); a Yubico
  anchor can never validate a TPM chain (`servicer_ca.go:303`).
- **Binding is per-format, and the mechanism is fixed, not policy.**
  `formatProfile.bindLeafSPKI` (Android, PIV) compares
  `RawSubjectPublicKeyInfo` directly; `bindTPMCertify` (TPM2) compares
  through `tpm2.VerifyCertifyRaw` because a TPM Name is a digest over the
  public *area*, not derivable from a public key
  (`invariants.go:108-145,242-259`).
- **Freshness is per-format.** Only a format with a `challenge` function is
  checked for one; supplying `ExpectedChallenge` for a format with none is
  itself an error (`ErrStaleEvidence`), not silently ignored
  (`invariants.go:195-224`). PIV deliberately has no challenge mechanism —
  its attestation certificate is minted once and is static
  (`invariants.go:131-140`).
- **`VerifyInvariants` must run after anchoring, never before.** Its own doc
  comment says so: everything it reads is only meaningful once the evidence
  is known to descend from a configured root (`invariants.go:167-176`).
- **The CSR-attestation gate never calls `Verify`/`VerifySignature`.** See
  [`architecture.md`](architecture.md) §"Two checks belong to different call
  paths" — `verifyCSRAttestation` builds a statement with only `Format` and
  `CertificateChain` and calls `VerifyChainAnchored`, not `Verify`. Proof of
  possession for that path comes from the CSR's own self-signature plus (for
  TPM2) the `TPM2_Certify` signature checked inside binding — not from
  `AttestationStatement.Signature`.
- **`VerifyOptions.FreshnessWindow` defaults on validate, not on
  construction.** `(*VerifyOptions).Validate()` sets it to 300 only when
  `CheckFreshness` is true and the window is still zero
  (`types.go:270-284`); a caller that skips `Validate()` and reads the field
  directly sees zero.

## Errors

All are typed sentinels (`errors.New`), matched with `errors.Is`; none are
constructed with `fmt.Errorf`.

Chain/signature (`errors.go`): `ErrSignatureVerificationFailed`,
`ErrChainVerificationFailed`, `ErrNonceMismatch`, `ErrEmptyCertificateChain`,
`ErrCertificateExpired`, `ErrCertificateNotYetValid`, `ErrEmptySignature`,
`ErrNilAttestingKey`, `ErrNilAttestedKey`, `ErrUnsupportedKeyType`,
`ErrUnsupportedSignatureAlgorithm`, `ErrInvalidSelfSignedCert`,
`ErrInvalidChainSignature`, `ErrMissingTimestamp`, `ErrInvalidTimestamp`,
`ErrFutureTimestamp`, `ErrAttestationExpired`, `ErrMissingPCRs`,
`ErrPCRMissing`, `ErrPCRMismatch`, `ErrNilVerifyOptions`,
`ErrNegativeFreshnessWindow`, `ErrMarshalAttestedKey`, `ErrNilStatement`,
`ErrNoTrustAnchors`, `ErrChainNotAnchored`.

Invariants (`invariants.go:33-53`): `ErrKeyNotBound` (the CSR key is not the
attested key — "the most important check in the whole path"),
`ErrStaleEvidence` (challenge mismatch, or a challenge supplied for a format
with none), `ErrUnknownFormat` (no profile for the format), `ErrBindingUnavailable`
(the format's binding mechanism is understood but the evidence to check it is
missing — the one waivable case).

Configuration (`pkg/config/attestation.go:27-38`): `ErrAttestationFormatEmpty`,
`ErrAttestationTrustStoreMissing`, `ErrAttestationTrustStoreEmpty`.

CSR-gate wrapping (`pkg/xkms`): `servicer_ca.go:38-64` declares
`ErrAttestationRequired`, `ErrAttestationVerificationFailed`,
`ErrAttestationNotConfigured`, `ErrAttestationFormatNotConfigured`,
`ErrAttestationVerifierInvalid`; `servicer_ca_attestpolicy.go:28-45`
translates the invariant errors above into `ca:`-prefixed sentinels
`ErrAttestationKeyNotBound`, `ErrAttestationStale`,
`ErrAttestationUnbindableFormat`, each wrapping the `pkg/attestation` cause
via `ErrOperationWrap` so `errors.Is` reaches both.

CSR-gate wrapping (`pkg/ca`, TCG-CSR-IDEVID path only):
`ErrTCGCSRVerificationFailed` (`pkg/ca/errors.go:289`) wraps both the
envelope-signature failure and a `VerifyInvariants` failure — the two are
distinguished by the wrapped `errs.Detail`'s text, not by a second sentinel
(`pkg/ca/tcg.go:363-365,385-390`).

## Configuration

Top-level `attestation:` key on the xkmsd `Config` (`pkg/config/config.go:65`,
`yaml:"attestation,omitempty"`). `nil` means attestation-gated CSR signing
fails closed for every format (`config.go:61-63`).

```yaml
attestation:
  formats:
    tpm2:
      external_root_paths:
        - /etc/xkms/tpm-manufacturer-root.pem
    yubikey-piv:
      external_root_paths:
        - /etc/xkms/yubico-piv-root.pem
    android-key-attestation:
      embedded_roots:
        - google-hardware-attestation   # pkg/attestation/truststore.GoogleHardwareAttestation
```

`Formats` keys are attestation format identifiers as they appear on the wire
(`transport.SignCSRRequest.AttestationFormat`), matched case-insensitively.
Each value is a `truststore.Config` (`pkg/attestation/truststore/truststore.go:58`):
`embedded_roots` (currently only `google-hardware-attestation` is a known
value) and/or `external_root_paths` (PEM files on disk). A declared format
that resolves to zero root certificates is `ErrAttestationTrustStoreEmpty`,
not an anchorless verifier.

There is no config surface for `AllowUnboundAttestationFormats` — it is an
embedder-only Go API call, off by default, with no YAML key or CLI flag. That
is deliberate: the knob widens a security gate, and the codebase's config
surface never exposes one that does that silently.

## Test strategy

- **Unit** — `pkg/attestation/verifier_test.go` (signature/chain paths),
  `verifier_anchor_test.go` (`VerifyChainAnchored` fail-closed and
  anchored-accept cases), `verifier_extended_test.go` (extended coverage of
  every verification branch), `invariants_test.go` (binding and freshness
  per format), `types_test.go` (`Validate`, `DefaultVerifyOptions`,
  `InsecureVerifyOptions`).
- **Configuration** — `pkg/config/attestation_test.go`
  (`AttestationConfig.Verifiers`, including the anchorless-format rejection).
- **CSR-gate integration** — `pkg/xkms/servicer_ca_test.go` and
  `servicer_ca_androidkey_test.go` exercise `verifyCSRAttestation` and
  `enforceAttestationInvariants` end to end, including the
  `AllowUnboundAttestationFormats` waiver path and its `WARN` log.
- **Server wiring** — `pkg/server/server_test.go` covers
  `Config.Attestation` → `SetAttestationVerifiers` startup wiring, including
  the fail-closed error path when `Verifiers()` returns an error.
- **TCG-CSR-IDEVID path** — no `pkg/ca` test references
  `attestation.VerifyInvariants`/`Evidence` by name; the call at
  `tcg.go:379` is exercised indirectly through `pkg/ca`'s own
  `SignTCGCSR`/`tcg_conformance_test.go` suite, not by a test owned by this
  feature. A binding failure specific to that path (a forged
  `TPM2_Certify` structure, for instance) is not separately regression-tested
  here — verify against `pkg/ca`'s suite, not this folder's, before relying
  on that case.
- Run a single package: `go test ./pkg/attestation/...`.

## Repository signing keys

`pkg/attestation/appraisal` (`signing_keys.go`, #1697):

| Symbol | Kind | Where |
|---|---|---|
| `ReleaseSigningKeyID` | const `"release-signing"` | `signing_keys.go:31` |
| `SigningKeyBinding`, `SigningKeyResolution` | types | `signing_keys.go:44`, `:89` |
| `ValidateRepository` | func | `signing_keys.go:101` |
| `Appraiser.SetSigningKeyBinding` / `GetSigningKeyBinding` / `ListSigningKeyBindings` / `DeleteSigningKeyBinding` / `ResolveSigningKey` | methods | `signing_keys.go:125`–`:178` |
| `SigningKeySource`, `WithSigningKeySource` | interface, option | `signing_keys.go:195`, `:202` |
| `Appraiser.RepositorySigningKey`, `Appraiser.TenantSigningKeys` | methods | `signing_keys.go:208`, `:226` |
| `XKMSService.SigningPublicKey` | method (a `SigningKeySource`) | `pkg/xkms/servicer_signing_keys.go:136` |
| `image.SigningKeyResolver`, `VerifierConfig.SigningKeys` | interface, field | `pkg/image/verifier.go:68`, `:62` |

`sdk/go` re-exports these under an `Attestation` prefix
(`sdk/go/attestation_appraisal.go:46`–`:130`, `:182`–`:204`), plus
`ImageSigningKeyResolver` and `ErrImageSigningKeyMismatch`
(`sdk/go/image.go:101`, `:181`).

Invariants:

- An unbound repository resolves to `ReleaseSigningKeyID` with
  `Default: true`; resolution never returns not-found.
- A repository's CoRIM verifies under the repository's key alone. The
  tenant's `reference-signer` endorsements do not apply to it
  (`verifyReferenceValues`, `signing_keys.go:263`).
- The Appraiser sees public keys only, through its `SigningKeySource`.
  Verifying a repository's signature without one is a `*ConfigError`
  (`signing_keys.go:208`).
- Every `XKMSService` signing-key verb authorizes
  `attestation_signing_keys:{bind,get,list}` itself
  (`authorizeSigningKeys`, `pkg/xkms/servicer_signing_keys.go:64`), as well
  as being gated on the wire. The permissions are in `pkg/auth/permissions.go:155`
  and `:268`, and in the module scopes at `pkg/apimodule/module_scopes.go:147`–`:155`.

Errors (`pkg/attestation/appraisal/errors.go:79`–`:121`):

- `ErrInvalidRepository` / `*RepositoryError`;
- `ErrInvalidSigningKey` / `*SigningKeyError`, for a bad key ID or backend
  name;
- `ErrSigningKeyRefused` / `*SignerRefusedError`, for a CoRIM signed by
  another key;
- in `pkg/xkms`, `ErrSigningKeyForbidden` / `*SigningKeyPermissionError`
  (`servicer_signing_keys.go:40`, `:45`);
- in `pkg/image`, `ErrSigningKeyMismatch` (`errors.go:182`).

One table, `apierrors.SigningKeySentinelClasses`
(`pkg/api/apierrors/tables.go:330`), classifies these errors for gRPC, MCP
and REST.

Tests:

- `pkg/attestation/appraisal/signing_keys_test.go` and
  `signing_keys_verify_test.go`: binding lifecycle, validation, resolution,
  and CoRIM refusal under another key;
- `pkg/image/verifier_signing_key_test.go`: image key mismatch;
- `pkg/xkms/servicer_signing_keys_test.go`: permission refusals and
  `ErrNotConfigured`;
- `pkg/api/{rest,mcp}/handlers_signing_key_test.go` and each transport's
  `transport_signing_key_test.go`: the wire round trip and error mapping;
- `sdk/ts/src/signingKey.test.ts`: the TypeScript wire contract.

## Host and container evidence

`HostEvidence.AKIntermediates` and `ContainerEvidence.AKIntermediates`
(`pkg/attestation/appraisal/host.go:39`, `container.go:50`) carry the CA
certificates between the AK certificate and the endorsed `ak-root`, issuer
first, without the leaf. `akChainPEM` (`host.go:199`) forwards the leaf, then
each intermediate, into `AppraiseQuoteRequest.AKCertificatePEM`, so an AK
issued by an intermediate chains to a root-only endorsement. A nil entry is
`ErrInvalidAKIntermediate` / `*AKIntermediateError` (`errors.go:91`, `:96`),
re-exported by `sdk/go` as `ErrAttestationInvalidAKIntermediate` /
`AttestationAKIntermediateError`. Tests:
`TestAppraiser_AppraiseHostAKIntermediates` and
`TestAppraiser_AppraiseContainerAKIntermediates`.

## Consumers

- `pkg/config.AttestationConfig.Verifiers()` — config → `map[string]*Verifier`.
- `pkg/xkms.XKMSService.SetAttestationVerifiers`/`verifyCSRAttestation`/
  `enforceAttestationInvariants` — the CSR-issuance gate for the generic
  `SignCSR` route; see [`../certificate-authority/`](../certificate-authority/)
  for the CA side of `SignCSR` and its route.
- `pkg/ca` (`tcg.go:379-390`) — the TCG-CSR-IDEVID enrollment path
  (`SignTCGCSR`) calls `attestation.VerifyInvariants` directly, for
  `FormatTPM2` only, with no `ExpectedChallenge` (that ceremony's freshness
  comes from credential activation and the quote, not a CA-issued
  challenge). It does **not** go through `AttestationConfig`/
  `SetAttestationVerifiers` — EK trust for this path is anchored separately,
  through `MultiIdentityCAConfig.TCGConfig.TrustAnchors`
  ([`../certificate-authority/engineering.md`](../certificate-authority/engineering.md)).
  Failures surface as `ca.ErrTCGCSRVerificationFailed`
  (`pkg/ca/errors.go:289`), wrapping the same `pkg/attestation` invariant
  errors this folder documents, not the `pkg/xkms` wrapper sentinels above.
- `pkg/server.Server` — startup wiring for the `pkg/xkms` path only, fatal on
  a broken anchor configuration (`server.go:916-923`).
- `examples/attestation/basic-attestation` — a narrated walk through
  `DefaultVerifyOptions`/`InsecureVerifyOptions` and the full `Verify` call
  shape; not itself a production consumer (see
  [`architecture.md`](architecture.md)).
