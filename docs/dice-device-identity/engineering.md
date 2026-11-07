# DICE Device Identity — Engineering

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-10-17

## Packages

| Path | Holds |
|------|-------|
| `pkg/attestation/dice/extension.go` | OIDs, `TcbInfo`, `FWID`, `OperationalFlags`, `Ueid`, marshal/parse, certificate helpers |
| `pkg/attestation/dice/uccs.go` | `ClaimsSet`, the `tcg-dice-UCCS-evidence` codec and the CBOR claims-set reader |
| `pkg/attestation/dice/verify.go` | `VerifyOptions`, `Evidence`, `Verify` |
| `pkg/attestation/dice/roottype.go` | `RootType`, its vendorInfo OIDs, `RootTypeVendorInfo`, `RootTypeFromPaths` |
| `pkg/attestation/dice/errors.go` | every sentinel this package returns |
| `pkg/ca/profile_dice.go` | the `dice-idevid` certificate profile |
| `pkg/acme/challenges/device-attest-01/possession.go` | the possession request profile: builder, parser and the finalize checks |

## Exported surface

### Structures

```go
type TcbInfo struct {
    Vendor, Model, Version string
    SVN, Layer, Index      *int
    FWIDs                  []FWID
    Flags                  *OperationalFlags
    VendorInfo, Type       []byte
}

type FWID struct {
    HashAlg asn1.ObjectIdentifier
    Digest  []byte
}

type OperationalFlags struct {
    NotConfigured, NotSecure, Recovery, Debug bool
}

type Ueid struct{ Value []byte }

type ClaimsSet struct {
    Nonce []byte           // eat_nonce, CWT claim key 10
    Other map[int64][]byte // every other claim, raw CBOR, by claim key
}
```

`Other` is why the claims-set parser can be lenient about unknown claims
without being dishonest: a claim this profile does not model is kept as the
CBOR item it arrived as rather than discarded, so a relying party can read
everything the device said.

**The pointers are load-bearing.** `SVN`, `Layer`, `Index` and `Flags` are
pointers because each has a meaningful zero, and "the device said zero" is not
the same evidence as "the device said nothing". The string fields use `""` for
absent, which is unambiguous — an empty vendor name is not a claim.

### Functions

| Function | Contract |
|----------|----------|
| `MarshalTcbInfo(*TcbInfo) ([]byte, error)` | Encodes the DER extension value. Refuses nil, negative svn/layer/index, and an FWID with an empty OID or digest. |
| `ParseTcbInfo([]byte) (*TcbInfo, error)` | Decodes it. Refuses unknown field tags, repeated or out-of-order tags, non-context-specific fields, invalid UTF-8, negative integers, empty `fwids`, a fifth flag bit, and trailing data. |
| `MarshalUeid([]byte) ([]byte, error)` | Refuses an empty identifier. |
| `ParseUeid([]byte) (*Ueid, error)` | Refuses an empty identifier and trailing data. |
| `CreateTcbInfoExtension(*TcbInfo) (pkix.Extension, error)` | **Critical**, per §6.1.1. |
| `CreateUeidExtension([]byte) (pkix.Extension, error)` | **Not critical** — a critical UEID no general client recognises would make the certificate unusable for ordinary TLS. |
| `TcbInfoFromCertificate` / `UeidFromCertificate` | `ErrTcbInfoNotFound` / `ErrUeidNotFound` when absent. `UeidFromCertificate` reads only the `tcg-dice-Ueid` extension. |
| `DeviceUeid(*x509.Certificate) ([]byte, error)` | The device identifier from **either** placement: the `tcg-dice-Ueid` extension, or the `ueid` claim (`ClaimUeid`, 256) of `tcg-dice-UCCS-evidence` (`extension.go:690`). Both present and different: `ErrUeidConflict`, wrapped in `errs.Detail` with both values in hex — never a silent choice. Both present and equal, or one present: that value. Neither: `ErrUeidNotFound`. A malformed extension or claim is returned as its own error. This is what `Verify` reads, and what a caller recording a device's identity should read: a device that cannot afford the extension, such as a constrained device that mints a fixed-template alias certificate, carries only the claim. |
| `(*ClaimsSet).Ueid() ([]byte, error)` | The `ueid` claim on its own (`uccs.go:201`), RFC 9711 type byte included. `ErrUeidNotFound` when absent, `ErrMalformedUeid` when not a CBOR byte string, `ErrEmptyUeid` when empty. |
| `HasExtensions(*x509.Certificate) bool` | Whether a certificate is device-resident. |
| `Challenge(*x509.Certificate) ([]byte, error)` | The nonce from the `eat_nonce` claim of `tcg-dice-UCCS-evidence`. Always an error when it cannot be produced, and **never** falls back to `vendorInfo`: `ErrUccsEvidenceNotFound` for an absent extension, `ErrNonceClaimMissing` for a claims set without the claim. |
| `MarshalUccsEvidence(*ClaimsSet) ([]byte, error)` | Encodes the DER extension value. The CBOR inside is RFC 8949 core deterministic, so one claims set has one encoding — §6.1.4 requires the issuer to make this field contribute to the CDI. |
| `ParseUccsEvidence([]byte) (*ClaimsSet, error)` | Decodes it. Refuses a sequence with other than one member, a non-primitive or empty `uccs`, and trailing data. |
| `MarshalClaimsSet` / `ParseClaimsSet` | The CBOR layer on its own. Parsing refuses a non-map, a tagged map, an indefinite-length item, a duplicate claim key, a non-integer claim key, an empty claims set, trailing bytes, a missing nonce, a nonce that is not a single byte string, and a nonce shorter than eight bytes. |
| `CreateUccsEvidenceExtension(*ClaimsSet) (pkix.Extension, error)` | **Critical**, for the reason `CreateTcbInfoExtension` is: the claims are what make the certificate an attestation. §6.1.4 states no criticality, so this is a choice. |
| `UccsFromCertificate(*x509.Certificate)` | `ErrUccsEvidenceNotFound` when absent. |
| `Verify([]*x509.Certificate, *VerifyOptions) (*Evidence, error)` | Chain leaf-first. `Evidence.RootType` is `RootTypeFromPaths` of the paths anchoring verified (`verify.go:229`), so it is `RootTypeUnreported` without `TrustedRoots` (CA m452). A software root on any certificate of those paths is refused as `ErrOperationalStateNotPermitted` unless `PermittedFlags.NotSecure` (`verify.go:512`). |
| `RootTypeVendorInfo(RootType) ([]byte, error)` | The DiceTcbInfo `vendorInfo` naming a root: the DER OID `OIDRootOfTrustHardware` (1.3.6.1.4.1.29377.101.24.1) or `OIDRootOfTrustSoftware` (.24.2), under `OIDRootOfTrust` (`roottype.go:70-104`). `ErrUnknownRootType` for `RootTypeUnreported` or an undefined value. |
| `RootTypeFromPaths(paths [][]*x509.Certificate) (RootType, error)` | The root type the DiceTcbInfo on the authenticated certificates declares (`roottype.go:157`). `paths` are what `x509.Certificate.Verify` returned for the leaf against a configured trusted root. No other certificate is read, and no paths (an unanchored chain) is `RootTypeUnreported` whatever the certificates declare (CA m452). A layer declares software when its §6.1.1 `notSecure` flag is set or its `vendorInfo` is `OIDRootOfTrustSoftware`, and hardware when its `vendorInfo` is `OIDRootOfTrustHardware` with `notSecure` clear (`declaredRootType`, `roottype.go:126`); any other `vendorInfo` is another vendor's data and declares nothing. A path is software if any layer declares software, else hardware if any layer declares hardware, else unreported (`pathRootType`, `roottype.go:177`); across paths the weakest wins. An unreadable DiceTcbInfo on a path is returned as its own error. |
| `VerifyChain(chain []*x509.Certificate, roots *x509.CertPool, now time.Time) ([][]*x509.Certificate, error)` | Anchors the leaf-first chain to `roots` with every DICE evidence extension decoded, then marked handled (invariant 3a), and returns the verified paths (`verify.go:363`). `attestation.Verifier` anchors a `dice` statement through it (`pkg/attestation/verifier.go:317`), because `crypto/x509` alone refuses the leaf's critical DiceTcbInfo. `ErrChainVerificationFailed` or `ErrCriticalEvidenceUnreadable`. |

### The possession request

In `pkg/acme/challenges/device-attest-01`; the template and why it looks the
way it does are in [architecture.md](architecture.md#possession-at-finalize-the-device-signs-a-fixed-template).

| Symbol | Contract |
|--------|----------|
| `PossessionNonceSize` | 32: the request carries `DICENonce(keyAuthorization)` (`possession.go:81`). |
| `PossessionIdentifierType` | `permanent-identifier` (`possession.go:85`). |
| `OIDExtensionRequest` | PKCS#9 extensionRequest, 1.2.840.113549.1.9.14 (`possession.go:90`). |
| `PossessionRequest{Claims, DeviceID, ApplicationEvidence, PublicKey}` | What a request states: the claims set its UCCS evidence carries, whose `Nonce` is `b`, that set's ueid, and the 32 bytes of application evidence its measurements (273) carry (`possession.go:132`). `Identifier()` is `{permanent-identifier, hex(DeviceID)}` (`:151`). |
| `BuildPossessionCRI(pub, claims, nonce) ([]byte, error)` | The DER CertificationRequestInfo the device signs (`possession.go:192`). `claims` is the alias certificate's claims set; `claims.Nonce` is replaced by `nonce`, and `Other` is carried verbatim. Refuses, with `ErrPossessionCSRMalformed`, a key that is not P-256, a nonce that is not 32 bytes, and a claims set that is not exactly ueid (256) and measurements (273) beside the nonce (`possessionSet`, `:243-263`); a 273 that is not the ruled shape is also `ErrPossessionMeasurementsShape` (`applicationEvidence`, `:362`). |
| `AssemblePossessionCSR(cri, signature) ([]byte, error)` | Wraps a device's DER ECDSA signature with ecdsa-with-SHA256 (`possession.go:268`). Refuses a request info that is not one DER value (`ErrPossessionCSRMalformed`) and a signature that is not one DER ECDSA-Sig-Value (`ErrPossessionSignatureInvalid`). It does not verify the signature; finalize does. |
| `SignPossessionCSR(signer, claims, nonce) ([]byte, error)` | Builds, signs and assembles in one call for a key behind a `crypto.Signer` (`possession.go:292`). A signer that fails is `ErrPossessionSigningFailed`. |
| `ParsePossessionCSR(*x509.CertificateRequest) (*PossessionRequest, error)` | Reverses the template exactly (`possession.go:663`): reads the whole claims set out of the UCCS evidence, rebuilds the CertificationRequestInfo from it and refuses the request with `ErrPossessionCSRMalformed` unless the bytes are identical, so no extra attribute, extension, claim, subject, other identifier or criticality survives. Holds 273 to the ruled shape through the same parser as `BuildPossessionCRI` and returns its 32 bytes as `ApplicationEvidence`. Does not check the signature. |
| `(*VerifiedAttestation).VerifyPossessionCSR(csr, orderIdentifiers) error` | The four finalize checks, in order: signature (`:386`), key (`:389`), nonce (`:392`), identifiers (`:395`). Refuses a non-`dice` record with `ErrKeyBindingUnavailable` and a nil record with `ErrNoVerifiedAttestation` (`possession.go:370`). |

The measurements claim (273) has one ruled shape (`possession.go:265-288`):
one `[258, bstr .cbor CoSWID]` entry whose evidence CoSWID holds one file
`"app"` with the hash-entry `[1 (sha-256), 32 bytes]`. Those 32 bytes are the
application evidence, opaque to go-xkms. The CoSWID's tag-id (text or a
16-byte UUID), tag-version (integer), software-name (text) and entity (one
entity-entry, text entity-name, a role or role list holding tag-creator) are the
producer's (RFC 9393 §2.3, CA m463): `producerFields` (`:443`) and `tagCreator`
(`:479`) check their presence and CBOR type, never their value. Any other
field (`onlyFields`, used by `evidenceFile` `:531`) and any encoding other than
RFC 8949 core deterministic (`deterministic`, `:399`) is refused. Nothing
matches the 32 bytes against a registered reference yet.

The ACME client mints the request for a `dice` device:
`AttestedKey.Format` selects it (`pkg/acme/client/tpm.go`), and
`attestedKeyCSR` (`pkg/acme/client/enrollment.go:1011`) calls
`SignPossessionCSR` with the claims set of the alias certificate in the key's
attestation statement (`aliasClaims`, `:1024`) and
`DICENonce(keyAuthorization)`. Every other format sends an ordinary request.

### VerifyOptions

| Field | Default | Meaning |
|-------|---------|---------|
| `TrustedRoots` | nil | Nil skips anchoring. Only correct when the caller anchored by another route: an unanchored chain is self-consistent whoever generated it. device-attest-01's raw-key path is that route: it verifies the leaf's signature under the provisioned DeviceID key first. Without it `Evidence.RootType` is `RootTypeUnreported`: an unanchored chain carries no DiceTcbInfo a verifier may believe (CA m452). |
| `ExpectedNonce` | — | **Required.** `ErrNonceRequired` without it. |
| `ExpectedUeid` | nil | "This is the device I enrolled" rather than "a device from this manufacturer". |
| `RequireUeid` | false | Demand a device identifier without matching it — the `tcg-dice-Ueid` extension **or** UCCS claim 256, as `DeviceUeid` reads them (`verify.go:47-50`, `verifyUeid` at `:473`). Without `RequireUeid` or `ExpectedUeid`, a leaf with neither yields `Evidence.Ueid == nil`; a malformed or conflicting identifier is an error either way. |
| `RequireMeasurement` | false | Demand at least one FWID. |
| `RequireTcbInfo` | false | Demand the extension. §6.1.4 permits a UCCS-only certificate, so this is not the default; set it where policy reads the operational flags, which live in `DiceTcbInfo` and are therefore **absent**, not clear, without it. |
| `RequireDeviceSignedLeaf` | false | State that the leaf's **issuer** is device-resident, so the leaf must carry ECDSA-SHA256. Needed because the issuer is usually not in the chain — a device has nowhere to keep its DeviceID certificate — and the signature algorithm is otherwise checked only on certificates a device-resident key signed. A device backend whose element signs the leaf sets it (`pkg/backend/avr/attestation.go:207`). |
| `PermittedFlags` | zero | The zero value permits **none**. Each of the four states says the TCB is not in its trustworthy operating state. |
| `CurrentTime` | zero | Verifier's clock, certificate expiry only. |

## Invariants

1. **Freshness is the nonce**, read from the `eat_nonce` claim of
   `tcg-dice-UCCS-evidence` and nowhere else. No code path compares a
   device-supplied value against `time.Now()`, and none falls back to
   `DiceTcbInfo.vendorInfo`.
2. **Device keys are ECDSA P-256.** Leaf, plus any certificate carrying a DICE
   extension. Not the issuing authority.
3. **Signature algorithm is checked on the issued certificate**, not the
   issuing one — and on the leaf itself under `RequireDeviceSignedLeaf`, for a
   profile whose leaf issuer is the device but is not in the chain.
3a. **Nothing is cleared unread.** Anchoring removes the DICE OIDs from every
   certificate's `UnhandledCriticalExtensions` so `crypto/x509` does not refuse
   a chain for carrying the critical `TcbInfo` §6.1.1 asks for. Every OID
   cleared is decoded first, on **every** certificate in the chain and not only
   on the leaf: `ErrCriticalEvidenceUnreadable` otherwise. Clearing an entry is
   a claim to have handled the extension, and an intermediate's evidence is
   read by nothing else.
4. **Absent and zero are distinct** for svn, layer, index and flags, on the
   wire and in the Go type.
5. **Unknown is refused in `DiceTcbInfo`** — unknown field tags, unknown
   flag bits — and **kept in the claims set**, where the CWT registry is open
   by design. architecture.md says why the two differ.
6. **Re-encoding is canonical and lossless.** Parse-then-marshal reproduces the
   input bytes; the operational flags BIT STRING is DER-minimal.
7. **The CA never strips evidence.** `notSecure` is carried onto the
   certificate.
8. **The root type is one value, derived once.** `dice.RootType` is the only
   definition; `attestation.Result`, device-attest-01's `VerifiedAttestation`
   and its persisted record, the AVR backend's `Attestation` and `sdk/go`
   (`DICERootType`) carry that type, and every reader derives it through
   `RootTypeFromPaths`, only from the certificates on paths verified to a
   trusted root (CA m452). A software root on any layer of those paths makes
   it software. Its numbers (0 unreported, 1 hardware, 2 software) are
   persisted and do not change.

## Errors

All typed sentinels in `pkg/attestation/dice/errors.go`, wrapped with
`errs.Detail` / `errs.Joined` for operator-facing context. Parsing:
`ErrNilCertificate`, `ErrNilTcbInfo`, `ErrTcbInfoNotFound`, `ErrUeidNotFound`,
`ErrMalformedTcbInfo`, `ErrMalformedUeid`, `ErrMalformedFWID`,
`ErrUnknownTcbInfoField`, `ErrTcbInfoFieldOrder`, `ErrNegativeTcbInfoValue`,
`ErrUnknownOperationalFlag`, `ErrEmptyUeid`, `ErrUeidConflict` (the extension
and claim 256 disagree, `errors.go:41`). UCCS evidence: `ErrNilClaimsSet`,
`ErrUccsEvidenceNotFound`, `ErrMalformedUccsEvidence`, `ErrMalformedClaimsSet`,
`ErrDuplicateClaim`, `ErrNonceClaimMissing`, `ErrMalformedNonceClaim`,
`ErrNonceClaimLength`. Verification:
`ErrNilVerifyOptions`, `ErrEmptyChain`, `ErrChainVerificationFailed`,
`ErrUnsupportedKeyType`, `ErrUnsupportedSignatureAlgorithm`,
`ErrNonceMismatch`, `ErrNonceRequired`, `ErrUeidMismatch`,
`ErrOperationalStateNotPermitted`, `ErrNoMeasurement`,
`ErrCriticalEvidenceUnreadable`. Root type: `ErrUnknownRootType`.

Every one of them is re-exported from `sdk/go/attestation_dice.go` as
`ErrDICE<Name>`, aliased to the canonical value rather than copied, so a
consumer that cannot import `pkg/` can still use `errors.Is`. The same file
re-exports `DeviceUeid` as `DICEDeviceUeid`, `ClaimUeid` as
`DICEClaimUeid`, and the root type as `DICERootType`, its constants, OIDs,
`DICERootTypeVendorInfo` and `DICERootTypeFromPaths`.

The possession request's sentinels live beside it in
`pkg/acme/challenges/device-attest-01/possession.go:92-120`:
`ErrPossessionCSRMalformed`, `ErrPossessionSignatureInvalid`,
`ErrPossessionSigningFailed`, `ErrPossessionKeyMismatch`,
`ErrPossessionNonceMismatch`, `ErrPossessionIdentifierMismatch`. The finalize
handler reports each as `badCSR` with the sentinel's text
(`pkg/acme/server/handlers/device_attest.go:228-230`).

`pkg/ca` adds `ErrDICEEvidenceMissing` and `ErrDICEEvidenceInvalid`. The
`dice-idevid` profile refuses a `DiceTcbInfo` with **no `fwids`** — reported as
`ErrDICEEvidenceInvalid` wrapping `dice.ErrNoMeasurement` — because every field
of the structure is optional and `30 00` is a valid empty one: requiring the
extension and requiring the measurement are two checks.

## OID registry

The same identifiers are stated in three places — `pkg/attestation/dice`
(canonical), `pkg/ca/tcg_oids.go` and `pkg/certstore/types.go` — because each
is a flat registry its own package reads. `TestDICEOIDsMatchTheAttestationPackage`
in `pkg/ca` pins the first two together;
`TestDICEOIDsHaveNames` in `pkg/certstore` pins every constant to a name-table
entry, so none can render as bare digits. `IsDICEOID` is the narrow arc
predicate; `IsTCGOID` already answers true for the whole DICE arc.

## Tests

```
make test-dice           # unit tests
make coverage-dice       # 95.0% of statements
make bench-dice          # marshal/parse throughput, DER and CBOR
make test-attestation    # the whole attestation tree
```

`pkg/attestation/dice/extension_vectors_test.go` and
`pkg/attestation/dice/uccs_vectors_test.go` hold the wire vectors as hex
literals, derived by hand from the ASN.1 in the specification and from the CBOR
head encoding rules of RFC 8949 §3, and checked with independent DER and CBOR
readers — **not** produced by the codecs they test. A failure there is a wire
break, not a test to update. Every structure has at
least one negative vector, and the full vector is walked byte-by-byte as a
truncation.

Nothing in the suite touches the host: certificate chains are generated in
memory.

The possession request has its own literal vector, the ADR's 365-byte
CertificationRequestInfo and its SHA-256 (`possession_test.go:48-53`), the wire
contract with the device firmware. `TestPossessionVector`
(`pkg/acme/challenges/device-attest-01/possession_test.go:126`) checks that
`BuildPossessionCRI` writes exactly those bytes for the vector's key, claims
set (ueid `01a1b2c3…90` and a measurement) and `b` = `00..1f`, and that the
parser reads them back. `TestPossessionSigningVector` (`:147`) signs the
template with the RFC 6979 A.2.5 key, deterministically, and pins the signature
and the assembled request (`:61-63`). A device implementation that mints the
template must reproduce the vector; never regenerate it.
`TestPossessionExtensionCriticality` (`:189`) pins the criticality of both
extensions, `TestBuildPossessionCRIRefusesWhatTheTemplateCannotCarry` the
builder's refusals, `TestParsePossessionCSRRefusesAnythingButTheTemplate`
the parser's refusals, and `TestVerifyPossessionCSRSignature`, `...Key`,
`...Nonce` and `...Identifiers` accept and refuse each finalize check. At the
handler, `TestBindDeviceAttestationKey_DICERequiresThePossessionRequest`
(`pkg/acme/server/handlers/device_attest_test.go:184`) refuses an ordinary
request for the attested key.

```
go test -tags "codec_cbor codec_json codec_msgpack tpm_simulator frost" \
    -run Possession ./pkg/acme/challenges/device-attest-01/
```

### End to end against the real firmware

`pkg/acme/client/device_attest_dice_e2e_test.go` enrolls trusted-firmware's
element-tier simulator (`tfwsim.StartElement`: the real firmware compiled for the
host, with a model of the ATECC608A that does real P-256) through
`Client.DeviceAttest`, the real ACME handlers and the production
`deviceattest01.TrustAnchorVerifier`. Its device registry is an in-memory
`DeviceResolver` holding the simulator's UEID and DeviceID public key: the
raw-key path, as a provisioning record would state it. The alias certificate is
signed by that key.

```
make agsim                                 # build the simulators into $TFWSIM_DIR
go test -tags "codec_json" -run TestDeviceAttestDICE ./pkg/acme/client/
```

`make agsim` builds `tfwsim` from the trusted-firmware module at the version `go.mod`
pins (`scripts/build-agsim.sh`), after checking the module hash against
`scripts/agsim.sum` (the root trusted-firmware module is not in `go.mod`, so
`go.sum` does not cover it; bumping the dependency adds a line there); `make test`, `make race` and
`make coverage-full` run it first. A missing binary fails the test and prints the
command; it never skips.

| Case | Outcome |
|---|---|
| order for the device's ueid, evidence over `DICENonce(keyAuthorization)`, possession request signed by the alias key | certificate issued, `permanentIdentifier` = hex ueid |
| order for another ueid | `unauthorized` |
| evidence over another challenge's nonce | `incorrectResponse` (`dice.ErrNonceMismatch`) |
| a provisioning record that names another DeviceID key | `unauthorized` (`ErrAttestedKeyMismatch`) |
| possession request for a key other than the alias key | `badCSR` |

The simulator's firmware has no command that signs the possession template, and
the alias key is the DeviceID key, so the test signs the possession request with
the simulator's published test private key.
The simulator identity is a test identity: its private key is the SHA-256 of a
published string, and no deployment may anchor on it.
