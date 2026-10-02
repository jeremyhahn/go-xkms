# DICE Device Identity — Engineering

> **Status: NORMATIVE** · Feature: `dice-device-identity` · Repo: `go-xkms` · Last verified: 2026-09-23

## Packages

| Path | Holds |
|------|-------|
| `pkg/attestation/dice/extension.go` | OIDs, `TcbInfo`, `FWID`, `OperationalFlags`, `Ueid`, marshal/parse, certificate helpers |
| `pkg/attestation/dice/uccs.go` | `ClaimsSet`, the `tcg-dice-UCCS-evidence` codec and the CBOR claims-set reader |
| `pkg/attestation/dice/verify.go` | `VerifyOptions`, `Evidence`, `Verify` |
| `pkg/attestation/dice/errors.go` | every sentinel this package returns |
| `pkg/ca/profile_dice.go` | the `dice-idevid` certificate profile |

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
| `TcbInfoFromCertificate` / `UeidFromCertificate` | `ErrTcbInfoNotFound` / `ErrUeidNotFound` when absent. |
| `HasExtensions(*x509.Certificate) bool` | Whether a certificate is device-resident. |
| `Challenge(*x509.Certificate) ([]byte, error)` | The nonce from the `eat_nonce` claim of `tcg-dice-UCCS-evidence`. Always an error when it cannot be produced, and **never** falls back to `vendorInfo`: `ErrUccsEvidenceNotFound` for an absent extension, `ErrNonceClaimMissing` for a claims set without the claim. |
| `MarshalUccsEvidence(*ClaimsSet) ([]byte, error)` | Encodes the DER extension value. The CBOR inside is RFC 8949 core deterministic, so one claims set has one encoding — §6.1.4 requires the issuer to make this field contribute to the CDI. |
| `ParseUccsEvidence([]byte) (*ClaimsSet, error)` | Decodes it. Refuses a sequence with other than one member, a non-primitive or empty `uccs`, and trailing data. |
| `MarshalClaimsSet` / `ParseClaimsSet` | The CBOR layer on its own. Parsing refuses a non-map, a tagged map, an indefinite-length item, a duplicate claim key, a non-integer claim key, an empty claims set, trailing bytes, a missing nonce, a nonce that is not a single byte string, and a nonce shorter than eight bytes. |
| `CreateUccsEvidenceExtension(*ClaimsSet) (pkix.Extension, error)` | **Critical**, for the reason `CreateTcbInfoExtension` is: the claims are what make the certificate an attestation. §6.1.4 states no criticality, so this is a choice. |
| `UccsFromCertificate(*x509.Certificate)` | `ErrUccsEvidenceNotFound` when absent. |
| `Verify([]*x509.Certificate, *VerifyOptions) (*Evidence, error)` | Chain leaf-first. |

### VerifyOptions

| Field | Default | Meaning |
|-------|---------|---------|
| `TrustedRoots` | nil | Nil skips anchoring. Only correct when the caller anchored by another route: an unanchored chain is self-consistent whoever generated it. |
| `ExpectedNonce` | — | **Required.** `ErrNonceRequired` without it. |
| `ExpectedUeid` | nil | "This is the device I enrolled" rather than "a device from this manufacturer". |
| `RequireUeid` | false | Demand the extension without matching it. |
| `RequireMeasurement` | false | Demand at least one FWID. |
| `RequireTcbInfo` | false | Demand the extension. §6.1.4 permits a UCCS-only certificate, so this is not the default; set it where policy reads the operational flags, which live in `DiceTcbInfo` and are therefore **absent**, not clear, without it. |
| `RequireDeviceSignedLeaf` | false | State that the leaf's **issuer** is device-resident, so the leaf must carry ECDSA-SHA256. Needed because the issuer is usually not in the chain — a device has nowhere to keep its DeviceID certificate — and the signature algorithm is otherwise checked only on certificates a device-resident key signed. `pkg/backend/avr` sets it. |
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

## Errors

All typed sentinels in `pkg/attestation/dice/errors.go`, wrapped with
`errs.Detail` / `errs.Joined` for operator-facing context. Parsing:
`ErrNilCertificate`, `ErrNilTcbInfo`, `ErrTcbInfoNotFound`, `ErrUeidNotFound`,
`ErrMalformedTcbInfo`, `ErrMalformedUeid`, `ErrMalformedFWID`,
`ErrUnknownTcbInfoField`, `ErrTcbInfoFieldOrder`, `ErrNegativeTcbInfoValue`,
`ErrUnknownOperationalFlag`, `ErrEmptyUeid`. UCCS evidence: `ErrNilClaimsSet`,
`ErrUccsEvidenceNotFound`, `ErrMalformedUccsEvidence`, `ErrMalformedClaimsSet`,
`ErrDuplicateClaim`, `ErrNonceClaimMissing`, `ErrMalformedNonceClaim`,
`ErrNonceClaimLength`. Verification:
`ErrNilVerifyOptions`, `ErrEmptyChain`, `ErrChainVerificationFailed`,
`ErrUnsupportedKeyType`, `ErrUnsupportedSignatureAlgorithm`,
`ErrNonceMismatch`, `ErrNonceRequired`, `ErrUeidMismatch`,
`ErrOperationalStateNotPermitted`, `ErrNoMeasurement`,
`ErrCriticalEvidenceUnreadable`.

Every one of them is re-exported from `sdk/go/attestation_dice.go` as
`ErrDICE<Name>`, aliased to the canonical value rather than copied, so a
consumer that cannot import `pkg/` can still use `errors.Is`.

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

### End to end against the real firmware

`pkg/acme/client/device_attest_dice_e2e_test.go` enrolls arduino-generic's
element-tier simulator (`agsim.StartElement`: the real firmware compiled for the
host, with a model of the ATECC608A that does real P-256) through
`Client.DeviceAttest`, the real ACME handlers and the production
`deviceattest01.TrustAnchorVerifier`. `dice_roots` holds a certificate for the
simulator's DeviceID public key, as a provisioning record would; the alias
certificate's issuer is that key.

```
make agsim                                 # build the simulators into $AGSIM_DIR
go test -tags "codec_json" -run TestDeviceAttestDICE ./pkg/acme/client/
```

`make agsim` builds from the arduino-generic module at the version `go.mod`
pins (`scripts/build-agsim.sh`), after checking the module hash against
`scripts/agsim.sum` (the root arduino-generic module is not in `go.mod`, so
`go.sum` does not cover it; bumping the dependency adds a line there); `make test`, `make race` and
`make coverage-full` run it first. A missing binary fails the test and prints the
command; it never skips.

| Case | Outcome |
|---|---|
| order for the device's ueid, evidence over `DICENonce(keyAuthorization)`, CSR for the alias key | certificate issued, `permanentIdentifier` = hex ueid |
| order for another ueid | `unauthorized` |
| evidence over another challenge's nonce | `incorrectResponse` (`dice.ErrNonceMismatch`) |
| `dice_roots` that do not anchor the device | `incorrectResponse` (`ErrCertificateChainInvalid`) |
| CSR for a key other than the alias key | `badCSR` |

The firmware has no command that signs a CSR, and the alias key is the DeviceID
key, so the test signs the CSR with the simulator's published test private key.
The simulator identity is a test identity: its private key is the SHA-256 of a
published string, and no deployment may anchor on it.
