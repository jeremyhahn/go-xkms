- **IDevID and IAK key creation templates now match TCG "TPM 2.0 Keys for
  Device Identity and Attestation" v1.00 r12 field for field**, §7.3.4
  Templates H-0 through H-4, built in one place (`DevIDTemplateSpec`,
  `pkg/tpm2/devid_template.go`) that both `CreateIDevID` and `CreateIAK`
  derive from. `CreateIAK` previously built its own inline copies of the
  templates the package exports, so the two could — and did — disagree.

  - **`unique` carries the required string of §7.3.1 Table 2** — `'IDEVID'`
    (49 44 45 56 49 44) or `'IAK'` (49 41 4B), unpadded and not NUL
    terminated — where both keys previously zero-filled it. The MUST exists
    so that a device's identity keys are reproducible by anyone following the
    specification; a zero-filled `unique` produced keys nothing else could
    recreate. The optional per-device string is the new `tpm.device-string`
    configuration key: printable ASCII, appended to the required string, the
    same value for both keys because §7.3.1 describes a property of the
    device. Where it is stored is the OEM's choice (§7.3.3 reserves NV Index
    0x01C90020 for it); this library reads it from configuration.
  - **An RSA IDevID names no signature scheme** (`TPM_ALG_NULL`), as H-1
    requires of a signing DevID, instead of pinning RSASSA or RSAPSS with
    SHA-256. The padding and digest are chosen per `TPM2_Sign` command, so one
    device identity key can now produce both the PKCS#1 v1.5 signature a
    certificate is signed with and the RSA-PSS a TLS 1.3 handshake requires.
    An IAK keeps RSASSA or RSAPSS with a hash: a Restricted signing key may
    not name `TPM_ALG_NULL` (TPM 2.0 Library Part 1, §25.2.3).
  - **`symmetric->algorithm`, `exponent` and `kdf->scheme` are stated
    explicitly** on every DevID template rather than left to Go's zero value.
  - **P-384 and P-521 suites** (Templates H-3 and H-4, with nameAlg SHA-384
    and SHA-512) are added and reachable from an `idevid.ecc.curve` /
    `iak.ecc.curve` configuration: `ECCIDevIDP384Template`,
    `ECCIDevIDP521Template`, `ECCAKP384Template`, `ECCAKP521Template`,
    re-exported through `sdk/go`. Template H-5 (SM2 P-256) is **not**
    implemented: it requires nameAlg `TPM_ALG_SM3_256`, which the TPMs this
    library is tested against do not implement (the reference simulator
    refuses such a template with `TPM_RC_HASH`), and `crypto/elliptic` has no
    SM2 curve. A configuration naming it is refused rather than substituted —
    `types.ErrUnknownCurve` from `types.ParseCurve`, and
    `ErrDevIDTemplateSuiteUnsupported` for any curve that reaches the template
    builder without one.
  - **`assertDevIDTemplateConformant` now covers `unique`, scheme, symmetric,
    exponent, KDF and curve** in addition to the H-0 attributes and the key
    policy, so any departure is refused with
    `ErrDevIDTemplateNonConformant` before `TPM2_CreatePrimary` rather than
    baked into a key that cannot be repaired. New errors:
    `ErrDevIDUniqueString`, `ErrDevIDUniqueStringTooLong`,
    `ErrDevIDTemplateSuiteUnsupported`.

  **Known departure from Table 5, deliberate, and the specification's own
  resolution.** Templates H-2, H-3 and H-4 state both `scheme->scheme =
  TPM_ALG_ECDSA` and `scheme->details = NULL`. No TPM can carry that pair: the
  details of an ECDSA `TPMT_ECC_SCHEME` are a `TPMS_SIG_SCHEME_ECDSA`, whose
  `hashAlg` is a `TPMI_ALG_HASH` with no `+` decoration, so `TPM_ALG_NULL` is
  not admissible there, and `TPM2_CreatePrimary` answers `TPM_RC_HASH` for
  P-256, P-384 and P-521 alike (measured; `devid_template_simulator_test.go`
  pins the refusal). The scheme stays `TPM_ALG_ECDSA` — the constraint Table 5
  actually states — and the details name the template's own nameAlg, which is
  the pairing §14 (Annex B, Table 24) uses when it names the conformance
  suites: "the ECDSA P-256/SHA-256 signature suite" and "the ECDSA
  P-384/SHA-384 signature suite". Dropping to a `TPM_ALG_NULL` scheme would
  create, but would discard the stated constraint and widen the key's grant.

- **`SignValidate` resolves an RSA signature scheme instead of copying the
  key's.** It sent the key's own scheme field as `inScheme`, which is a
  `TPM_ALG_NULL` for a Template H-1 IDevID, and `TPM2_Sign` refuses a
  `TPM_ALG_NULL` `inScheme` on a key that names no scheme with
  `TPM_RC_SCHEME` — for a key that constrains nothing, the command must say
  what to sign with. It now uses the same `rsaSignScheme` resolution the
  `crypto.Signer` path uses, and unpacks the response as the shape it asked
  for rather than deciding that separately.

- **Upgrade note — this re-keys every IDevID and IAK, and supersedes the
  upgrade note of the Template H-0 / key policy change in this same
  release.** Both changes move inputs to a primary key's derivation:
  `adminWithPolicy` and `authPolicy` from that change, and `unique` and the
  RSA scheme from this one. A device provisioned before this release holds
  identity keys that `CreateIDevID` / `CreateIAK` can no longer derive.
  There is no in-place migration — that is what a primary key is. Those
  devices must be re-provisioned and their IDevID/IAK certificates re-issued;
  the existing certificates remain valid for the old keys, which the new code
  cannot reproduce. Setting `tpm.device-string` later re-keys again, for the
  same reason, so choose it before provisioning a fleet. Do this once, for
  both changes, rather than twice.
