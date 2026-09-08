# TPM 2.0 — Engineering Contract

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-09-08

## Exported surface — `pkg/tpm2`

The package is large; the map in [`architecture.md`](architecture.md)
§"Shape chosen" is the index. The groups an implementer reaches for:

| Need | Start at |
|---|---|
| open a device, run a session | `tpm.go`, `session.go`, `auth.go` |
| create or load a key | `key.go`, `template.go`, `secretkey.go` |
| sign / verify / derive | `ecdsa.go`, `rsa.go`, `ecdh.go`, `sigscheme.go`, `kdf.go` |
| seal to platform state | `seal.go`, `sealer.go`, `policy.go`, `pcr.go` |
| NV storage | `nvram.go`, `nv_extend.go` |
| attest / certify | `attestation.go`, `certify_verify.go`, `eventlog.go` |
| IDevID / TCG enrollment | `cert_idevid.go`, `idevid_csr.go`, `tcg_csr_serverside.go`, `cert_convert.go` |
| provision the platform | `platform.go`, `platform_keystore.go`, `platform_types.go`, `provision.go` |
| ask what this TPM can do | `capabilities.go`, `capability_device.go`, `version.go` |
| lockout state | `lockout.go` |
| randomness | `random.go` |

`reexports.go` is the curated surface for consumers that should not import the
whole package. `pkg/tpm2/store` holds the key-backend types (`KeyBackend` in
`store/interfaces.go`). `pkg/tpm2/mocks` supplies test substitutes.

`pkg/attestation` is the verification half: `verifier.go`, `invariants.go`,
`types.go`, `errors.go`, `truststore/`, `android/`.

## Invariants

- **Every session and object context must be released.** This is the single
  most important rule in the package, and it has three dedicated simulator
  suites: `object_context_leak_simulator_test.go`,
  `auth_session_leak_simulator_test.go`,
  `auth_session_leak_transport_fault_simulator_test.go`, plus
  `resource_leak_simulator_test.go`. A leak does not fail immediately — it
  exhausts the TPM hours later, which is why it needs tests rather than care.
- **A quote is meaningless without a fresh nonce.** Never verify a quote whose
  nonce you did not just generate.
- **`ImportAttestation*` stores, `VerifyAttestationQuote` decides.** Storing
  evidence is not verifying it.
- **PCR selection is fixed at seal time.** Changing the selection does not
  re-bind existing sealed blobs; it makes new ones behave differently.
- **NV indices must not collide.** PIV storage derives its indices from a
  configured base (`pivcert.GetNVIndex`); other NV users must not overlap it.
- **Failed authorizations advance the lockout counter**, and it persists across
  reboots. Retrying blindly is how a TPM becomes unusable for its recovery
  interval.
- **The simulator serves one client at a time.** Two suites sharing a simulator
  block each other; this is a property of the simulator, not a bug to work
  around with retries.
- **Concurrency.** TPM access is serialised — the device has a single command
  channel. Do not expect parallel throughput.
- **An ECC public area is only ever accepted as a point on its curve.** Every
  reconstruction of an `ecdsa.PublicKey` from a `TPMT_PUBLIC` goes through the
  one unexported helper `eccPublicKey` (`eccpub.go`), which delegates to
  `pkg/crypto/ecpoint`. Assigning the raw `X` and `Y` coordinates into the
  struct performs no validation at all, so an off-curve point supplied by a
  broken, emulated or hostile TPM would be accepted and then used as an
  attestation identity. Never reconstruct one by hand.
- **An IDevID or IAK is created from TCG Template H-0, with its key policy
  assigned at creation.** TCG *TPM 2.0 Keys for Device Identity and
  Attestation* v1.00 r12 §7.3.4.1 fixes the object attributes: `fixedTPM`,
  `fixedParent`, `sensitiveDataOrigin`, `sign`, `userWithAuth` **and**
  `adminWithPolicy` SET; `decrypt` CLEAR; `Restricted` CLEAR for the signing
  IDevID and SET for the IAK. The split of roles is the point (§7.2.4): the
  authValue can *use* the key, only a policy can *administer* it. The
  `authPolicy` is the IDevID/IAK Key Policy of §7.3.6.6 — a `TPM2_PolicyOR`
  over PolicyUser, PolicyCertify, PolicyActivateCredential and
  PolicyDelegationNV — computed by `DevIDKeyPolicyDigest` for the template's
  `nameAlg` and pinned to the specification's published Tables 14–19 in
  `devid_policy_test.go`. It depends on the nameAlg, so the static templates
  ship it empty and `CreateIDevID`/`CreateIAK` assign it;
  `assertDevIDTemplateConformant` (`key.go`) then refuses any template whose
  attributes, policy, `unique`, scheme, symmetric definition, exponent, KDF or
  curve depart from H-0 through H-4, *before* `TPM2_CreatePrimary`, because
  every one of those values is an input to the primary's derivation and cannot
  be corrected once the key exists. `assertAdminAuthorizable` remains the
  narrower guard underneath it.
- **One builder produces every DevID template.** `DevIDTemplateSpec.Template`
  (`devid_template.go`) is the only place a Recoverable IDevID/IAK template is
  assembled; the package variables (`RSASSAAKTemplate`,
  `ECCIDevIDP384Template`, …) and both creation paths derive from it. They did
  not: `CreateIAK` built inline copies of the templates the package exported,
  so the two disagreed the moment either changed.
  - `unique` is the string §7.3.1 Table 2 requires — `'IDEVID'` or `'IAK'`,
    unpadded, not NUL terminated — optionally followed by the printable-ASCII
    `tpm.device-string`, which is a property of the device and so is shared by
    both its keys. `DevIDUniqueString` builds and validates it; the combined
    length is bounded by the crypto suite's `unique` field (the RSA modulus
    size, or an ECC coordinate).
  - An RSA IDevID's scheme is `TPM_ALG_NULL` (H-1, "Signing"), so
    `TPM2_Sign` is told the padding and digest per command — see
    `rsaSignScheme` / `rsaSchemeHash`, which both the `crypto.Signer` path and
    `SignValidate` use. An IAK names RSASSA or RSAPSS with a hash, because a
    Restricted signing key may not name `TPM_ALG_NULL` (TPM 2.0 Library
    Part 1, §25.2.3).
  - `symmetric->algorithm`, `exponent` and `kdf->scheme` are stated rather
    than left to the Go zero value. go-tpm tags those fields
    `gotpm:"nullable"` and writes `TPM_ALG_NULL` for the zero value, so this
    is the same key on the wire today (measured in `devid_template_test.go`);
    it is stated so that a field deciding a device's identity does not depend
    on a struct tag.
  - Suites: H-1 RSA, H-2 P-256, H-3 P-384 (nameAlg SHA-384), H-4 P-521
    (nameAlg SHA-512).
  - **H-5 (SM2 P-256) is not supported.** It requires nameAlg
    `TPM_ALG_SM3_256`, which the TPMs this library is tested against do not
    implement — the reference simulator refuses such a template with
    `TPM_RC_HASH` — and `crypto/elliptic` has no SM2 curve, so a key on it
    could not be returned as the `*ecdsa.PublicKey` the creation API produces.
    Shipping an untestable template would be worse than saying so. A
    configuration asking for it is refused rather than substituted: an
    `idevid.ecc.curve` / `iak.ecc.curve` of `SM2` fails in `types.ParseCurve`
    with `types.ErrUnknownCurve`, and any curve reaching `eccTemplate` without
    a template — P-224 is the only one that can — is refused with
    `ErrDevIDTemplateSuiteUnsupported`, whose message names H-5 and why.
    `TestDevIDTemplate_SM2IsNotImplemented` re-measures both halves, so the
    day a TPM or Go gains SM2 the test says so.
  - **Known departure, deliberate, and the specification's own resolution.**
    H-2 through H-4 state both `scheme->scheme = TPM_ALG_ECDSA` and
    `scheme->details = NULL`, a pair no TPM can carry: the details of an ECDSA
    `TPMT_ECC_SCHEME` are a `TPMS_SIG_SCHEME_ECDSA` whose `hashAlg` is a
    `TPMI_ALG_HASH` with no `+` decoration. `TPM2_CreatePrimary` answers
    `TPM_RC_HASH` for all three curves; `devid_template_simulator_test.go`
    measures it and exists to stop anyone "fixing" it back. The scheme stays
    ECDSA — the constraint Table 5 states — and the details name the
    template's nameAlg, which is the pairing §14 (Annex B, Table 24, the IEEE
    802.1AR PICS) uses when it names the conformance suites: "the ECDSA
    P-256/SHA-256 signature suite" (ECDSA256) and "the ECDSA P-384/SHA-384
    signature suite" (ECDSA384). Table 24 lists no P-521 row, being a subset
    of 802.1AR's PICS, so H-4's own nameAlg (SHA-512, Table 7) supplies that
    pairing by the same rule.
- **ADMIN-role commands on an IDevID or IAK run under `DevIDAdminSession`.**
  `TPM2_Certify` (objectHandle) and `TPM2_ActivateCredential`
  (activateHandle) authorize the key at the ADMIN role, which the authValue is
  now refused for with `TPM_RC_AUTH_TYPE`. The session walks the matching
  branch — `PolicySecret(TPM_RH_ENDORSEMENT)`, `PolicyCommandCode(command)`,
  `PolicyOR(the four branches)` — so it authorizes exactly one command as the
  Privacy Administrator; a session built for one command answers
  `TPM_RC_POLICY_CC` when used for another. The USER role — signing — is the
  authValue on every path, which is why `createKeySession` never builds a
  platform-policy session for a DevID key: that session's digest could not
  equal the key's `authPolicy`. Binding a DevID key to platform state is the
  Delegation Policy NV index of §7.3.5, an owner operation that is not part of
  provisioning.
- **An identity key's CN is resolved by one rule on every path.**
  `DevIDCommonName` (`config.go`): an explicit `cn` wins; otherwise the
  device's model and serial number — the Platform Identity Information the
  TCG-CSR-IDEVID carries (§7.2.3 step 4a) and 802.1AR binds a DevID Subject to
  (§2.3.4) — joined as `model-serial`; otherwise `ErrDevIDCNUnresolved`.
  `IDevIDAttributesFromConfig`, `CreateIAK` and the cold-cache rebuild in
  `IAKAttributes` all call it, so a rebuild can never describe a key
  differently from provisioning (#337), and the IAK and IDevID of one device
  never disagree about which device they name. Nothing fabricates a fixed
  default: the key store composes its storage key from the CN, and
  `store.FileBackend` refuses an empty one (`ErrEmptyKeyCN`) rather than
  collapsing every nameless key onto the bare extension (#440).

## Error semantics

Typed errors throughout; `pkg/attestation/errors.go` holds the verification
vocabulary. The categories that need distinguishing:

| Condition | Meaning |
|---|---|
| PCR mismatch on unseal | the platform state changed — the mechanism working |
| auth failure | wrong authorization; **advances the lockout counter** |
| lockout active | the TPM is refusing authorizations |
| NV exhausted | no room for another index |
| session/context exhaustion | handles leaked earlier in this process |
| EK chain does not verify | the manufacturer root is not trusted |
| AK certification invalid | the AK is not bound to that EK |
| quote signature or nonce invalid | the evidence is not fresh or not from that AK |
| `ErrECCPublicArea` | the ECC public area does not yield a valid public key: bad parameters, an unknown curve, or a point that is not on the curve. On the `TPM2_Certify` path it is wrapped as `ErrCertifyMalformed`; the underlying `ecpoint.ErrInvalidPoint` stays reachable through `errors.Is` |
| `ErrAdminWithPolicyNoAuthPolicy` | the template about to be created from sets `adminWithPolicy` while naming no `authPolicy`, so the object's ADMIN role would be unauthorizable by anything. Raised by `assertAdminAuthorizable` before `TPM2_CreatePrimary`; nothing is created |
| `ErrDevIDTemplateNonConformant` | the IDevID or IAK template about to be created from departs from TCG Templates H-0 through H-4 in an attribute, its `authPolicy`, its `unique` string, its scheme, its symmetric definition, its exponent, its KDF or its curve. Raised by `assertDevIDTemplateConformant` before `TPM2_CreatePrimary`; nothing is created |
| `ErrDevIDUniqueString` | a `unique` string that is not §7.3.1 Table 2's, or a `tpm.device-string` that is not printable ASCII |
| `ErrDevIDUniqueStringTooLong` | the required string plus the device string exceeds the crypto suite's `unique` field |
| `ErrDevIDTemplateSuiteUnsupported` | a crypto suite the specification defines no template for: a `nameAlg` with no Policy NV Index, or a scheme H-1 does not allow for the key's purpose |
| `ErrDevIDPolicyUnsupported` | a key kind or `nameAlg` for which the specification defines no template or Policy NV Index (only SHA256, SHA384 and SHA512 are defined) |
| `ErrDevIDPolicyDigestCompute` | the trial-policy computation of a key policy or NV Index Name failed inside go-tpm |
| `ErrDevIDPolicySession` | the ADMIN-role policy session could not be built: a command with no branch in the key policy, a `PolicySecret` refused for a wrong endorsement auth, or a TPM error on a policy command |
| `ErrDevIDCNUnresolved` | neither `cn` nor both a device model and serial number were available to name an IDevID or IAK |
| `store.ErrEmptyKeyCN` | a key-store operation was attempted with an empty CN, which would compose a storage key of the bare extension |

**Fail closed:** every one of these refuses. Nothing degrades to a software key
or an unverified acceptance.

## Configuration

`pkg/tpm2/config.go`. The settings that change behaviour:

- **Device path**, or simulator host/port. In the shipped configs the simulator
  is addressed as `simulator_host` / `simulator_port` (default `2321`) — **not**
  as `device_path`. A `tcp://host:port` string in `device_path` names a file
  that does not exist; `Config.ToTPMConfig` maps the simulator fields to
  `CommandAddress` and clears the device path. The integration config
  (`configs/xkmsd-integration.yaml`) documents this at length because it has
  cost time before.
- **Hierarchy authorizations** — endorsement, lockout, owner. Platform-held.
- **PCR selection and policy** — `pkg/seal/policy` and `pcr.go`.
- **Session encryption** — TPM2 session encryption is configurable; see the
  legacy `docs/configuration/tpm2-session-encryption.md` pending its own
  migration.

## Persistence

Three distinct stores, all on the device:

- **Persistent handles** — long-lived keys such as the SRK.
- **NV indices** — PIV certificates (`pkg/pivcert/tpm2`), platform data. Finite.
- **Sealed blobs** — held outside the TPM, decryptable only by it under policy.

Nothing here is portable: a sealed blob is bound to that TPM, and often to that
TPM in that measured state. Plan recovery accordingly — this is the same
constraint that makes barrier recovery keys worth having
([`../sealing-and-barrier/`](../sealing-and-barrier/engineering.md)).

## Test strategy

The suite is unusually large and deliberately structured:

- **Unit** — one `_test.go` per file.
- **Specification vectors** — `devid_policy_test.go` pins every step of the
  IDevID/IAK Key Policy computation (PolicyUser, PolicyCertify,
  PolicyActivateCredential, the Policy NV Index Names, PolicyDelegationNV and
  the final PolicyOR) to the digests TCG publishes in Tables 14–19 of *TPM 2.0
  Keys for Device Identity and Attestation* v1.00 r12, across SHA256/384/512
  where the specification prints them. go-tpm's `PolicyUpdate` and the
  specification are two independent implementations; the suite is the proof
  they agree. The specification is checked in under `docs/references/`.
  `devid_template_test.go` does the same for the §7.3.4 creation templates,
  pinning H-1 through H-4 field by field and running one mutation per field
  the specification fixes through `assertDevIDTemplateConformant`.
- **Simulator suites** (`*_simulator_test.go`) — the whole device surface
  against `tpm_simulator.go`: crypto ops, key lifecycle, algorithm agility,
  attestation certify, IDevID CSR round-trip and sizing, device identity
  signing (`idevid_sign_simulator_test.go` — which bytes each of the two
  identity keys actually signs), IDevID admin-role authorization
  (`idevid_admin_policy_simulator_test.go` — reads the created object's public
  area back from its persistent handle and drives `TPM2_Certify` against it,
  because the attribute bits alone do not prove the ADMIN role is reachable),
  device identity key derivation (`devid_template_simulator_test.go` --
  measures that `unique` changes the created key's Name, that every shipped
  suite creates and that no two suites derive the same key, that H-2's
  `scheme->details = NULL` is refused by the TPM, and that the key
  `CreateIDevID` persists is the one `DevIDTemplateSpec` derives),
  seal-with-PCR-policy, SSRK platform policy,
  capabilities, PIN enrollment.
- **Leak suites** — object contexts, auth sessions, auth sessions under
  transport fault, general resources. These are the regression guard for the
  package's hardest rule.
- **Regression fixtures** — `loadkeypair_delete_regression_simulator_test.go`,
  `left_alone_fixes_test.go` keep specific past bugs from returning.
- **Harness** — `simharness_simulator_test.go`.
- **Integration** — `test/integration/tpm2`, `test/integration/acme-tpm`.

Hardware runs need a real TPM; the simulator covers everything else, one client
at a time.

## Observability

TPM operations log with the correlation ID. Two things are worth logging
explicitly at startup because they are invisible otherwise: which device or
simulator was opened, and the current lockout state. A deployment silently on a
simulator, or one whose TPM is in lockout, looks identical to a healthy one
until the first operation fails.
