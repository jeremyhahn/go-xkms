# TPM 2.0 — Engineering Contract

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-10-12

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
| IDevID / IAK key policy and delegation | `devid_policy.go`, `devid_policy_session.go`, `devid_delegation.go` |
| Local Attestation Key (LAK), certified by the IAK | `local_attestation_key.go` (`(*TPM2).CreateLAK`, `LAKAttributes`, `LAK`, `CertifyLAK`, `CertifyKeyWithLAK`), `cert_idevid.go` (`ProvisionLAKCert`, `LAKCertificate`, `DeleteLAKCertificate`) |
| provision the platform | `platform.go`, `platform_keystore.go`, `platform_types.go`, `provision.go` |
| classify provisioning state, clear for reprovisioning | `provisioning_state.go` (`ProvisioningState`, `(*TPM2).State`), `provision.go` (`(*TPM2).ClearForReprovision`, `(*TPM2).ForceClear`) |
| build/answer an EK credential challenge without a provisioned identity key | `credential_challenge.go` (`NewCredentialChallenge`, `ActivationKeyName`), `activation_key.go` (`(*TPM2).CreateActivationKey`, `(*TPM2).AnswerCredentialChallenge`) |
| ask what this TPM can do | `capabilities.go`, `capability_device.go`, `version.go` |
| lockout state | `lockout.go` |
| randomness | `random.go` |

`reexports.go` is the curated surface for consumers that should not import the
whole package. `pkg/tpm2/store` holds the key-backend types (`KeyBackend` in
`store/interfaces.go`). TPM key blobs persist through `BlobStorer`
(`Read`/`Write`/`Delete` by name, `store/interfaces.go:132`); its one
implementation, `NewFSBlobStore(logger, backend)` (`store/blob.go:59`), is a
go-qrdb DAO over `kvadapter.New(backend)` whose entity ID is the hash of the
blob name, so a read is a direct lookup. `pkg/tpm2/mocks` supplies test
substitutes.

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
  configured base and a per-slot certificate ID
  (`pkg/storage/hardware/tpm2_cert_storage.go:564-570`); other NV users must
  not overlap that range.
- **Failed authorizations advance the lockout counter**, and it persists across
  reboots. Retrying blindly is how a TPM becomes unusable for its recovery
  interval.
- **The simulator serves one client at a time.** Two suites sharing a simulator
  block each other; this is a property of the simulator, not a bug to work
  around with retries.
- **Concurrency.** TPM access is serialised — the device has a single command
  channel. Do not expect parallel throughput.
- **`(*TPM2).State` never fails on a property read.** `FixedProperties`
  degrades every individual `TPM2_GetCapability` failure to a zero value
  rather than returning an error, so `State`'s only real failure surface is
  computing the live platform policy digest for `PlatformSRKPolicyCurrent`
  (`PlatformPolicyDigest`, which reads the live PCR) when a Platform SRK is
  present — wrapped as `ErrProvisioningStateRead`. This is deliberate:
  `State` is a classification a caller polls, not a health check, and a
  caller that wants to know why a single property is unavailable reads it
  directly.
- **`(*TPM2).ClearForReprovision` tries LOCKOUT, then PLATFORM, then PPI
  `ForceClear`, and only the last one needs a reboot.** Each refused step is
  logged with its own typed error (`ErrClearLockoutRefused`,
  `ErrClearPlatformRefused`) before falling through; `ForceClear`'s own error
  (typically `ErrForceClear`, wrapping the seam failure) is returned
  directly, since it is the last path. `ForceClear`'s single sysfs write
  goes through the package-level `ppiRequestWriter` seam
  (`os.WriteFile` in production) so it is never exercised against a real
  host in a test.
- **`NewCredentialChallenge` needs no TPM; `AnswerCredentialChallenge` and
  `ActivateCredential` need the real one.** The verifier-side construction
  (`credential_challenge.go`) is pure software over an EK public key and an
  activation key's Name (`ActivationKeyName`); only the device side that
  actually decrypts the seed with the EK's private key proves possession.
  `CreateActivationKey` creates its transient key in the null hierarchy
  (`TPM_RH_NULL`, re-randomized every TPM reset), so it needs no hierarchy
  auth, and `AnswerCredentialChallenge` flushes it once the challenge has
  been answered — it is a one-shot object, not a key a caller reuses.
- **`AnswerCredentialChallenge` works without a persistent EK.** When no EK
  is loaded at `EKConfig.Handle` but the EK certificate is in NV (the state
  `TPM2_Clear` leaves), `createTransientEK` (`activation_key.go`) recreates
  the EK under the endorsement hierarchy from the TCG low-range template
  matching the certificate's key (`transientEKTemplate`: `RSAEKTemplate` for
  RSA-2048, `ECCEKTemplate` for P-256), refuses it unless its public key
  equals the certificate's, and flushes it on every path. The persistent EK
  is never created or re-persisted there. High-range certificates
  (index `0x01C00012` and above) are refused: their H templates carry a
  PolicyOR auth policy `activateCredential` does not satisfy.
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
  `TPM_RC_POLICY_CC` when used for another. `createKeySession` never builds a
  platform-policy session for a DevID key: that session's digest could not
  equal the key's `authPolicy`. The USER role is the authValue when one is
  set, and otherwise the delegated session below.
- **Delegated use of an IDevID or IAK goes through its Policy NV Index, and
  that is what `platform-policy` on an identity key means.** §7.3: the key
  policy's fourth branch is `TPM2_PolicyAuthorizeNV` over the Name of the
  reserved index (§7.3.2: DS1 `0x01C90010` / DA1 `0x01C90018` for SHA256).
  `DefineDevIDPolicyNV` defines it to NV Policy Template I-0/I-1..I-3
  (`0x220F1008`, dataSize `2 + digest`, `authPolicy` = PolicyUser) under
  **Owner** authorization (§7.3.5) and is idempotent; an index whose Name is
  not the specification's (Table 18 once written, the same public area before
  its first write) is refused with `ErrDevIDPolicyNVIndex` — one attribute
  bit off is a different Name, and a different Name can never delegate the
  key. `WriteDevIDDelegationPolicy` writes the Delegation Policy as a
  `TPMT_HA` — two bytes of hash ID, then the digest, `DevIDDelegationPolicyPayload`
  — under a `PolicySecret(TPM_RH_ENDORSEMENT)` session, so only the Privacy
  Administrator chooses it (§7.2.4), and may replace it at any time (§7.3.1).
  `DevIDDelegatedSession` satisfies a `DevIDDelegation` in a session, runs
  `TPM2_PolicyAuthorizeNV`, then the key policy's `PolicyOR`; the TPM honours
  it only if the index holds exactly the digest the session reached
  (`TPM_RC_VALUE` otherwise, kept in the error chain). `DevIDSigningDelegation`
  and `DevIDAttestationDelegation` are the specification's example policies,
  pinned to Table 20. **`platform-policy: true` on `idevid` or `iak`** does not
  change the key — it is Template H-0 regardless — it makes `CreateIDevID` /
  `CreateIAK` define the index and write `DevIDPlatformDelegation`:
  `TPM2_PolicyPCR` over the platform PCR at its current value, in the key's
  nameAlg (`platformPCRDigest`). With no authValue configured, `createKeySession`
  then hands out the delegated session for that key, so signing stops when the
  platform state moves and resumes once the Privacy Administrator writes the
  new state's policy. With an authValue configured, the authValue is used
  (§7.2.4 keeps it as a USER path on Template H-0); making platform state the
  *only* path means an authValue nobody knows, which is the Owner's choice.
  `provisionDevIDPlatformDelegation` uses the hierarchy authorization for both
  the Owner define and the Privacy Administrator write, because `Provision`
  sets one value on both hierarchies (`SetHierarchyAuth`).
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
- **Every configuration-derived field of an identity key is assigned by one
  function on both paths.** `applyIAKConfig` / `applyIDevIDConfig`
  (`key.go`) set the CN, key type, store, platform binding, signature
  algorithm and authValue; `CreateIAK` / `CreateIDevID` call them after the
  `*AttributesFromConfig` builders, and the cold-cache rebuilds
  `IAKAttributes` / `IDevIDAttributes` call them over the attributes read
  back from the TPM. Each time the two paths assigned a field separately it
  was lost on restart — the CN (#337), PlatformPolicy and KeyType (#466),
  the password (#467): a key with a configured authValue signed in the
  process that provisioned it and answered `TPM_RC_BAD_AUTH` from the next
  boot on. The authValue lives in an enclave (`types.NewPassword`); a value
  the attributes already hold is cleared before it is replaced. The IAK's
  self-certification (`TPM2_CertifyCreation`) is authorized by the IAK's own
  authValue, not the EK's (#467).

- **The Local Attestation Key (LAK) is an ordinary Platform-SRK child key,
  not an Endorsement-hierarchy primary (go-xkms#715).** TCG DevID v1 r12/v1.10
  r9 §8 requires the IAK's certificate Subject to be a unique X.500 DN;
  WebAuthn Level 2 §8.3.1 requires the "tpm" attestation statement's AIK
  certificate Subject to be empty, and go-webauthn enforces this literally.
  Rather than compromise the IAK's TCG shape, the LAK is a second,
  owner-created attestation key per TCG "TPM 2.0 Keys for Device Identity and
  Attestation" v1.10 r9 §5.3/§6.3 ("Owner Creation of a LAK Certificate based
  on an IAK Certificate"): `CreateLAK` (`local_attestation_key.go:45`) builds
  it with `CreateECDSA`/`CreateRSA` under the Platform SRK, Restricted and
  Sign-only (`ecdsa.go`, `rsa.go` recognise `types.KeyTypeLAK` and force a
  named scheme — a Restricted signing key may not use `TPM_ALG_NULL`), then
  makes it persistent at `LAKConfig.Handle` via `TPM2_EvictControl` under the
  Owner hierarchy exactly as `CreateIAK` persists the IAK. `LAKAttributes`
  rebuilds it from the persisted handle on restart, the same shape as
  `IAKAttributes`. Because it is not a DevID key, `devidKeyKindOf` does not
  recognise `KeyTypeLAK`: the LAK's own authorization is ordinary
  password/policy auth, never the DevID admin-policy session an IAK/IDevID
  target requires.
- **`DeleteIAK` is what makes replacing an IAK possible.** `CreateIAK`
  persists to `IAKConfig.Handle` with `TPM2_EvictControl`, which fails
  `TPM_RC_NV_DEFINED` while that handle is occupied. `DeleteIAK`
  (`key.go`) first evicts the persisted IAK under the Owner hierarchy, using
  the EK attributes' hierarchy authorization. It then removes the IAK
  certificate from the certificate store or `IAKConfig.CertHandle` and drops
  the cached attributes. A step that finds nothing to remove is not an error.
  The IAK Policy NV Index stays, because `CreateIAK` rewrites it.
  `xkey tpm iak create --force` calls it before `CreateIAK`. Without
  `--force`, an existing IAK is refused with `ErrIAKAlreadyExists`.
- **`CertifyKey`'s TPM2_Certify mechanics are shared by every signer, not
  duplicated per key.** `certifyKeyAs` (`attestation.go:94`) takes the
  signing key's attributes as a parameter; `CertifyKey` (signer: IAK),
  `CertifyLAK` (signer: IAK, target: LAK — the provisioning-time
  certification) and `CertifyKeyWithLAK` (signer: LAK, target: an ordinary
  key such as a WebAuthn credential key) are thin wrappers over it. Only the
  *target*'s own authorization branches on its key type
  (`devidKeyKindOf`); the signer's session is always ordinary object auth.
- **`pkg/ca.IssueLAKCertificate` verifies the LAK's TPM2_Certify evidence
  against the IAK's certificate, never against live TPM state.** The CA has
  no TPM access; it checks that the presented IAK certificate chains to the
  certificate about to sign the LAK and is within its validity period, then
  runs `tpm2.VerifyCertifyByCertificate` — which itself requires the IAK
  certificate to carry `tcg-kp-AIKCertificate` (2.23.133.8.3), the signature
  over `certifyInfo` to verify under the IAK's certified public key, the
  attestation to carry `TPM_GENERATED_VALUE`, and the certified Name to match
  the LAK's public area. The issued certificate follows the WebAuthn Level 2
  §8.3.1 profile (`ca.NewTCGLocalAttestationKeyProfile`, `profiles.go:709`):
  empty Subject, a critical subjectAltName directoryName carrying
  tcg-at-tpmManufacturer/tpmModel/tpmVersion, the tcg-kp-AIKCertificate EKU
  alone (no TLS purposes, no TCG certificate policies — this is not a TCG
  DevID credential), and Basic Constraints CA:false. The IAK's own TCG
  DevID-shaped certificate is unchanged.
- **A certificate store cannot key the LAK certificate by Common Name, because
  it has none.** `certstore.CertificateKey` (`pkg/certstore/certstore.go:46`)
  keys a certificate by `Subject.CommonName` when non-empty, or by its SPKI
  SHA-256 thumbprint (`qrdbsdk.ComputeSPKIThumbprint` — qrdb's own canonical
  mTLS binding identifier, not a parallel algorithm) when the Subject is
  empty. `compositeCertStore.StoreCertificate`/`StoreCertificateChain` apply
  this uniformly; a caller retrieving the LAK certificate later must compute
  the same key to look it up.

- **`DecodePCRs` treats its input as adversarial.** `Quote.PCRs` and the
  TCG-CSR `ProdCaData` carry PCR banks encoded by `EncodePCRs` with
  `encoding/gob`, and verifiers decode what a remote attester sent.
  `encoding/gob` is not hardened against adversarial input, so `DecodePCRs`
  (`pkg/tpm2/encoding.go:74`) refuses more than 64 KiB before decoding and
  validates the result against what `ReadPCRs` can produce
  (`encoding.go:50-66`, sharing `maxPCRIndex` with `ReadPCRs`). The gob
  encoding itself is unchanged: it is the wire format producers already emit.

## Object authorization

Every child object go-xkms creates under an SRK — sealed data (`SealKey`,
`Seal`, the platform store's sealed PKCS#11 PIN, `tpmpolicy` secrets and vTPM
state keys, FROST shares, the barrier's `TPM2Strategy` root key), symmetric
keys, and RSA, ECDSA and AES keys — has its policy bound by `bindObjectPolicy`
(`object_policy.go:56`) at creation and its USER role answered by
`objectSession` (`object_policy.go:115`) at use: `TPM2_Unseal`, `TPM2_Sign`,
`TPM2_RSA_Decrypt` (`RSADecrypt`, `rsa.go:285`) and `TPM2_ECDH_ZGen`. The
invariant is that an object with a policy can only be used through that
policy.

| Object binding | `authPolicy` | `userWithAuth` | USER role answered by |
|---|---|---|---|
| platform policy, password | `PolicyOR(PolicyPCR, PolicyAuthValue)` | CLEAR | PCR branch with no password; `PolicyAuthValue` branch with it (the recovery PIN) |
| platform policy, no password | `PolicyPCR` alone (`platformPCRPolicyDigestFromPin`, `tpm.go:821`) | CLEAR | `PolicyPCR` session (`platformPCRSession`, `session.go:575`) |
| named policy, with or without password | `AuthorizedObjectPolicy` (see [`../tpm-policies/engineering.md`](../tpm-policies/engineering.md)) | CLEAR | the authorized policy session; the password only where the policy asks for it |
| caller digest (`SealOptions.AuthPolicy`), sealed data only | the caller's digest | CLEAR | a policy session the caller builds (systemd-cryptsetup for a `systemd-tpm2` LUKS token); xkms builds none |
| no policy, password | empty | SET | salted HMAC session proving the password |
| no policy, no password | empty | SET | an empty password: refused for sealed data by `SealKey` (`sealer.go:289`) with `ErrSealUnprotected` (`types.go:504`); allowed for keys, whose `TPM2_Load` is gated by the parent |

- **`userWithAuth` is cleared on every object with an `authPolicy`**
  (`restrictUserRole`, `object_policy.go:97`). With it SET, TPM 2.0 lets the
  `authValue` alone satisfy the USER role (Part 1 §19.7.5): an object bound
  to a policy without a password answered a plain empty password, skipping
  the policy, and one with a password answered that password alone. A
  password on a policy-bound object is enforced only with `PolicyAuthValue`
  inside the policy.
- **No open `PolicyAuthValue` branch.** `PolicyAuthValue` proves knowledge of
  the object's `authValue`; an empty one is known to everyone. A passwordless
  platform-policy object therefore gets the `PolicyPCR` branch alone, and a
  named policy gets the outer `PolicyAuthValue` branch only when the object
  has a password (`namedPolicyBinding`).
- **The object chooses its session.** `objectSession` uses the named-policy
  binding record when there is one, `devidKeySession` for an IDevID or IAK,
  and otherwise reads the loaded object's `authPolicy` back with
  `TPM2_ReadPublic`: empty selects the password session; with a password the
  platform `PolicyAuthValue` branch; without one `platformPCRBranchSession`
  (`object_policy.go:169`), which builds the `PolicyPCR` session when the
  `authPolicy` is the live `PolicyPCR` digest and the platform `PolicyOR`'s
  PCR branch otherwise. The read-back only selects which session to build;
  the TPM still checks the session against the object, so a wrong choice can
  only fail. A caller's `TPMPolicy` is not needed at use.
- **NV indices.** An NV index defined with the platform policy (`NVWrite`,
  `NVDefineCounter`, `NVDefineExtend`) never has an auth value, so its policy
  is the `PolicyPCR` branch alone and it is defined without
  `TPMA_NV_AUTHREAD`/`TPMA_NV_AUTHWRITE` (`nvPlatformPolicy`,
  `nvram.go:903`): its empty auth value authorizes nothing. It is read through
  `TPMA_NV_POLICYREAD` (`nvPolicyReadAuthorization`, `nvram.go:918`, chosen
  from the index's own attributes) or by the owner, and written by the owner.
- **The seal refusal belongs to `SealKey`.** `requireSealProtection`
  (`seal.go:231`) runs in `SealKey`, which `Seal` and every sealing caller go
  through. Keys and symmetric key objects keep the pre-existing rule that
  their `TPM2_Load` is gated by the Platform SRK's USER PIN or platform
  policy, so they may carry neither.
- **Defaults bind to the parent's policy.** `Seal` with no `KeyAttributes`
  (`defaultSealKeyAttributes`, `sealer.go:41`) binds a passwordless seal to
  the Platform SRK's own policy and a password-carrying seal to the password
  alone. `frost.TPM2SecretSealKeyAttributes`
  (`pkg/keyprovider/frost/wrapkey.go:80`) does the same for FROST shares.
- **A caller-computed digest (`SealOptions.AuthPolicy`).** `Seal` installs
  it as the sealed object's `authPolicy` (`applySealAuthPolicy`,
  `sealer.go:171`) after checking it is the size of the object's name
  algorithm digest (`ErrSealAuthPolicySize`) and that the seal names no TPM
  policy as well (`ErrSealAuthPolicyConflict`). It counts as a policy, so
  the seal is not refused as unprotected, and `userWithAuth` is cleared as
  for every policy-bound object. xkms builds sessions only for its own
  platform and named policies, so it does not unseal such an object:
  whoever computed the digest does. `pkg/luks` uses it for the
  `systemd-tpm2` token it seals under the Shared SRK, which only
  systemd-cryptsetup unseals (`luks.ErrTPMSSRKUnsealUnsupported`). The PCR
  selection behind the digest is the caller's own record (the token's PCR
  list); `Seal` takes only the digest.
- **AAD is bound inside the sealed secret.** A keyed-hash object has no
  AAD input, so `Seal` with `SealOptions.AAD` seals
  `magic(16) ‖ SHA-256(AAD) ‖ data` (`bindSealAAD`,
  `sealed_data_authentication.go`) and `Unseal` returns the data only for the
  same AAD, compared in constant time (`openSealAAD`). The TPM
  integrity-protects the whole secret. It costs 48 of the 128 bytes
  (`MAX_SYM_DATA`), so AAD seals hold at most 80 bytes
  (`ErrSealAADTooLarge`). A seal without AAD is unchanged on the wire.
- **Unseal classifies its failures.** A refusal of the sealed object by
  `TPM2_Load` with a parameter-scoped response code (`TPM_RC_INTEGRITY`,
  `_BINDING`, `_SIZE`, `_INSUFFICIENT`, …) or `TPM_RC_SENSITIVE`, a wrong
  backend type, a half-present public/private pair, an area over 2048 bytes
  or the two over 3072 (`ErrObjectAreaTooLarge`, refused by `LoadKeyPair` /
  `LoadKeyPairFromBlobs` before the TPM is asked), a loaded object
  `TPM2_Unseal` refuses as not sealed data (`TPM_RC_TYPE` /
  `TPM_RC_ATTRIBUTES` on the item handle), or a mismatched AAD matches
  `types.ErrSealedDataAuthentication` (`ErrSealedObjectRejected`,
  `ErrSealedObjectIncomplete`); a policy or UserAuth failure, a warning, a
  transport or storage error does not. Only `TPM2_Load` is classified:
  `TPM2_PolicyPCR` answers a moved PCR with the parameter-scoped
  `TPM_RC_VALUE`, which is environment. See
  [`../sealing-and-barrier/engineering.md`](../sealing-and-barrier/engineering.md)
  §"Sealed-data authentication".
- **Existing objects keep their attributes.** An object or NV index created
  before this rule keeps `userWithAuth` (or `TPMA_NV_AUTHREAD`) SET and, when
  passwordless and platform-bound, its open `PolicyAuthValue` branch.
  Re-create it to apply the rule; nothing is migrated.

## Bus protection

The TPM bus is outside the security boundary: an observer with a probe on
LPC/SPI/I²C sees every command and response. No secret crosses it in
plaintext, and nothing about that is configurable.

**Salt key.** Every session that carries a secret is salted: its session key
comes from a random salt encrypted to a TPM-resident key, so a capture neither
decrypts its parameters nor lets the auth value behind its HMAC be brute
forced offline. `saltKey` (`pkg/tpm2/session.go:94`) uses the persistent EK at
`ek.handle`, which it only reads (`TPM2_ReadPublic`) and never modifies. When
no EK is resident — between `TPM2_Clear` and `CreateEK` during provisioning,
or on a TPM whose EK was never persisted — `nullSaltKey` (`session.go:115`)
creates an ephemeral ECC P-256 key in the NULL hierarchy from go-tpm's
`ECCSRKTemplate` (`session.go:122`), and `startSaltedSession`
(`session.go:181`) flushes it as soon as `TPM2_StartAuthSession` returns. A
failure to flush it does not fail the command the session serves — the
session no longer needs it — but is returned by the session's closer, the
teardown channel every caller already handles. Any other lookup failure is
`ErrSaltKey`; it is never answered with an unsalted session.

**Auth values.** A non-empty auth value is proven through a salted HMAC
session, never a `TPM_RS_PW` password session, which would put the value on
the bus verbatim:

- objects and NV indexes — `objectAuthSession` (`session.go:261`);
- hierarchies (the SO PIN) — `hierarchyAuthSession` (`session.go:272`), bound
  to the hierarchy. `TPM2_HierarchyChangeAuth` and `TPM2_Clear` change the
  hierarchy's own auth, and the TPM computes their response HMAC with the new
  value; a bound session authorizing its bind entity leaves the auth value out
  of the HMAC key, so the response verifies. `withHierarchyAuth`
  (`session.go:324`) wraps a command in one;
- the PIN branch of the platform policy — `platformPolicySession`
  (`session.go:442`) salts the `PolicyAuthValue` session. Unsalted, its HMAC
  key is the PIN alone.

An empty auth value with nothing to encrypt stays a zero-round-trip empty
password session.

**Parameter encryption.** AES-128-CFB on the first command or response
parameter, in the direction the secret travels (`paramEncryption`,
`session.go:50`): the TPM refuses the attribute with `TPM_RC_ATTRIBUTES` on a
command whose first parameter is not a TPM2B, so it is set per command, never
blanket. Where the package builds the authorization itself the same session
encrypts; where the authorization comes from `CreateSession` /
`CreateKeySession` — a policy session may answer the PCR branch, which cannot
encrypt because the TPM mixes the entity's auth value into the key — a
separate `encryptionSession` (`session.go:250`) is attached as an extra
session.

| Command | Secret | Protection | Site |
|---|---|---|---|
| `TPM2_CreatePrimary` (EK, SSRK, PSRK, IAK, IDevID, `ChangeAuth`) | new key's `userAuth` (the USER PIN for the PSRK); hierarchy auth | salted bound session, encrypt in | `createPrimary`, `key.go:552` |
| `TPM2_EvictControl` | hierarchy auth | salted bound session | `evictControl`, `key.go:570` |
| `TPM2_HierarchyChangeAuth` | old and new hierarchy auth | salted bound session, encrypt in | `hierarchyChangeAuth`, `tpm.go:1154` |
| `TPM2_Clear` | lockout auth | salted bound session | `Clear`, `provision.go:26` |
| `TPM2_PolicySecret` (endorsement) | endorsement auth | salted bound session | `policySecret`, `session.go:343` |
| `TPM2_NV_DefineSpace` | hierarchy auth, index auth | salted bound session, encrypt in | `nvDefineSpace`, `nvram.go:888` |
| `TPM2_NV_Write` (`NVWrite`) | sealed data; hierarchy auth | salted bound session, encrypt in | `nvram.go:117` |
| `TPM2_NV_Read` (`NVRead`) | sealed data | extra session, encrypt out | `nvram.go:310` |
| `TPM2_NV_Increment`, `TPM2_NV_Extend`, `TPM2_NV_UndefineSpace`, NV reads under owner auth | hierarchy auth | salted bound session | `nvram.go:539`, `:638`, `:864`, `nvReadAuthorization` `:911` |
| `TPM2_Create` / `TPM2_CreateLoaded` (seal, RSA, ECDSA, secret, symmetric) | sealed data (symmetric keys included), key `userAuth` | extra session, encrypt in | `seal.go:145`, `rsa.go:124`, `ecdsa.go:123`, `secretkey.go:86` |
| `TPM2_Unseal` | sealed data (the auto-unsealed PKCS#11 PIN, symmetric key material) | extra session, encrypt out | `seal.go:317`, `seal.go:427` |
| `TPM2_RSA_Decrypt`, `TPM2_ECDH_ZGen` | plaintext, shared secret | extra session, encrypt out | `rsa.go:308`, `ecdh.go:112` |
| `TPM2_ActivateCredential` | recovered credential | extra session, encrypt out | `attestation.go:614` |
| `TPM2_GetRandom` | key material | extra session, encrypt out | `random.go:88` |
| `TPM2_Sign`, `TPM2_Quote`, `TPM2_Certify`, `TPM2_CertifyCreation`, `TPM2_Load` | key or parent auth | salted HMAC or policy session | `CreateSession` `session.go:620`, `createKeySession` `session.go:808` |

`TPM2_NV_Extend` is not in go-tpm; `nvExtendExecute` (`nv_extend.go:38`)
marshals it by hand but computes and verifies its authorization through the
go-tpm `Session`, so it takes the same salted sessions as every other command.
`HashSequence` (`tpm.go:1847`) runs its sequence object under an empty auth
value: the ticket's hierarchy needs no authorization, and go-tpm cannot attach
a session to `TPM2_HashSequenceStart` (its response handle is untagged).

**Callers on a raw transport.** Three callers drive go-tpm on a transport of
their own rather than through a `TPM2`. They take the same session layer
through its transport-level entry points, which salt against the ephemeral
NULL-hierarchy key (a bare transport carries no EK configuration) and never
touch the EK or any SRK:

- `HierarchyAuthSession(t, hierarchy, auth)` (`session.go:291`) — the salted
  bound hierarchy session of `hierarchyAuthSession`, encrypting nothing; an
  empty auth is the empty password session.
- `CommandEncryptionSession(t)` (`session.go:306`) and
  `ResponseEncryptionSession(t)` (`session.go:317`) — the extra session of
  `encryptionSession`, encrypting the command's or the response's first
  parameter.

| Caller | Command | Secret | Protection | Site |
|---|---|---|---|---|
| `pkg/luks` `SealPassphrase` | `TPM2_Create` under the sealing parent | LUKS passphrase | extra session, encrypt in | `pkg/luks/tpm.go:241` |
| `pkg/luks` `UnsealPassphrase` | `TPM2_Unseal` (PCR policy session) | LUKS passphrase | extra session, encrypt out | `pkg/luks/tpm.go:355` |
| `pkg/storage/hardware` `TPM2CertStorage` | `TPM2_NV_DefineSpace`, `TPM2_NV_Write`, `TPM2_NV_Read`, `TPM2_NV_UndefineSpace` | owner auth (SO PIN) | salted bound session | `ownerAuthSession`, `pkg/storage/hardware/tpm2_cert_storage.go:681` |
| `pkg/backend/tpm2` `UnwrapKey` | `TPM2_Unseal` of the imported object | unwrapped key material | extra session, encrypt out | `pkg/backend/tpm2/importexport.go:423` |

`pkg/luks` opens its own transport per operation (`TPMOpener`) and hands it
to the entry points; its sealing parent and PCR policy are unchanged. The
certificate NV indexes hold public certificates under an empty index auth,
so their data is not encrypted — only the SO PIN needed protecting.

## Symmetric keys

`GenerateSymmetricKey`, `GetSymmetricKey` and `SymmetricEncrypter`
(`pkg/tpm2/symmetric.go:98`, `:211`, `:278`) back the `types.SymmetricKeyProvider`
of `pkg/backend/tpm2` (`backend.go:960`, `:1006`) and the PKCS#11 `C_DeriveKey`
path (`pkg/tpm2/kdf.go:57`). The AES key (128 or 256 bits) is generated in Go,
sealed in the TPM as a keyed-hash object, and unsealed for every `Encrypt`,
`Decrypt` and derivation; AES-GCM itself runs in Go (`pkg/crypto/aead`).

**Storage is the seal path.** A symmetric key is created by `sealKeyInternal`
(`seal.go:24`) and unsealed by `unsealKeyInternal` (`seal.go:250`), the path
every other secret sealed under the Platform SRK takes; `symmetric.go` adds no
session or policy code of its own:

- **Parent: the Platform SRK, only.** `symmetricSealAttrs`
  (`symmetric.go:169`) takes `attrs.Parent`, or the Platform SRK's own
  attributes when none is named, and refuses any parent whose handle is not
  `platformSRKHandle` (`platform_keystore.go:599`) with
  `ErrSymmetricKeyParent`. The Shared SRK is never a parent.
- **Parent authorization: USER PIN or platform policy.** `TPM2_Create` and
  `TPM2_Load` are authorized by `CreateSession` (`session.go:523`): with
  `Parent.Password` set, the salted USER PIN session (the `PolicyAuthValue`
  branch when the Platform SRK carries the platform policy); without it, the
  PCR branch. Nobody without the PIN, or without the measured platform state,
  can load the key.
- **Object authorization, as for every sealed object.** The object's
  `userAuth` is `attrs.Password`; with a policy its `authPolicy` is that
  policy and `userWithAuth` is clear, and `TPM2_Unseal` is authorized by
  `objectSession` — see §"Object authorization". Unlike `SealKey`, a
  symmetric key may carry neither a policy nor a password: its use is gated by
  the Platform SRK at `TPM2_Load`. The template is always `KeyedHashTemplate`;
  a caller's `TPMAttributes` is dropped.
- **DA protection.** `NoDA` is clear, as on every sealed object and on the
  Platform SRK itself (`enableDAOnSRK`, `platform_keystore.go:652`): a wrong
  object password advances the lockout counter.
- **Bus.** The key material enters under an `encryptIn` session
  (`seal.go:138`) and leaves under an `encryptOut` session (`seal.go:315`),
  both salted. It never crosses the TPM bus in plaintext.

Blobs are `<CN>.blob`, `<CN>.pub` and, for a platform-policy key,
`<CN>.policy`, the same files `DeleteKey` removes.

**Keys written before this rule.** Earlier releases parented symmetric keys
on the Shared SRK with no authorization and `NoDA` set, and stored them as
`<CN>.priv` plus a size-prefixed `<CN>.pub`. They are not migrated.
`GetSymmetricKey` recognises that public area (`unprotectedSymmetricKeyBlob`,
`symmetric.go:552`) and returns `ErrUnprotectedSymmetricKey`, whose detail
names the exact `<CN>.priv` file to remove (`symmetric.go:241`).

`FileBackend.Delete` (`store/file_backend.go:95`) includes
`FSEXT_LEGACY_PRIVATE_BLOB` (`.priv`, `store/interfaces.go:51`) in the
extensions it removes, so a `<CN>.priv` blob is cleaned up whenever `Delete`
runs for that CN. It cannot run there on its own: `DeleteKey` for a sealed
object first calls `UnsealKey` to prove the caller owns the key
(`key.go:1775`), and `UnsealKey` loads the private blob from
`FSEXT_PRIVATE_BLOB` (`.blob`) — a pre-#1148 key has no such file, so the
load fails before `DeleteKey` ever reaches the delete step. A pre-#1148 key
is therefore never removable through `DeleteKey`/`DeleteKeyPair`; an operator
who hits `ErrUnprotectedSymmetricKey` deletes the named `<CN>.priv` (and its
`<CN>.pub`) from the TPM2 key directory by hand — see
[`user.md`](user.md)'s "Legacy symmetric key cleanup" for the exact steps.
There is no scanning command that finds these files automatically; adding
one is a future decision, not part of this fix (go-xkms#1168).

**Why not `TPM2_EncryptDecrypt2`.** A TPM-resident `TPM_ALG_SYMCIPHER` key
would never leave the TPM, but the command offers CFB, CBC, ECB, CTR and OFB
only; no mode is authenticated. GCM could be composed from TPM CTR plus a Go
GHASH, at the cost of exposing the hash subkey `H` to the host, of a
composition that is not a FIPS-validated GCM, and of a TPM round trip per
1 KiB (`MAX_DIGEST_BUFFER`). The command is also optional in the PC Client
profile and absent on some firmware TPMs. It is feasible later as an opt-in
for small payloads, behind a `TPM2_GetCapability(TPM_CAP_COMMANDS)` check,
not as the default.

Tests: `symmetric_psrk_simulator_test.go` covers the USER PIN round trip, a
missing or wrong PIN (`TPM_RC_AUTH_FAIL`), both platform-policy branches (a
moved PCR refuses the PCR branch with `TPM_RC_POLICY_FAIL`; the PIN branch
survives), the object's own password, the Platform SRK as the parent handle
of every `TPM2_Create` and `TPM2_Load`, the refusal of a Shared SRK parent and
of a pre-rule blob. The #1147 bus recorder asserts that neither the AES key
nor the PIN appears in any command or response.

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
| `ErrSymmetricKeyParent` | a symmetric key was asked to live under a parent other than the Platform SRK, or no Platform SRK is available. Nothing is created or loaded |
| `ErrUnprotectedSymmetricKey` | the stored symmetric key predates the Platform SRK rule (Shared SRK parent, no authorization, `NoDA`). It is refused, never loaded; delete and regenerate it |
| `ErrPCRDataTooLarge` | encoded PCR banks over 64 KiB, refused by `DecodePCRs` before gob decodes them (`pkg/tpm2/encoding.go:74`) |
| `ErrInvalidPCRData` | decoded PCR banks no TPM reports: more than 8 banks, more than 24 PCRs in a bank, an index outside 0..23, or a value longer than 64 bytes (`validatePCRBanks`, `pkg/tpm2/encoding.go:91`) |
| `ErrECCPublicArea` | the ECC public area does not yield a valid public key: bad parameters, an unknown curve, or a point that is not on the curve. On the `TPM2_Certify` path it is wrapped as `ErrCertifyMalformed`; the underlying `ecpoint.ErrInvalidPoint` stays reachable through `errors.Is` |
| `ErrAdminWithPolicyNoAuthPolicy` | the template about to be created from sets `adminWithPolicy` while naming no `authPolicy`, so the object's ADMIN role would be unauthorizable by anything. Raised by `assertAdminAuthorizable` before `TPM2_CreatePrimary`; nothing is created |
| `ErrDevIDTemplateNonConformant` | the IDevID or IAK template about to be created from departs from TCG Templates H-0 through H-4 in an attribute, its `authPolicy`, its `unique` string, its scheme, its symmetric definition, its exponent, its KDF or its curve. Raised by `assertDevIDTemplateConformant` before `TPM2_CreatePrimary`; nothing is created |
| `ErrDevIDUniqueString` | a `unique` string that is not §7.3.1 Table 2's, or a `tpm.device-string` that is not printable ASCII |
| `ErrDevIDUniqueStringTooLong` | the required string plus the device string exceeds the crypto suite's `unique` field |
| `ErrDevIDTemplateSuiteUnsupported` | a crypto suite the specification defines no template for: a `nameAlg` with no Policy NV Index, or a scheme H-1 does not allow for the key's purpose |
| `ErrDevIDPolicyUnsupported` | a key kind or `nameAlg` for which the specification defines no template or Policy NV Index (only SHA256, SHA384 and SHA512 are defined) |
| `ErrDevIDPolicyDigestCompute` | the trial-policy computation of a key policy or NV Index Name failed inside go-tpm |
| `ErrDevIDPolicySession` | a key policy session could not be built: a command with no branch in the key policy, a `PolicySecret` refused for a wrong endorsement auth, a delegation in another hash algorithm or with nothing to satisfy, or a TPM refusal of a policy step — the step is named and the TPM response code stays in the chain (`TPM_RC_VALUE` at `PolicyAuthorizeNV` is "the index holds a different policy"; at `PolicyPCR`, "the platform moved") |
| `ErrDevIDPolicyNVIndex` | the Policy NV Index exists with a public area other than Template I-0/I-1..I-3, so its Name is not Table 18's and nothing written into it can delegate the key. Raised by `DefineDevIDPolicyNV` and `WriteDevIDDelegationPolicy`; nothing is written |
| `ErrDevIDDelegation` | the TPM refused to define the index (wrong Owner auth, NV exhausted) or to write it (wrong endorsement auth, index not defined) |
| `ErrDevIDCNUnresolved` | neither `cn` nor both a device model and serial number were available to name an IDevID or IAK |
| `store.ErrEmptyKeyCN` | a key-store operation was attempted with an empty CN, which would compose a storage key of the bare extension |
| `ErrDevIDProvisionEKCert` | `Install` was asked for an IDevID and the EK certificate could not be read from NV RAM or the certificate store. The TCG-CSR-IDEVID carries it (§6.2.2 step 4b) and the CA verifies it (step 6b); without it the ceremony cannot complete and no key is minted. The cause (`ErrEndorsementCertNotFound`, a TPM error) is reachable through `errors.Is` |
| `ErrDevIDProvisionIDevID`, `ErrDevIDProvisionIAK` | `CreateIDevID` / `CreateIAK` failed during `Install`. Previously the IDevID failure was logged as "continuing without it" and `Install` returned nil |
| `ErrDevIDProvisionLookup` | reading the IDevID or IAK persistent handle answered something other than TPM_RC_HANDLE. Only that code means "absent, create it"; anything else — a transport fault, a lockout — is a fault and is not treated as a provisioned key |
| `ErrTCGCSRAttestation` | the TPM refused the quote that fills the CSR's `prodCaData`. Absence — no transport to quote over — is still an absent field (`prodCaDataSz` 0), which §13.1 allows; a refusal is not |
| `ErrTCGCSRPad` | the TPM's RNG could not supply the §13.1 random pad |
| `ErrEKCertServiceUnreachable` | `EKConfig.CertDownload` is `true` and the manufacturer EK certificate service request (`downloadEKCertFromManufacturer`) failed to connect, timed out, or answered a non-200 status. The underlying transport error — including a context-deadline timeout — is reachable as detail through `errors.Is` |
| `ErrEKCertServiceParseFailed` | the manufacturer EK certificate service answered 200 but the body was neither valid DER nor PEM `x509.Certificate` bytes |
| `ErrSaltKey` | no key could be resolved to salt a session against: reading the EK failed for a reason other than an absent handle, or the ephemeral NULL-hierarchy key could not be created. No unsalted session is started in its place |
| `ErrSaltedSession` | `TPM2_StartAuthSession` for a salted session failed; the TPM or transport error stays in the chain |
| `ErrProvisioningStateRead` | `State` could not compute the live platform policy digest needed for `PlatformSRKPolicyCurrent` |
| `ErrClearLockoutRefused`, `ErrClearPlatformRefused` | `ClearForReprovision`'s LOCKOUT or PLATFORM `TPM2_Clear` attempt was refused; logged, then the next path is tried |
| `ErrForceClear` | the PPI sysfs write (`ForceClear`, the seam `ppiRequestWriter`) failed |
| `ErrCredentialChallenge` | `NewCredentialChallenge` or `ActivationKeyName` failed converting the EK public key, importing it as an encapsulation key, or unmarshalling/naming a public area |
| `ErrEKPublicRequired`, `ErrActivationKeyNameRequired` | `NewCredentialChallenge` was called with a nil EK public key or an empty activation key Name |
| `ErrActivationKeyCreate` | `CreateActivationKey`'s `TPM2_CreatePrimary` (null hierarchy) failed |
| `ErrActivationKeyRequired`, `ErrCredentialChallengeRequired` | `AnswerCredentialChallenge` was called with a nil `*ActivationKey` or `*CredentialChallenge` |
| `ErrEKCertNotInNV` | `AnswerCredentialChallenge` found no persistent EK and could not read an EK certificate from NV |
| `ErrEKTemplateUnsupported` | the NV EK certificate is in the high range, or its key is neither RSA-2048 nor ECC P-256, so no transient EK template matches it |
| `ErrEKPublicKeyMismatch` | the transient EK's public key is not the key the NV EK certificate certifies; the EK is flushed and the challenge refused |

**Fail closed:** every one of these refuses. Nothing degrades to a software key
or an unverified acceptance.

## TCG-CSR-IDEVID wire structure

`CreateTCG_CSR_IDEVID` (`idevid_csr.go`) emits the §13.1 structure:
`TCG_CSR_IDEVID.structVer` = `TCGCSRIDevIDStructVer` (`0x01000100`, the
leading `0x01` identifies an IDevID CSR; §13.2's LDevID CSR carries `0x02`),
`contents` = the byte length of `csrContents`, `sigSz` = the signature length;
`csrContents.structVer` = `TCGIDevIDContentStructVer` (`0x00000100`),
`hashAlgoId` and `hashSz` = the **signer's** hash (the IAK under
`EnrollmentStrategyIAK`, the IDevID under single-pass — the algorithm
`HashSequence` digests the contents with and the one the CA re-hashes with),
twelve four-byte payload sizes in the specification's order, `padSz`, the
payloads with no delimiters, then `padSz` bytes of random data from the TPM's
RNG bringing the structure to a multiple of `TCGCSRAlignment` (16) when
`idevid.pad` is set. The signature is over the packed `csrContents` bytes.

Two departures remain and are recorded, not hidden: §13.1 describes the
signature as "DER encoded ... including algorithm ID" while the CSR's own
top-level signature (`TCG_CSR_IDEVID.signature`, over the packed
`csrContents` bytes, checked by `verifyRSASignatureStateless` /
`verifyECDSASignatureStateless` in `tcg_csr_serverside.go`) carries the raw
TPM signature instead — PKCS#1 v1.5 / PSS bytes for RSA, ASN.1 `r,s` for
ECDSA (`SignValidate`, `tpm.go:1926`) — changing it changes every verifier in
`pkg/ca` and `pkg/acme`; and `idevid.pad=false` emits an unpadded structure
the specification's typedef does not describe. `UnmarshalIDevIDCSR` accepts
both structure versions so a CA on this release still enrolls a device on
the previous one.

The two certification signatures carried *inside* `csrContents` —
`atCertifyInfoSignature` (the IAK's own `TPM2_CertifyCreation`) and
`sgnCertifyInfoSignature` (the IAK's `TPM2_Certify` of the IDevID) — are a
third, narrower departure from §13.1's "DER encoded" text, and are not ASN.1
at all for either key type: PKCS#1 v1.5 / PSS bytes for RSA, and for ECDSA
the raw `r‖s` pair, each component left-padded to the attesting key's curve
field size (32/48/66 bytes for P-256/P-384/P-521). `CreateIAK` and
`CreateIDevID` (`key.go:865`, ECDSA branch at `key.go:1115`; `key.go:1441`,
ECDSA branch at `key.go:1753`) pack it through the shared
`packRawECDSASignature` (`eccpub.go:78`); `VerifyCertifyRaw`'s
`signatureFromScheme` (`certify_verify.go:334`) is the one place that parses
it back, by splitting the buffer exactly in half — so it, not §13.1, is the
format's normative definition. Before #1182 the ECDSA branches of `CreateIAK`
and `CreateIDevID` packed ASN.1 DER here instead, which no verifier —
including `signatureFromScheme` itself — could parse; an RSA IAK or IDevID
was never affected, and the outer CSR signature above was never affected
either, since it is a separate field checked by a separate, DER-aware
verifier.

**Parsing is bounded by the input, not by the length fields.** A
TCG-CSR-IDEVID reaches the CA from the network -- the `enroll-01` challenge
response and ACME finalize (`pkg/acme/server/handlers/order_finalize.go`) --
and carries fifteen attacker-chosen 32-bit lengths.
`UnmarshalIDevIDCSR` (`pkg/tpm2/idevid_csr.go:656`) refuses input over
`MaxIDevIDCSRSize` (1 MiB, `idevid_csr.go:35`) with
`*IDevIDCSRTooLargeError`, and every variable-length field, the signature
included, is read by `readSizedField` (`idevid_csr.go:822`), which compares
the declared length with the bytes remaining **before** `make` and returns
`*IDevIDCSRFieldSizeError{Field, Declared, Remaining}` (it wraps
`io.ErrUnexpectedEOF`) when it does not fit. `UnpackIDevIDContent`
(`idevid_csr.go:702`) applies the same bound to a caller's reader.
`UnpackIDevIDCSR` (`idevid_csr.go:849`), whose size fields and data slices
are independent struct fields, copies through `copySizedField`
(`idevid_csr.go:839`): a size larger than its slice is `store.ErrCorruptCopy`
before the buffer is allocated. `ParseEventLog` bounds each event's data at
`MaxEventDataSize` (`pkg/tpm2/eventlog.go:38`, `*EventDataTooLargeError`).
`UnpackProdCaData` (`prodcadata.go`) already checked the sum of its four
lengths against the input before allocating. Regression and fuzz coverage:
`pkg/tpm2/idevid_csr_bounds_test.go` (`FuzzUnmarshalIDevIDCSR`), go-xkms#1172.

## Configuration

`pkg/tpm2/config.go`. The settings that change behaviour:

- **Device path**, or simulator host/port. In the shipped configs the simulator
  is addressed as `simulator_host` / `simulator_port` (default `2321`) — **not**
  as `device_path`. A `tcp://host:port` string in `device_path` names a file
  that does not exist; `Config.ToTPMConfig` maps the simulator fields to
  `CommandAddress` and clears the device path. The integration config
  (`configs/xkmsd-integration.yaml`) documents this at length because it has
  cost time before.
- **Hierarchy authorizations** — endorsement, lockout, owner. Platform-held,
  never stored in configuration and never defaulted to a fixed password.
  `EKConfig` and `SRKConfig` carry a `HierarchyAuth types.SecretValue` field
  used only as the *current* auth `Install` transitions away from (never as
  a substitute for the live `soPIN` argument); `PlatformSRKConfig` carries no
  hierarchy-auth field at all. When no SO PIN has been set the Owner
  hierarchy carries empty auth — the TCG factory-default state. When one has
  been set, it reaches `TPM2_CreatePrimary`/`TPM2_EvictControl` only as the
  `soPIN` argument threaded through `Install`/`Provision`/`ProvisionOwner`
  (Shared SRK) or through
  `PlatformKeyStore.Initialize`/`EnrollPlatformSRK`/`ensureSRKAuth` (Platform
  SRK) at the moment of the call — see [`architecture.md`](architecture.md)
  §"Trust boundaries" for why the two keys' calls are never conflated.
  `PlatformSRKAttributesFromConfig` builds the Platform SRK from the SSRK
  config's algorithm and key parameters only, and always leaves
  `TPMAttributes.HierarchyAuth` empty. The Platform SRK's own authorization
  value — its `Password`, distinct from the owner-hierarchy auth — is the
  user PIN, supplied the same way, never a config literal.
  `pkg/backend/tpm2`, which uses the Platform SRK as its own working key, has
  no hierarchy-auth field of its own and routes through the `pkgtpm2.Config`
  it builds (or a caller-supplied one via `Config.TPMConfig`) instead of
  duplicating one, and never falls back to the Shared SRK when the Platform
  SRK is unavailable.
- **`idevid.platform-policy` / `iak.platform-policy`** — provisions the key's
  Policy NV Index with the platform Delegation Policy (see Invariants). The
  default configuration sets it on the IDevID. It does not alter the key.
- **PCR selection and policy** — named TPM policies in `pkg/tpm2/policy` ([`../tpm-policies/`](../tpm-policies/)) and `pcr.go`.
- **Platform PCR** (`platform-pcr`, backend `platform_pcr`) — the PCR the
  golden measurement is extended into and every platform policy is computed
  over. Unset (zero) means `DefaultPlatformPCR` (16) on every path: the
  library `DefaultConfig`, `pkg/backend/tpm2.Config.Validate` (xkmsd's
  `backends.tpm2`, node-seal and platform-store opens), and xKey's CLI and
  GUI. It never means PCR 0, the firmware PCR. An unset bank means
  `PCRBankSHA256`. Before 2026-09-29, xkmsd left an unset `platform_pcr` at 0
  while xKey used 16, so the two computed different platform policies on one
  TPM.
- **Session encryption** — not configurable. Every secret crosses the TPM bus
  encrypted, always; the `encrypt-sessions` / `EncryptSession` switch was
  removed (#1147). See [Bus protection](#bus-protection).
- **`Debug`** (`EKConfig`, `IAKConfig`, `IDevIDConfig`, `SRKConfig` — each
  carries its own field) — defaults to `false` for every key type
  (`pkg/tpm2/config.go:91,109,120,141`). It gates non-secret diagnostic
  logging only: `PlatformPassword.Bytes`'s cache-hit/unseal-attempt log
  lines (`pkg/tpm2/password.go:121,168`) and
  `store.DebugKeyAttributes`'s attribute dump
  (`pkg/tpm2/store/helpers.go:65-78`), neither of which ever logs a secret
  value. Before the 2026-09-28 crypto audit it also defaulted to `true` for
  EK/IAK/IDevID/SSRK and gated a "Secrets" block in
  `types.KeyAttributes.String()` that printed `Password` and `SealData`
  verbatim; that block is gone regardless of `Debug` — see
  `docs/key-management/engineering.md`.
- **`ek.cert-download`** (`EKConfig.CertDownload`, default `false`) — opts in
  to downloading the EK certificate from the TPM manufacturer's EK
  certificate service (`https://ekop.intel.com/ekcertservice/` by default)
  when `EKCertificate` finds no certificate in NV RAM or the certificate
  store. **Off by default**: with it `false`, `EKCertificate` returns
  `ErrEndorsementCertNotFound` as soon as the local lookups are exhausted and
  makes no outbound network call — an air-gapped host never blocks on it
  (#761). `ek.cert-download-url` overrides the compiled-in endpoint (must be
  `https://`); `ek.cert-download-timeout` bounds the request
  (`DefaultEKCertDownloadTimeout`, 10s, when unset). The request is bounded
  through its context regardless of which `*http.Client` serves it
  (`Params.HTTPClient` overrides the client for tests; production uses
  `http.DefaultClient`).

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
  where the specification prints them, and the example Delegation Policies
  "with leading HASH ID" to Table 20 (whose row labels abbreviate: the values
  are the `PolicyOR`s of Figures 10 and 11). go-tpm's `PolicyUpdate` and the
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
  Delegation Policy NV (`devid_delegation_simulator_test.go` — defines the
  index, checks its Name against Table 18, writes Table 20's policy, signs
  through `TPM2_PolicyAuthorizeNV`, and proves a foreign index, a wrong
  authorization, a replaced policy and a moved platform are each refused),
  device identity key derivation (`devid_template_simulator_test.go` --
  measures that `unique` changes the created key's Name, that every shipped
  suite creates and that no two suites derive the same key, that H-2's
  `scheme->details = NULL` is refused by the TPM, and that the key
  `CreateIDevID` persists is the one `DevIDTemplateSpec` derives),
  seal-with-PCR-policy, SSRK platform policy,
  capabilities, PIN enrollment, the §13.1 wire structure
  (`tcg_csr_structure_simulator_test.go` — a reader written from the
  specification's field list, independent of the packer, checks every
  version, size prefix, payload order, the pad and the signature of a CSR the
  device actually built) and provisioning fail-closed
  (`devid_provision_simulator_test.go` — `Install` with an IDevID configured
  and no EK certificate, a transport fault on the lookup, and a fault on
  `TPM2_CreatePrimary`, each of which returned nil before).
- **EK certificate download** (`ek_cert_download_simulator_test.go`) — proves
  `EKConfig.CertDownload=false` (the default) makes `EKCertificate` return
  `ErrEndorsementCertNotFound` without any HTTP call (an injected
  `RoundTripper` fails the test if invoked); with it `true`, an `httptest`
  TLS server stands in for the manufacturer service for a successful
  DER/PEM download, a request that exceeds `CertDownloadTimeout`
  (`ErrEKCertServiceUnreachable`, bounded rather than blocking), and a
  malformed response (`ErrEKCertServiceParseFailed`).
- **Bus capture** (`session_encryption_simulator_test.go`) — routes the TPM
  through a recording transport and, for provisioning with an SO PIN, PSRK
  creation, sealing and unsealing through both the PIN and the PCR branch, an
  NV secret under owner auth and `TPM2_GetRandom`, asserts that the plaintext
  PIN or secret appears in no command and no response, that each
  secret-bearing command carries a session with the decrypt or encrypt
  attribute, and that the sessions authorizing it are salted. The recorder
  copies each command before forwarding it: the in-process simulator decrypts
  an encrypted parameter in place, in the buffer it is handed. The same file
  covers `saltKey` with no EK resident and with a failing transport. The
  recorder is `pkg/tpm2/tpm2test/tpmbus`, which imports nothing from go-xkms
  so the raw-transport callers use it too:
  `session_transport_simulator_test.go` (the transport-level entry points,
  including a salt key the TPM refuses to flush),
  `pkg/luks/tpm_bus_simulator_test.go`,
  `pkg/storage/hardware/tpm2_cert_storage_bus_test.go` and
  `pkg/backend/tpm2/importexport_bus_sim_test.go`. The
  integration counterpart, `test/integration/tpm2/capture_test.go`, runs the
  same kind of capture against the devcontainer's networked simulator
  (`make test-tpm2-encryption`, or `make test-tpm2-encryption-local` against a
  local simulator).
- **Leak suites** — object contexts, auth sessions, auth sessions under
  transport fault, general resources. These are the regression guard for the
  package's hardest rule.
- **Regression fixtures** — `loadkeypair_delete_regression_simulator_test.go`,
  `left_alone_fixes_test.go` keep specific past bugs from returning.
  `provision_test.go` has two tests that keep the FactoryReset handle-table
  fix (go-xkms#798) from regressing. `TestFactoryReset_IAKAtLegacyECCHandle_Evicted`:
  an IAK at 0x81010002 (this package's default IAK handle, which is also the
  TCG ECC EK address) is evicted. `TestFactoryReset_ForeignObjectAtTCGECCEKHandle_Preserved`:
  an object at that address that the configuration does not own, such as a
  manufacturer ECC EK, is kept. `factoryResetInternal` preserves both TCG EK
  addresses and `Config.EK.Handle`, minus the handles the configuration owns
  (`ownedPersistentHandles`: IAK, IDevID, Platform SRK).
- **Provisioning state / reprovisioning / credential challenge** —
  `provisioning_state_simulator_test.go` (`State` on a fresh, provisioned and
  owned TPM, and the one real failure surface reached through a
  command-selective fault injection), `clear_for_reprovision_simulator_test.go`
  (`ClearForReprovision` on all three paths, the PPI path through its
  injectable seam, never the host's sysfs), `credential_challenge_test.go`
  (the pure-software half: building and naming a challenge, no simulator
  needed) and `activation_key_simulator_test.go` (the full device round
  trip, including that a challenge built against one EK or one activation
  key's Name cannot be answered by a different EK or a different key on the
  same TPM, and that the software-built challenge is answered correctly by
  the real IAK-bound `ActivateCredential` path enroll-01 and `pkg/ca` use).
- **Harness** — `simharness_simulator_test.go`.
- **Integration** — `test/integration/tpm2`, `test/integration/acme-tpm`.

Hardware runs need a real TPM; the simulator covers everything else, one client
at a time.

**Running it.** `make test` greps `pkg/tpm2` out of its package list, so the
package has its own targets: `make test-tpm2-simulator` (the whole package
under `codec_cbor codec_json codec_msgpack tpm_simulator`, bounded at
`TPM2_SIMULATOR_TIMEOUT`, default 20 minutes, against a run of about 90
seconds on a workstation), `make coverage-tpm2-simulator` (mocks and tests
excluded from the profile) and `make bench-tpm2-simulator`. The CI job
`tpm2-simulator` runs the first on every push and pull request; the simulator
is cgo and links `-lcrypto`, so the job installs `libssl-dev`.

## Observability

TPM operations log with the correlation ID. Two things are worth logging
explicitly at startup because they are invisible otherwise: which device or
simulator was opened, and the current lockout state. A deployment silently on a
simulator, or one whose TPM is in lockout, looks identical to a healthy one
until the first operation fails.
