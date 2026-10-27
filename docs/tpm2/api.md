# TPM 2.0 — API

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-10-13

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## The TPM has no transport surface of its own, deliberately

`pkg/tpm2` is a device library. It talks to hardware attached to the machine it
runs on, and exposing "run this TPM command" as an RPC would hand remote callers
the platform's root of trust.

What appears on the wire is the *result* of TPM work, through the features that
use it. Each row below links to the feature that owns it.

| Capability that uses the TPM | Where it is documented |
|---|---|
| Keys in the TPM, and `AttestKey` | [`../key-management/api.md`](../key-management/api.md) |
| `Seal` / `Unseal` / `CanSeal` with PCR binding | [`../sealing-and-barrier/api.md`](../sealing-and-barrier/api.md) |
| Barrier under the `tpm2` strategy | [`../sealing-and-barrier/api.md`](../sealing-and-barrier/api.md) |
| PIN operations on the TPM2 backend | [`../pin-management/api.md`](../pin-management/api.md) |
| PIV certificates in TPM NV | [`../piv-smartcard/api.md`](../piv-smartcard/api.md) |
| EK / AK certificate issuance, TCG CSR, device enrollment | [`../certificate-authority/api.md`](../certificate-authority/api.md) |
| `enroll-01` attested ACME enrollment | [`../acme-issuance/api.md`](../acme-issuance/api.md) |
| Backend capabilities (`HardwareBacked`, `Attestation`, `SecurityLevel: 3`) | [`../crypto-backends/api.md`](../crypto-backends/api.md) |

## Device identity key authorization

The IDevID and IAK are created to TCG *TPM 2.0 Keys for Device Identity and
Attestation* v1.00 r12, Template H-0 over the H-1 through H-4 crypto suites
(`pkg/tpm2/devid_template.go`), and carry the specification's IDevID/IAK Key
Policy as their `authPolicy` (`pkg/tpm2/devid_policy.go`).
The authValue may **use** the key; only the policy may **administer** it
(§7.2.4). The surface an integrator can reach:

| Symbol | What it is |
|---|---|
| `DevIDKeyKind` · `DevIDKeySigning` / `DevIDKeyAttestation` | which key: the Unrestricted IDevID or the Restricted IAK. They differ only in the Policy NV Index their DelegationNV branch is bound to |
| `DevIDKeyPolicyDigest(kind, nameAlg)` | the §7.3.6.6 `PolicyOR` digest assigned as `authPolicy`. Pinned to Tables 14–19 of the specification; computable offline |
| `DevIDKeyPolicyBranches(kind, nameAlg)` | the four constituent digests, in the order `TPM2_PolicyOR` must receive them |
| `DevIDPolicyNVIndex` / `DevIDPolicyNVPublic` / `DevIDPolicyNVName` | the reserved Policy NV Index (§7.3.2), its Template I-1..I-3 public area, and its Name (§7.3.6.5) |
| `(*TPM2).DevIDAdminSession(kind, nameAlg, command, endorsementAuth)` | the policy session that authorizes the ADMIN role for exactly one command — `TPM_CC_Certify` or `TPM_CC_ActivateCredential` — as the Privacy Administrator. Any other command is refused before a session is opened; the TPM answers `TPM_RC_POLICY_CC` if the session is used for a command it was not built for |
| `(*TPM2).DefineDevIDPolicyNV(kind, nameAlg, ownerAuth)` | defines the key kind's Policy NV Index to Template I-0/I-1..I-3 under Owner authorization (§7.3.5). Idempotent; an existing index with any other Name is refused with `ErrDevIDPolicyNVIndex` |
| `(*TPM2).WriteDevIDDelegationPolicy(kind, nameAlg, policyDigest, endorsementAuth)` | writes a Delegation Policy into the index as the Privacy Administrator (§7.2.4), as a `TPMT_HA`. Replaces whatever the index held |
| `(*TPM2).DevIDDelegatedSession(kind, nameAlg, delegation)` | the USER-role session of a delegated entity (§7.3): satisfies the delegation, `TPM2_PolicyAuthorizeNV`, `PolicyOR`. Refused, with the TPM's code in the chain, when the index holds a different policy or the delegation's assertions fail |
| `DevIDDelegation` · `DevIDCommandDelegation(nameAlg, command, allowed...)` · `DevIDSigningDelegation` · `DevIDAttestationDelegation` | a Delegation Policy as its digest plus the assertions that reach it. The two named ones are the specification's examples (§7.3.7, Table 20): Sign + Certify; Quote + GetSessionAuditDigest + Certify + ActivateCredential |
| `(*TPM2).DevIDPlatformDelegation(nameAlg)` | `TPM2_PolicyPCR` over the platform PCR at its current value — what `platform-policy` on an IDevID/IAK provisions into the index |
| `DevIDDelegationPolicyPayload(nameAlg, digest)` | the bytes the index stores: hash algorithm ID, then digest (§7.3.5 NOTE) |
| `DevIDCommonName(cn, platform)` | the one naming rule for both keys: explicit `cn`, else `model-serial`, else `ErrDevIDCNUnresolved` |
| `DevIDTemplateSpec` · `.Template()` | builds the §7.3.4 creation template for a crypto suite: H-1 RSA, H-2 P-256, H-3 P-384, H-4 P-521. `Kind` picks IDevID or IAK, `DeviceString` supplies the optional §7.3.1 per-device string. `authPolicy` is left empty; the creation path assigns it per `nameAlg` |
| `DevIDUniqueString(kind, deviceString)` | the §7.3.1 Table 2 `unique` bytes: `'IDEVID'` or `'IAK'`, unpadded and not NUL terminated, followed by the printable-ASCII device string |
| `DevIDUniqueIDevID` / `DevIDUniqueIAK` | those two required strings |
| `RSASSAAKTemplate`, `RSAPSSAKTemplate`, `ECCAKP256Template`, `ECCAKP384Template`, `ECCAKP521Template`, `RSASSAIDevIDTemplate`, `RSAPSSIDevIDTemplate`, `ECCIDevIDP256Template`, `ECCIDevIDP384Template`, `ECCIDevIDP521Template` | the suites as package values, built by `DevIDTemplateSpec` with no device string |

`CreateIDevID` and `CreateIAK` call the policy computation themselves and,
when the key's configuration sets `platform-policy`, define and write its
Policy NV Index with the platform delegation. The functions are exported so a
verifier or an out-of-process provisioner can reproduce the policy a device
*should* carry and compare it to the public area the device presents, and so
a device Owner can define the index and write a Delegation Policy of their
own after provisioning. Re-exported through `sdk/go` with a
`TPM`/`TPMDevID` prefix; the `*TPM2` methods are reached on the backend.

Errors: `ErrDevIDTemplateNonConformant`, `ErrDevIDUniqueString`,
`ErrDevIDUniqueStringTooLong`, `ErrDevIDTemplateSuiteUnsupported`,
`ErrDevIDPolicyUnsupported`, `ErrDevIDPolicyDigestCompute`,
`ErrDevIDPolicySession`, `ErrDevIDPolicyNVIndex`, `ErrDevIDDelegation`,
`ErrDevIDCNUnresolved`
(`pkg/tpm2`); `ErrEmptyKeyCN` (`pkg/tpm2/store`). All refuse; nothing degrades.

## Provisioning state, reprovisioning, and an EK credential challenge without a TPM

Added for go-trusted-platform's own installer/orchestration use
(go-xkms#798); re-exported through `sdk/go` unchanged (all four are type
aliases or direct function re-exports, so new `TrustedPlatformModule`
methods and new package functions appear automatically).

| Symbol | What it is |
|---|---|
| `(*TPM2).State() (*ProvisioningState, error)` | one classification: the TPMA_PERMANENT `ownerAuthSet`/`endorsementAuthSet`/`lockoutAuthSet` bits, which of EK/SSRK/IAK/IDevID/Platform SRK's configured persistent handles exist, and whether the Platform SRK's `authPolicy` equals the current `PlatformPolicyDigest` |
| `(*TPM2).ClearForReprovision() (rebootRequired bool, err error)` | `TPM2_Clear` via LOCKOUT, then PLATFORM, then UEFI PPI `ForceClear`; `rebootRequired` is true only for the PPI path. Replaces a consumer's private `TPM2_Clear`/PPI escalation |
| `NewCredentialChallenge(ekPub crypto.PublicKey, activationKeyName []byte) (*CredentialChallenge, secret []byte, error)` | builds a `TPM2_MakeCredential` challenge (`TPM2B_ID_OBJECT` + `TPM2B_ENCRYPTED_SECRET`) entirely in software; the caller needs no TPM |
| `ActivationKeyName(publicArea []byte) ([]byte, error)` | computes the TPM Name of a marshaled `TPMT_PUBLIC` a verifier received off the wire (a TCG-CSR-IDEVID's `AttestPub`, or an `ActivationKey.Public`), for use as `NewCredentialChallenge`'s `activationKeyName` |
| `(*TPM2).CreateActivationKey() (*ActivationKey, error)` | creates a transient, unrestricted signing key in the null hierarchy (no hierarchy auth), used only to answer a credential challenge before any persistent identity key exists |
| `(*TPM2).AnswerCredentialChallenge(key *ActivationKey, challenge *CredentialChallenge) ([]byte, error)` | answers a challenge using a `CreateActivationKey` object; generalises `ActivateCredential`'s hardcoded IAK path. Flushes the key when done. With no persistent EK it uses a transient EK recreated from the NV EK certificate's TCG template and verified against it |

`pkg/ca`'s `VerifyTCG_CSR_IDevIDBytes` (below) uses `NewCredentialChallenge` +
`ActivationKeyName` and no longer requires a TPM of its own; enroll-01's
device side (`ActivateCredential`) and `AnswerCredentialChallenge` share the
same `TPM2_ActivateCredential` mechanics under the hood.

## Writing the EK certificate

| Symbol | What it is |
|---|---|
| `(*TPM2).ProvisionEKCert(hierarchyAuth, ekCertDER []byte) error` | defines the EK certificate NV index under the owner hierarchy, authorized by `hierarchyAuth` (the SO PIN; nil when none is set), because `TPM2_NV_DefineSpace` takes only `TPM_RH_OWNER` or `TPM_RH_PLATFORM` (Part 3 §31.3.1). A TCG-default `EKConfig.CertHandle` is resolved by the EK's key type (TCG EK Credential Profile v2.1 §2.2.1.4): RSA 2048 `0x01C00002`, ECC P-256 `0x01C0000A`, P-384 `0x01C00016`, P-521 `0x01C00018`; any other EK is refused with `ErrEKCertKeyType`, and an operator-chosen index is used as configured. A rejected authorization is `ErrNVCertHierarchyAuth`. It writes the certificate in chunks of at most `TPM_PT_NV_BUFFER_MAX` bytes, so any certificate up to `TPM_PT_NV_INDEX_MAX` fits; an index that is already defined is refused with `ErrEKCertExists` and left untouched. With no `EKConfig.CertHandle` the certificate goes to the certificate store instead |
| `(*TPM2).ReplaceEKCert(hierarchyAuth, ekCertDER []byte) error` | replaces the certificate at the `EKConfig.CertHandle` index and no other. Everything that can be checked first is: a handle that is not an NV index or names a non-ordinary index (`ErrEKCertIndexInvalid`), an index the platform hierarchy created (`ErrEKCertPlatformIndex`), an empty or oversized certificate (`ErrNVCertEmpty`, `ErrNVCertTooLarge`) and DER that does not parse (`ErrInvalidEKCertFormat`) are refused with the stored certificate untouched. It then undefines the index under the owner hierarchy, which also proves `hierarchyAuth` (the owner authorization, whether or not a persistent EK exists), and redefines and writes it there as `ProvisionEKCert` does, so a repeated call behaves like the first. The EK itself is never touched. `xkey tpm ek restore --force` calls it, on the RSA 2048 index (`0x01C00002`), or on the ECC P-256 index (`0x01C0000A`) with `--ec` |
| `(*TPM2).ProvisionIDevIDCert` / `ProvisionIAKCert` / `ProvisionLAKCert(hierarchyAuth []byte, cert *x509.Certificate) error` | with a configured `CertHandle`, defines and writes the certificate's NV index under the owner hierarchy authorized by `hierarchyAuth` (the SO PIN; nil when none is set; Part 3 §31.3.1, §31.7.1); otherwise the certificate store takes it and ignores `hierarchyAuth`. An existing index with the certificate attributes is written again, or undefined and redefined when the size changes (§31.4.1), so a second provisioning does not fail with `TPM_RC_NV_DEFINED`. An index with any other attributes is refused with `ErrNVCertIndexMismatch` and left untouched, and a rejected authorization is `ErrNVCertHierarchyAuth`. `sdk/go` re-exports these errors and `ErrNVCertTooLarge` as `ErrTPMNVCert*` and `ErrTPMEKCertKeyType` |

## The one place TPM evidence crosses the wire

Attestation. Three surfaces carry it, and they are worth reading together
because they are the trust chain:

1. **`POST /api/v1/attest`** (`AttestKey`, `xkms.attestKey`) — evidence that a
   key was generated inside this TPM.
2. **`POST /api/v1/ca/tcg/{ek,ak,sign-csr,enroll}`** — the CA verifying a TCG
   CSR carrying an IDevID and issuing against it. `VerifyTCG_CSR_IDevIDBytes`
   returns `(blob, secret, plain)`; the blob is a `TPM2_MakeCredential` payload
   only the real TPM can activate.
3. **ACME `enroll-01`** — the same `MakeCredential`/`ActivateCredential`
   exchange, wrapped in RFC 8555 so standard tooling can drive it.

In all three the server never trusts an assertion: it encrypts a secret to the
endorsement key and requires the TPM to produce it. For (2) and (3), that
possession proof is not, by itself, provenance: before the CA generates the
`TPM2_MakeCredential` payload or issues an IAK/IDevID, it separately verifies
the EK certificate's chain against a configured TPM-manufacturer trust
anchor and its tcg-kp-EKCertificate extended key usage
(`verifyEKCertificateChain`, `pkg/ca/tcg_ek_trust.go`) — see
[`../certificate-authority/engineering.md`](../certificate-authority/engineering.md).

## Verification is client-side too

`pkg/attestation` (`verifier.go`, `invariants.go`, `truststore/`) is the
verification half, and it runs wherever the evidence is consumed. It checks the
EK chain against a configured manufacturer truststore, the AK's certification
against the EK, the quote signature, the nonce, and the PCR values against
expectation.

`pkg/attestation/android` covers the phone-as-HSM key type, whose attestation
format is Android's rather than TCG's — see the xkey phone documentation.

`pkg/attestation/peer` is the **attested-peer** verifier: given a quote a peer
produced with `TPM2.Quote`, its attestation-key certificate and the verifier's
own policy, it renders a per-check verdict with a typed cryptographic/absence
failure class, binding the quote to the TLS channel through the qualifying
data. It is what a transport gate calls to admit only a currently attested
caller — see [`docs/attested-peer/`](../attested-peer/architecture.md).

## Status and error mapping

Where TPM conditions surface on a transport, through the owning feature:

| Condition | REST | gRPC / Unix |
|---|---|---|
| TPM absent or unreachable | 503 | `Unavailable` |
| TPM in dictionary-attack lockout | 423 | `FailedPrecondition` |
| PCR mismatch on unseal | 409 | `FailedPrecondition` |
| NV space exhausted | 507 | `ResourceExhausted` |
| EK chain fails verification | 400 | `InvalidArgument` |
| quote invalid or stale nonce | 400 | `InvalidArgument` |
| platform not provisioned | 409 | `FailedPrecondition` |

A PCR mismatch is **not** a server fault. It means the machine is not in the
state the data was sealed against, which is precisely what sealing was for.

## Versioning and deprecation

TPM 2.0 is a TCG specification; command and structure encodings are the
standard's. `pkg/tpm2/version.go` and `capabilities.go` report what a given TPM
supports — capability differences between vendors are real, and code should ask
rather than assume.

Nothing in this feature is deprecated. The compatibility hazard is not the API:
a sealed blob is bound to one TPM, often in one measured state, and no version
policy changes that.
