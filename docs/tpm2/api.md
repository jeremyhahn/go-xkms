# TPM 2.0 — API

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-09-08

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
endorsement key and requires the TPM to produce it.

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
