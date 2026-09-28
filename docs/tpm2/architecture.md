# TPM 2.0 — Architecture

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-09-28

## The problem

A TPM is the cheapest hardware root of trust there is — it is already soldered
to the board. But it is also the most awkward: session handling, transient
object contexts, PCR policies, NV space, hierarchy authorizations, and a
dictionary-attack lockout that punishes mistakes. Code that treats it as "an
HSM with a weird API" leaks handles, exhausts NV, and trips lockouts.

`pkg/tpm2` is the one place in the portfolio that talks to a TPM, and it is
sized accordingly.

## Shape chosen: a full TPM library, not a thin wrapper

`pkg/tpm2` covers the whole device rather than only what a KMS obviously needs,
because the platform's other uses — attestation, IDevID, measured boot,
sealed unlock — need the rest:

| Concern | Files |
|---|---|
| Device, sessions, auth | `tpm.go`, `session.go`, `auth.go`, `password.go`, `lockout.go` |
| Keys and templates | `key.go`, `template.go`, `secretkey.go`, `sigscheme.go` |
| Crypto | `rsa.go`, `ecdsa.go`, `ecdh.go`, `symmetric.go`, `kdf.go`, `random.go` |
| Sealing | `seal.go`, `sealer.go`, `policy.go`, `pcr.go` |
| NV storage | `nvram.go`, `nv_extend.go` |
| Attestation | `attestation.go`, `certify_verify.go`, `eventlog.go` |
| IDevID / TCG enrollment | `cert_idevid.go`, `idevid_csr.go`, `tcg_csr_serverside.go`, `cert_convert.go` |
| IDevID / IAK key policy and delegation | `devid_policy.go`, `devid_policy_session.go`, `devid_delegation.go` |
| Platform provisioning | `platform.go`, `platform_keystore.go`, `platform_types.go`, `provision.go` |
| Provisioning state, reprovisioning, EK credential challenge | `provisioning_state.go`, `credential_challenge.go`, `activation_key.go` |
| Capabilities | `capabilities.go`, `capability_device.go`, `version.go` |
| Simulator | `tpm_simulator.go`, `tpm_simulator_stub.go` |

`pkg/attestation` sits above it with the verification half: `verifier.go`,
`invariants.go`, `truststore/`, and an `android/` path for the phone-as-HSM
case.

Rejected alternatives:

- **Using a TPM only through a `SealingStrategy`.** Rejected: attestation,
  IDevID enrollment and measured boot are not sealing, and they are the reason
  the platform wants a TPM at all.
- **A thin wrapper over `go-tpm`.** Rejected: the awkward parts — session
  lifetime, object contexts, NV budgeting, lockout — are exactly what a wrapper
  leaves to the caller and callers get wrong. There is a dedicated leak-test
  suite for precisely this.
- **Requiring hardware for development.** Rejected: `tpm_simulator.go` means
  the whole surface is testable without a TPM.
- **Reimplementing `TPM2_MakeCredential`'s software construction by hand.**
  Rejected in favour of go-tpm's own `tpm2.CreateCredential` /
  `tpm2.ImportEncapsulationKey` (`credential_challenge.go`,
  `NewCredentialChallenge`): the KDFa/AES-CFB/HMAC construction TCG TPM 2.0
  Part 1 §24 defines is exactly what those functions already do, and go-tpm
  is the one dependency every consumer of this package already carries.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| TPM device library | `pkg/tpm2` | go-xkms |
| Attestation verification | `pkg/attestation` | go-xkms |
| TPM2 sealing strategy | `pkg/seal/strategy_tpm2.go` | go-xkms — [`../sealing-and-barrier/`](../sealing-and-barrier/architecture.md) |
| TPM2 PIN backend | `pkg/pintpm2` | go-xkms — [`../pin-management/`](../pin-management/architecture.md) |
| TPM2 keystore backend | `pkg/backend/tpm2` | go-xkms — [`../crypto-backends/`](../crypto-backends/architecture.md) |
| TPM2 PIV storage (NV) | `pkg/pivcert/tpm2` | go-xkms — [`../piv-smartcard/`](../piv-smartcard/architecture.md) |
| TCG EK/AK certificate issuance | `pkg/ca` `CATCGEnrollment` | go-xkms — [`../certificate-authority/`](../certificate-authority/architecture.md) |
| `enroll-01` ACME challenge | `pkg/acme/challenges/enroll-01` | go-xkms — [`../acme-issuance/`](../acme-issuance/architecture.md) |
| LUKS TPM unlock | `pkg/luks` | go-xkms |

TPM2 is not a single row in the portfolio ownership register — it is the
hardware underneath several of them. This folder documents the device layer; each consuming feature
documents its own use.

## Data flow

**Sealing to platform state:**

```
seal:    data + PCR policy  →  TPM2_Create under the SRK, policy-bound
unseal:  TPM re-evaluates the policy against current PCRs
         → PCRs match   → data released
         → PCRs differ  → refused, and that is the mechanism working
```

**Identity and attestation:**

```
EK (endorsement key, manufacturer-rooted)
  → AK (attestation key) certified against the EK
    → quote over selected PCRs + a nonce
      → pkg/attestation verifier: EK chain, AK certification, quote signature,
        PCR values against expectation
IDevID: TCG-CSR-IDEVID  →  tcg_csr_serverside.go  →  CATCGEnrollment
                             → pkg/ca verifyEKCertificateChain: EK chain,
                               tcg-kp-EKCertificate EKU
```

`TPM2_MakeCredential` / `TPM2_ActivateCredential` is what makes this
unforgeable: a secret encrypted to the EK can only be recovered inside that
TPM. It is the mechanism behind the ACME `enroll-01` challenge. But
possession alone is not provenance: the CA verifies the EK certificate's
chain (`pkg/ca/tcg_ek_trust.go`, `verifyEKCertificateChain`) before it will
generate the `TPM2_MakeCredential` challenge or issue an IAK/IDevID, exactly
as it verifies the AK's EK chain before trusting a quote (below) — the two
checks share the same `pkg/attestation/truststore` trust-anchor
configuration shape, configured independently
(`ca.tcg-config.trust-anchors` for issuance,
`attestation.formats.tpm2` for quote verification).

## Trust boundaries

- **The EK chains to the manufacturer.** Attestation is only as good as the
  manufacturer root you accept — `pkg/attestation/truststore`. The same is
  true of IAK/IDevID issuance: see
  [`../certificate-authority/architecture.md`](../certificate-authority/architecture.md)
  "Trust boundaries".
- **Restricted and unrestricted signing keys are not interchangeable, and the
  device identity keys are one of each.** TCG "TPM 2.0 Keys for Device Identity
  and Attestation" v1.00 r12 (checked in under `docs/references/`) makes the
  IAK/AK/LAK *Restricted* — they may sign
  nothing but a digest the TPM produced, which is what makes an attestation
  unforgeable — and the IDevID/LDevID *Unrestricted*, precisely so a device can
  sign arbitrary data such as a TLS `CertificateVerify` with its own identity.
  `Sign` therefore routes them differently: an attestation key hashes its input
  inside the TPM and signs the digest under the `TPMT_TK_HASHCHECK` ticket
  `TPM2_Hash` returns, while a device identity key signs the caller's digest
  verbatim under a NULL ticket. Signing an already-computed digest through the
  ticketed path produces a signature over `H(digest)`, which no peer can verify.
  The TPM withholds that ticket for data beginning with `TPM_GENERATED_VALUE`,
  which is how a restricted key is kept from signing a forged attestation;
  `ErrRestrictedSignRefused` reports that refusal rather than passing on a
  ticket the TPM never issued.
- **A DevID template is built once, and every field of it is a derivation
  input.** `DevIDTemplateSpec` (`devid_template.go`) is the single place a
  Recoverable IDevID/IAK template is assembled; the exported package templates
  and both creation paths derive from it, and `assertDevIDTemplateConformant`
  re-checks the result immediately before `TPM2_CreatePrimary`. The
  alternative -- a template transcribed at each call site -- is what let
  `CreateIAK`'s inline copy drift from the template the package exported. The
  consequence to hold onto is that `unique`, the scheme, the attributes and
  the policy are not descriptions of a key: they *are* the key. Changing any
  of them re-keys the device, which is why they are pinned by tests against
  the specification's tables rather than left to review.
- **A device identity key's password can use it but cannot administer it.**
  TCG "TPM 2.0 Keys for Device Identity and Attestation" v1.00 r12 §7.2.4 is
  explicit that the recommended templates "enable the IDevID/IAK key's
  authValue password to authorize use of the key but not administration of
  the key": `userWithAuth` SET, `adminWithPolicy` SET. Someone who learns the
  signing password can sign — they cannot certify, re-certify, or release a
  credential against the key. The IDevID and IAK are created from that
  template (§7.3.4.1, Template H-0, over the H-1 through H-4 crypto suites)
  with the §7.3.6.6 IDevID/IAK Key Policy as
  their `authPolicy`: a `PolicyOR` whose branches let the *Privacy
  Administrator* — whoever holds `endorsementAuth` — use the key, certify it
  (`TPM2_Certify`), release a credential to it (`TPM2_ActivateCredential`), or
  delegate use through a reserved Policy NV index (§7.3.5). Every ADMIN-role
  command therefore runs under `DevIDAdminSession`, which walks exactly one
  branch and is refused by the TPM for any other command (`TPM_RC_POLICY_CC`).
  The digests are computed offline through go-tpm's trial-policy calculator
  and pinned to the specification's own Tables 14–19; the two implementations
  agreeing is the evidence the policy on the key is the one the specification
  defines.
- **Platform binding of a device identity key is a delegation, not a
  different key.** The specification fixes the key's policy, so "only use this
  IDevID when the platform is in its measured state" cannot be written into
  the key. §7.3 puts it in a reserved Policy NV Index instead: the Owner
  defines the index (§7.3.5, Owner authorization), the Privacy Administrator
  writes a Delegation Policy into it (§7.2.4, `PolicySecret` on the
  Endorsement Hierarchy), and a user reaches the key's fourth policy branch by
  satisfying that policy and executing `TPM2_PolicyAuthorizeNV`. Two things
  follow. The delegation can be replaced without touching the key — after a
  firmware update the Privacy Administrator writes the new state's
  `PolicyPCR` and signing resumes with the same identity. And the index is
  only trusted through its Name: `TPM2_PolicyAuthorizeNV` extends the Name
  the index actually has, so an index with any other public area — one
  attribute bit, a different `authPolicy` — produces a digest the key policy
  does not contain, and this library refuses to define or write such an
  index (`ErrDevIDPolicyNVIndex`) rather than let the refusal surface later
  as an unexplained `TPM_RC_POLICY_FAIL`. `platform-policy` on an IDevID or
  IAK is exactly this delegation, provisioned by the operator as Owner and
  Privacy Administrator at once ("SHOULD NOT be populated by the OEM",
  §7.3.5 — the operator running provisioning is the Owner). The authValue
  remains a USER path on Template H-0 (§7.2.4); the library does not forget
  it on the Owner's behalf.
- **A verifier needs no TPM of its own to build an EK credential challenge.**
  `NewCredentialChallenge` performs `TPM2_MakeCredential`'s construction in
  software against any EK public key, so a CA or installer that has never
  touched a TPM can still prove a remote device possesses one
  (go-xkms#798); the device side still needs a real TPM to answer
  (`AnswerCredentialChallenge` / `ActivateCredential`), which is the actual
  proof of possession. `pkg/ca`'s `VerifyTCG_CSR_IDevIDBytes` uses this, and
  no longer requires `SetTPM` to have been called.
- **A quote proves state at a moment**, bound to a nonce. A quote without a
  fresh nonce proves nothing about now.
- **PCR selection is the security policy.** Sealing to firmware PCRs survives
  kernel updates; sealing to PCRs that change on update means the data will not
  unseal after the next one. Both are legitimate; pick deliberately.
- **The lockout counter is real and terminal-ish.** Failed authorizations
  advance it; recovery needs the lockout authorization or the TPM's own
  interval. `lockout.go` is not a formality.
- **NV space is finite and shared.** PIV storage, platform data and anything
  else compete for it.
- **Sessions and object contexts leak if not released** — there are dedicated
  simulator suites (`object_context_leak_simulator_test.go`,
  `auth_session_leak_simulator_test.go`, `resource_leak_simulator_test.go`)
  because this is the failure mode that shows up as "the TPM stopped working
  after a few hours".
- **Hierarchy passwords are the platform's**, not the KMS's — which is why the
  TPM2 PIN backend has no SO PIN.
- **The Owner hierarchy auth is never stored in configuration, for either
  SRK — it is an operator input supplied at the moment of the operation.**
  No Security Officer PIN means the Owner hierarchy carries empty auth, the
  TCG factory-default state; `SRKConfig` (the Shared SRK) and
  `PlatformSRKConfig` (the Platform SRK, this library's own storage parent,
  handle `0x81000002`) both carry no hierarchy-auth field for this reason.
  When an operator has set an SO PIN, it reaches `TPM2_CreatePrimary`,
  `TPM2_EvictControl` and `TPM2_HierarchyChangeAuth` only as an explicit
  function argument at the moment of the call — `soPIN` on
  `Install`/`Provision`/`ProvisionOwner` for the Shared SRK, and the same
  `soPIN` argument threaded through
  `PlatformKeyStore.Initialize`/`EnrollPlatformSRK`/`ensureSRKAuth` for the
  Platform SRK — never a config literal, and never persisted between calls.
  `PlatformSRKAttributesFromConfig` reflects this: it always returns empty
  `TPMAttributes.HierarchyAuth`, even when the SSRK config it borrows
  algorithm and key parameters from carries a (runtime-supplied) value of its
  own — the two keys' owner-hierarchy authorizations are never the same Go
  value, only, at any moment, potentially the same TPM-level secret if the
  caller happens to pass it to both calls.
  `pkg/backend/tpm2`, which uses the Platform SRK as its own working key
  precisely because that key does not need to follow the TCG-standard SSRK
  workflow, never carries a hierarchy-auth field of its own for the same
  reason and never falls back to the Shared SRK when the Platform SRK is
  unavailable — construction fails instead.
- **The Platform SRK's own authorization value (its `Password`, not its
  owner-hierarchy auth) is the user PIN**, supplied the same way — as an
  argument to `Initialize`/`EnrollPlatformSRK`/`ChangeAuth`/`VerifyAuth` —
  never a config literal or a compiled-in default.
- **Configuration is the source of truth for whether the Platform SRK is
  platform-policy bound, on every path that resolves it.**
  `TPM2.PlatformSRKAttributes` has two paths to the same answer: when a
  `PlatformKeyStore` is attached (`TPM2.SetPlatformKeyStore`) it syncs
  `PlatformPolicy` from the key store's own attrs; when none is attached —
  the state an unattended daemon boot is in, since nothing in `pkg/server` or
  `pkg/seal` calls `SetPlatformKeyStore` (only the interactive `xkey` GUI
  does) — it calls `PlatformSRKAttributesFromConfig` itself, the same
  function `PlatformKeyStore` uses, rather than leaving `PlatformPolicy` at
  the Go zero value the way a bare `TPM2.KeyAttributes` read would (that read
  has no configuration in scope, and deliberately does not infer the policy
  from the object's read-back `AuthPolicy` either — that would let an
  unrelated object's coincidentally-matching `AuthPolicy` silently select the
  PCR branch). `defaultSealKeyAttributes`/`defaultUnsealKeyAttributes` — what
  `TPM2.Seal`/`Unseal` apply when the caller passes no `KeyAttributes`, which
  is what the barrier's `TPM2Strategy` and `PlatformSealer` do — inherit
  whichever attrs `PlatformSRKAttributes` returns, so both paths agreeing is
  what lets `CreateSession`/`PlatformPolicySession` choose the `PolicyPCR`
  branch instead of a plain password session with empty auth bytes (which
  the TPM would correctly refuse with `TPM_RC_AUTH_FAIL` against an enrolled
  SRK's real, non-empty PIN) on an unattended boot with no `PlatformKeyStore`
  attached yet. Both branches — unattended `PolicyPCR` and interactive
  `PolicyAuthValue` — are exercised against the simulator in
  `pkg/tpm2/platform_keystore_enroll_simulator_test.go`
  (`TestEnrollPlatformSRK_DefaultSealUnseal_PCRBranchUnattended`,
  `TestEnrollPlatformSRK_DefaultSealUnseal_PINBranchViaPlatformKeyStore`).
- **Every caller that builds a `Config` for this library must set
  `PlatformSRK.PlatformPolicy: true`, unconditionally** — there is no
  plain-password shape for the Platform SRK (go-xkms#677: `authValue` = user
  PIN, `authPolicy` = platform PCR policy). Two callers violated this and
  disagreed with each other until go-xkms#997: `pkg/backend/tpm2`'s
  `Config.ToTPMConfig` (`pkg/backend/tpm2/config.go:211-213`) hardcoded
  `PlatformPolicy: false` into the `PlatformSRKConfig` it built, so a Platform
  SRK created by that backend's simulator first-boot recipe
  (`provisionSimulatorEKSRK`, `pkg/backend/tpm2/backend.go:264-299`) carried
  no `AuthPolicy` in its template at all, while `pkg/tpm2.DefaultConfig` and
  every enrollment path already set it. `pkg/server/platform_store.go`'s
  `buildTPM2PlatformSealer` then directly violated the "configuration is the
  source of truth" invariant above: rather than trusting what
  `PlatformSRKAttributes()` resolved, it force-set the returned
  `KeyAttributes.PlatformPolicy` to `true` unconditionally
  (formerly at `pkg/server/platform_store.go:241`, removed by #997), which hid
  the mismatch instead of surfacing it — a Platform SRK autodetected this way
  reported `PlatformPolicy: true` no matter what the underlying TPM object
  actually was. The fix set `ToTPMConfig`'s `PlatformSRKConfig` to
  `PlatformPolicy: true` (`pkg/backend/tpm2/config.go:211-213`) and deleted the
  override (`pkg/server/platform_store.go:224-234`), so `buildTPM2PlatformSealer`
  now reports exactly what `PlatformSRKAttributes()` resolves, same as every
  other caller.

## What this feature deliberately does not do

- **It does not own the barrier or the registry.** It supplies a strategy.
- **It does not decide PCR policy for you.**
- **It does not verify Android attestation itself** — `pkg/attestation/android`
  handles that key type for the phone-as-HSM path.
- **It is not a TPM simulator for others to depend on.** The simulator is a test
  fixture.
