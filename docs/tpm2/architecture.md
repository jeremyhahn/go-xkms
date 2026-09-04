# TPM 2.0 — Architecture

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-08-19

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
| Platform provisioning | `platform.go`, `platform_keystore.go`, `platform_types.go`, `provision.go` |
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
```

`TPM2_MakeCredential` / `TPM2_ActivateCredential` is what makes this
unforgeable: a secret encrypted to the EK can only be recovered inside that
TPM. It is the mechanism behind the ACME `enroll-01` challenge.

## Trust boundaries

- **The EK chains to the manufacturer.** Attestation is only as good as the
  manufacturer root you accept — `pkg/attestation/truststore`.
- **Restricted and unrestricted signing keys are not interchangeable, and the
  device identity keys are one of each.** TCG "TPM 2.0 Keys for Device Identity
  and Attestation" v1.10 r9 makes the IAK/AK/LAK *Restricted* — they may sign
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

## What this feature deliberately does not do

- **It does not own the barrier or the registry.** It supplies a strategy.
- **It does not decide PCR policy for you.**
- **It does not verify Android attestation itself** — `pkg/attestation/android`
  handles that key type for the phone-as-HSM path.
- **It is not a TPM simulator for others to depend on.** The simulator is a test
  fixture.
