# TPM 2.0 — API

> **Status: NORMATIVE** · Feature: `tpm2` · Repo: `go-xkms` · Last verified: 2026-08-19

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
