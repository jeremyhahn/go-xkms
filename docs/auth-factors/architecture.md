# Auth Factors — Architecture

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-09-29

## The problem

go-qrdb owns identity, users and multi-factor authentication. It defines a
`Factor` plugin interface and a registry, and it deliberately has **zero
hardware coupling** — it must run on a laptop with no TPM and no smartcard
reader. But the interesting factors in a trusted-computing stack are all
hardware: a PIV card, a PKCS#11 token, a FIDO2 authenticator, a client
certificate whose key lives in a TPM.

This feature is the hardware half: go-xkms implements go-qrdb's `Factor`
interface for each hardware type and registers the implementations into
go-qrdb's registry.

## Shape chosen: one canonical factor slice, built by one function

`pkg/factor/registry.go` holds the whole design decision:

```go
func DefaultFactors(cfg Config) []qrdbsdk.AuthFactorPlugin {
	return []qrdbsdk.AuthFactorPlugin{
		piv.New(...), pkcs11.New(...), fido2.New(...), mtls.New(...),
	}
}

func NewDefaultRegistry(cfg Config) (*qrdbsdk.AuthFactorRegistry, error)
```

The doc comment states the rule that matters: `DefaultFactors` is **the single
authoritative definition of the four factors**, and both `NewDefaultRegistry`
and downstream composers — go-quicbaas via the SDK re-export — call this
function, so the set never diverges. A composer that assembled its own list
would drift the moment a fifth factor was added.

Four factors: `piv`, `pkcs11`, `fido2`, `mtls`.

The zero `Config` is valid and yields software-backed PIV plus DER/COSE-verifying
PKCS#11, FIDO2 and certificate-possession mTLS. That matters for development:
the factor set works with no hardware present, and hardware is injected rather
than required.

Rejected alternatives:

- **Implementing the factors in go-qrdb.** Rejected by the ownership boundary —
  qrdb has zero hardware coupling by design, and a `libpcsclite` dependency in
  the database layer would propagate to every consumer.
- **Each composer building its own factor list.** Rejected: that is exactly the
  drift `DefaultFactors` exists to prevent.
- **A build-tag-gated factor set.** Rejected: the factors degrade gracefully
  (software PIV, verification-only PKCS#11) rather than disappearing, so a
  single binary serves both hardware and software deployments.

## Component boundaries

| Piece | Package | Owner |
|---|---|---|
| The `Factor` / `AuthFactorPlugin` interface | `go-qrdb/sdk/go` | **go-qrdb** |
| `AuthFactorRegistry` | `go-qrdb/sdk/go` | **go-qrdb** |
| PIV factor | `pkg/factor/piv` | go-xkms |
| PKCS#11 factor | `pkg/factor/pkcs11` | go-xkms |
| FIDO2 factor | `pkg/factor/fido2` | go-xkms |
| mTLS (certificate-possession) factor | `pkg/factor/mtls` | go-xkms |
| Canonical set + registry construction | `pkg/factor/registry.go` | go-xkms |
| Enrollment/verification helpers | `pkg/auth_factors` (`piv.go`, `pkcs11.go`, `webauthn.go`) | go-xkms |
| The canonical hardware implementations the factors wrap | `pkg/pivcert`, `pkg/pkcs11`, `pkg/fido2` | go-xkms |
| User store, identity, RBAC | go-qrdb | **go-qrdb** |

This is capability row **"FIDO2 / PIV / PKCS#11 factor impls" (tier 2)**. Tier 2
means composition-plane: these are registered in-process, not exposed as their
own transport surface. The SDK reaches them as
`Security().Auth().FIDO2()` / `.PIV()`.

**The registry is go-qrdb's.** A comment or document describing "the xkms
`FactorRegistry`" is describing a thing that does not exist.

## Data flow

Enrollment, then authentication:

```
enroll:   user + hardware  →  factor.Enroll  →  enrollment record  →  qrdb user store
                                 │
                                 └── records the factor's parameters:
                                     PIV slot + certificate
                                     PKCS#11 mechanism (default CKM_ECDSA_SHA256)
                                     FIDO2 RP id + origin(s) + UV requirement + credential
                                     mTLS certificate thumbprint

auth:     qrdb issues a challenge (TTL: 5 minutes by default)
            → factor.Verify(challenge, response)
              → PIV / PKCS#11: signature over the challenge, verified against the enrollment
              → FIDO2: WebAuthn assertion
              → mTLS: proof of possession of the enrolled certificate
            ← qrdb decides the authentication outcome
```

go-xkms never decides whether a user is authenticated. It answers one question
per factor — "did this hardware produce a valid response to this challenge?" —
and qrdb composes the answers into an authentication decision.

## Trust boundaries

- **Challenges are qrdb's and are time-bounded.** Default TTL is five minutes
  per factor; `Config.ChallengeTTLSeconds` overrides it for all four uniformly.
  A long TTL is a replay window.
- **The enrollment is the only source of a verification key.** Each factor's
  challenge carries the enrolled public key, and `Verify` reads it from the
  stored challenge. A response carries a signature (and, for FIDO2, the
  assertion's authenticatorData and clientDataJSON), never a key. A key the
  client could supply would let anyone sign with a key of their own.
- **`FIDO2RPID` is a security parameter, not a label.** The relying-party id
  recorded at enrollment is what binds a credential to an origin; changing it
  invalidates existing enrollments, and setting it too broadly widens where a
  credential can be used.
- **FIDO2's expected origin(s) and user-verification requirement are also
  recorded at enrollment**, not renegotiated at verification. `Verify`
  refuses a clientDataJSON `origin` outside the enrolled set and, by default,
  an assertion that only proves user presence without verification — the
  WebAuthn/CTAP2 best practice for a factor used to unseal or authenticate.
- **`PKCS11Mechanism` is recorded on the enrollment**, not chosen at
  verification. Default `CKM_ECDSA_SHA256`. `Verify` enforces this: it reads
  the mechanism from the challenge (never the response) and refuses when the
  response names a different one, so an attacker who could pick the mechanism
  at verification time cannot downgrade it.
- **Software PIV is a development convenience, and must be asked for by name.**
  With `PIVGenerator` nil the factor is software-backed — it proves possession of
  a key, not possession of a card. That substitution is silent and the resulting
  enrollment is indistinguishable from a hardware one, so any path where an
  operator named PIV expecting a smartcard sets `RequirePIVGenerator` and gets a
  refusal instead. Inject a PKCS#11 or TPM2 generator for deployments where the
  distinction matters.
- **mTLS proves certificate possession, not identity.** Binding a certificate to
  a user is qrdb's cert-binding scheme, not this package's.

## What this feature deliberately does not do

- **It defines no user model, no identity, no RBAC.** Those are go-qrdb's, and
  go-xkms has no local user store and no local cert-binding scheme.
- **It does not own the registry or the interface** — it registers *into* them.
- **It does not compose.** Which factors a product requires, and how many, is
  go-quicbaas's decision one layer up.
- **It is not the WebAuthn relying party.** The RP is
  [`../webauthn/`](../webauthn/architecture.md); the FIDO2 factor is the
  authentication-factor adapter that uses it.
