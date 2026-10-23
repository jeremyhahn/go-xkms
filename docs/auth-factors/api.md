# Auth Factors — API

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-10-12

Transport shapes: [`../key-management/api.md`](../key-management/api.md)
§"How the six transports are shaped".

## This is a tier-2 capability

The six-transport completeness rule applies to **tier 1** — data and control
plane capabilities. Auth factors are **tier 2: composition plane, in-process**.
They are registered into go-qrdb's `AuthFactorRegistry` at composition time and
have no transport surface of their own, by design rather than by omission.

What *is* on the wire is (a) the hardware operations each factor wraps, and
(b) the authentication surface go-qrdb exposes and go-xkms serves.

## In-process surface

| Capability | Embedded call | Notes |
|---|---|---|
| Build the canonical factor slice | `factor.DefaultFactors(cfg)` | the authoritative list: `piv`, `pkcs11`, `fido2`, `mtls` |
| Build a registry with them | `factor.NewDefaultRegistry(cfg)` | returns `*qrdbsdk.AuthFactorRegistry`; administrator enrolment |
| Build an embedded node's registry | `factor.NewNodeRegistry(cfg)` | every factor but `mtls`; go-qrdb's own `mtls` factor serves quorum share holders (`pkg/factor/registry.go:114`) |
| Register into an existing registry | `registry.Register(f)` for each of `DefaultFactors(cfg)` | the registry type is **go-qrdb's** |
| Decoy enrollment for a user with no enrollment | `f.DecoyEnrollment(seed, userID, like)` on each factor | called by go-qrdb's login ceremony, not by composers; the decoy's challenge `MethodData` has the same keys and types as a real one |

SDK access is `Security().Auth().FIDO2()` and `Security().Auth().PIV()`.

## The SDK login plane

Projects above go-xkms reach the whole login plane through `sdk/go`, without
importing `pkg/*`:

| Need | SDK call | Source |
|---|---|---|
| Hardware factor verification inside an embedded qrdb node | `xkms.WithXKMSFactorVerifiers(AuthFactorOptions)` returns `embedded.Option`s for qrdb's embedded transport | `sdk/go/auth.go:149` |
| Factor records (enroll, list, remove) and the rest of the identity plane | `xkms.Auth(qrdbClient)`: `Users`, `Roles`, `Permissions`, `Factors`, `Login`, `Sessions`, `RBAC`, `VolumePools` | `sdk/go/auth.go:38,80` |
| PIV login and the session pair | `xkms.NewLoginClient(cfg)`: `PIVLogin`, `Refresh`, `Logout`, `Validate` | `sdk/go/login.go:89` |

`WithXKMSFactorVerifiers` always registers the PKCS#11 verifier, whose enrolled
public key travels in the factor record. It registers the WebAuthn verifier
only when `WebAuthnService` is set, and the PIV verifier only when `PIVRoots`
is set (`sdk/go/auth.go:151-165`). A missing dependency is not an error.

`PIVLogin` posts to `POST /api/v1/auth/login/piv` (`sdk/go/login.go:122`). The
PIV slot certificate is the TLS client certificate, so this client speaks
mTLS HTTPS directly; possession of the card key is the credential.

The factor-record service itself is go-qrdb's `UserAuthFactorService`, which
xkmsd's embedded node serves on its TLS unix socket behind the node's
authentication chain (enabled by `pkg/server/qrdb_node.go:85-89`). go-xkms has
no REST proxy for it.

## One authentication chain on every transport

The node's chain carries xkms's session-JWT authenticator
(`node.WithAuthenticators`), so the bearer token `auth login` mints is accepted
on REST, gRPC, MCP and the unix socket alike, and the admin plane refuses an
anonymous caller with `Unauthenticated` on each of them
(`pkg/server/unified_api_e2e_test.go`).

## Factor challenge and response payloads

go-qrdb's auth-factor service issues a factor's challenge, returns its
`MethodData` to the client, keeps the challenge server-side, and passes that
stored challenge to the factor's `Verify` with the client's response. The
enrolled verification key travels in `MethodData`, so the factor never has to
take one from the response.

| Factor | Challenge `MethodData` | Response |
|---|---|---|
| `piv` | `enrolled_cert_pem` (enrolled certificate, PEM), `slot`, `algorithm` | `Value`: signature over the challenge message (see below) |
| `pkcs11` | `enrolled_public_key_der` (enrolled PKIX key, standard base64), `mechanism`, `algorithm`, `key_id` | `Value`: DER ECDSA or PKCS#1 v1.5 RSA signature over SHA-256(challenge message) |
| `fido2` | `enrolled_cose_public_key` (enrolled COSE key, standard base64), `rp_id`, `origins` (`[]string`), `require_uv` (`bool`), `credential_id`, `challenge_base64` | `Value`: assertion signature; `Metadata`: `authenticator_data`, `client_data` (base64) |
| `mtls` | `enrolled_public_key_der` (the enrolled certificate's public key, standard base64 PKIX DER; never the certificate), `cert_spki_thumbprint`, `cert_cn` | `Value`: ECDSA or RSA signature over SHA-256(challenge message), or Ed25519 over the challenge message |

A response carries **no public key**. Verification uses only the key in the
stored challenge. Key material placed in a response's metadata
(`public_key_pem`, `public_key_der`, `cose_public_key`) is ignored, and a
challenge without the enrolled key is refused.

### The challenge message

The `piv`, `pkcs11` and `mtls` factors verify a signature over go-qrdb's
challenge message, never over the bare nonce (#1684).
`challenge.Message` (`pkg/factor/internal/challenge/challenge.go:31`) builds it
as `qrdbsdk.QuorumChallengeMessage(ChallengeID, purpose, Nonce)`. The purpose
is `MethodData[qrdbsdk.QuorumChallengePurposeKey]`, which go-qrdb sets on a
quorum challenge, and `""` when there is none. This is how go-qrdb's own `mtls`
factor reads it. So a proof binds the challenge ID and purpose, and a proof
made for one quorum operation never answers a challenge for another with the
same nonce. Each factor also refuses a challenge with an empty nonce.

| Factor | Verifies at |
|---|---|
| `mtls` | `pkg/factor/mtls/factor.go:262` |
| `pkcs11` | `pkg/factor/pkcs11/factor.go:314` |
| `piv` | `pkg/factor/piv/factor.go:261` |

The prover is `qrdbsdk.SignQuorumChallenge(signer, challengeID, purpose,
nonce)`. The `piv` factor's own prover, `Factor.SignChallenge`
(`pkg/factor/piv/factor.go:277`), signs the same message with the slot's key.

The `fido2` factor is not changed. Its WebAuthn challenge is the nonce
(`challenge_base64`), and go-qrdb ships no `fido2` factor whose message it
could follow.
### PIV factor signature verification

The `piv` factor's `Verify` (`pkg/factor/piv/factor.go`) accepts every
algorithm its `Enroll` can produce — `rsa2048`, `rsa4096`, `ecdsap256`,
`ecdsap384`, `ed25519` — dispatching by the enrolled key's type:

| Algorithm | Signature format |
|---|---|
| ECDSA (P-256, P-384) | ASN.1 DER `(r, s)` over SHA-256(challenge message) |
| RSA (2048 bits or larger) | PKCS#1 v1.5 over SHA-256(challenge message); moduli under 2048 bits are refused |
| Ed25519 | raw signature over the raw challenge message — Ed25519 hashes its own input and does not accept a pre-hashed digest for standard (non-Ed25519ph) signing |

## The authentication surface that consumes them

These routes belong to the identity plane; they are listed here so the reader
can see where a factor is actually exercised.

| Capability | REST | gRPC / Unix | QUIC | MCP | Embedded |
|---|---|---|---|---|---|
| Register (WebAuthn) | `POST /api/v1/webauthn/registration/begin` · `/finish` | `BeginRegistration` · `FinishRegistration` | same as REST | **MISSING — docs/13** | `FIDO2Service.BeginRegistration` · `FinishRegistration` |
| Authenticate (WebAuthn) | `POST /api/v1/webauthn/login/begin` · `/finish` | `BeginAuthentication` · `FinishAuthentication` | same as REST | **MISSING — docs/13** | `FIDO2Service.BeginAuthentication` · `FinishAuthentication` |
| SDK ceremony variants | `POST /api/v1/webauthn/sdk/registration/begin` · `/finish` · `/sdk/authentication/begin` · `/finish` | — | same as REST | — | — |
| PIV login | `POST /api/v1/auth/login/piv` | **MISSING — docs/13** | same as REST | **MISSING — docs/13** | — |
| List a user's credentials | `GET /api/v1/users/{username}/credentials` | `ListUserCredentials` | same as REST | **MISSING — docs/13** | `UserService.ListUserCredentials` |
| Bind a certificate to a user (mTLS factor) | `POST /api/v1/users/{username}/cert-bindings` | `BindUserCert` | same as REST | **MISSING — docs/13** | `UserService.BindUserCert` |

The WebAuthn routes sit in `GroupWebAuthn` and are `RouteAuthPublic` — they are
**unauthenticated because they are the authentication**. `POST
/api/v1/auth/login/piv` is likewise `RouteAuthPublic` in `GroupAuthSession`.
Both groups sit behind the login rate limiter.

**PIV login proves hardware, or says it did not.** With an attestation anchor
configured (`auth.piv_login.attestation_roots`; for a YubiKey, the Yubico PIV
Attestation root, plus optional `attestation_intermediates`), the client
presents its login certificate first and the slot's attestation certificate
after it. The device attestation certificate (slot `f9`) can follow as an
intermediate. The exchange accepts the login as smartcard-backed only when
that separate attestation:

- chains to the anchor;
- carries the same SubjectPublicKeyInfo as the login certificate;
- carries the Yubico attestation claims (firmware, serial, PIN and touch
  policy);
- passes any deployment policy set in `PIVLoginOptions.AttestationPolicy`.

The login certificate is never its own evidence. The binding is on the key,
so a genuine attestation borrowed from another card attests nothing here, and
certificates the client presents are chain material, never anchors. An issuer
DN (`trusted_issuers`) remains an additional allowlist, not evidence. A
recorded enrollment level never replaces the attestation.

With no anchor configured, the exchange refuses every login unless
`allow_unattested: true` is set explicitly. The two settings are mutually
exclusive, so there is no "attest if possible, otherwise allow" mode. The
minted token carries `attest_level`: `hardware` when the key was proven,
`unattested` (or the recorded level's name) when the deployment accepted it
without proof, so the two are never indistinguishable.

Every refusal answers `401` with `client certificate is not
hardware-attested`. The stable reason code
(see [engineering.md](engineering.md) §"Refusal reasons") is only on the
audit record for `auth.login.piv`, as `attestation: <code>`.

`GET /api/v1/users/{username}/credentials` and the cert-binding route are in
`GroupUsers`: authenticated, permission-gated (`users:read`, `users:update`),
and **not** tenant-scoped — the user plane is identity-scoped, not
tenant-scoped.

## Status and error mapping

| Condition | REST | gRPC / Unix |
|---|---|---|
| challenge expired | 401 | `Unauthenticated` |
| assertion or signature invalid | 401 | `Unauthenticated` |
| enrollment not found | 404 | `NotFound` |
| RP id mismatch | 400 | `InvalidArgument` |
| rate limited (login groups) | 429 | `ResourceExhausted` |

Every one of these is a failure, not a downgrade. There is no response shape
that means "partially verified".

## Versioning and deprecation

Adding a factor to `DefaultFactors` is additive on the wire — a client that does
not know it simply never selects it. Removing one invalidates every enrollment
that used it, which is breaking for users, not just for code.
