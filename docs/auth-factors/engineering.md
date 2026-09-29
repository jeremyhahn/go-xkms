# Auth Factors — Engineering Contract

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-09-29

## Exported surface — `pkg/factor`

```go
// Config configures the default factor registry. The zero value is valid.
type Config struct {
	PIVGenerator        xkms.PIVKeyGenerator // nil → software-only generator
	RequirePIVGenerator bool                 // true → nil PIVGenerator refuses instead
	PKCS11Mechanism     string               // empty → CKM_ECDSA_SHA256
	FIDO2RPID           string               // empty → package default
	ChallengeTTLSeconds int                  // zero → each factor's default (5 minutes)
}

func DefaultFactors(cfg Config) []qrdbsdk.AuthFactorPlugin
func NewDefaultRegistry(cfg Config) (*qrdbsdk.AuthFactorRegistry, error)
```

`DefaultFactors` returns, in order: `piv.New`, `pkcs11.New`, `fido2.New`,
`mtls.New`. It is the **single authoritative definition** of the four factors —
`NewDefaultRegistry` and every downstream composer call it rather than building
their own slice.

Per-factor constructors and configs:

| Factor | Package | Config fields |
|---|---|---|
| `piv` | `pkg/factor/piv` | `Generator xkms.PIVKeyGenerator`, `RequireGenerator bool`, `ChallengeTTLSeconds int` |
| `pkcs11` | `pkg/factor/pkcs11` | `DefaultMechanism string`, `ChallengeTTLSeconds int` |
| `fido2` | `pkg/factor/fido2` | `RPID string`, `ChallengeTTLSeconds int` |
| `mtls` | `pkg/factor/mtls` | `ChallengeTTLSeconds int` |

Enrollment and verification helpers used by the API layer are `pkg/auth_factors`
(`piv.go`, `pkcs11.go`, `webauthn.go`).

The interfaces implemented — `qrdbsdk.AuthFactorPlugin`,
`qrdbsdk.AuthFactorRegistry`, `qrdbsdk.NewFactorRegistry` — belong to go-qrdb
and are reached through `go-qrdb/sdk/go` only. Never `go-qrdb/pkg/*`.

## SessionStore interface (`pkg/webauthn/interfaces.go`)

The `SessionStore` interface (`pkg/webauthn/interfaces.go:47`) has a critical
`Take` method that implements atomic session claiming:

```go
// Take atomically claims a session: it returns the session data AND
// removes it in one indivisible operation, so exactly one caller can ever
// observe a given session.
Take(ctx context.Context, sessionID string) (*webauthn.SessionData, error)
```

**Implementors must make this atomic.** A WebAuthn ceremony session is
single-use, and the finish handler must call `Take` BEFORE validating the
authenticator response. Validating first and deleting afterwards leaves a window
in which two concurrent finish requests both validate against the same challenge
and both succeed. A non-atomic implementation that cannot guarantee this must not
be used.

`Take` returns `ErrSessionNotFound` when no session was claimed (missing or
already taken) and `ErrSessionExpired` when the claimed session had aged out. An
expired session is consumed all the same (cannot be retried).

## Invariants

- **`DefaultFactors` is the only place the factor set is enumerated.** Adding a
  fifth factor means editing that function; a composer that maintains its own
  list is a defect.
- **The zero `Config` is valid** and yields software-backed PIV plus
  DER/COSE-verifying PKCS#11, FIDO2 and mTLS. Construction never fails for lack
  of hardware.
- **`NewDefaultRegistry` errors only on registration failure**, which cannot
  happen for distinct non-empty factor names. The error is returned for
  completeness; do not treat a nil error as meaningful validation.
- **A factor verifies; it does not authenticate.** The return value answers
  "was this response valid for this challenge under this enrollment?" — nothing
  more. qrdb composes the decision.
- **Enrollment parameters are fixed at enrollment.** The PKCS#11 mechanism, the
  FIDO2 RP id and the PIV slot are recorded when the factor is enrolled and are
  not renegotiable at verification. This is what prevents downgrade.
- **The PKCS#11 mechanism is checked, not just recorded.** `Enroll` refuses a
  mechanism whose family (`CKM_ECDSA*` vs. an `RSA` mechanism) does not match
  the enrolled key's own algorithm — a record that could never be satisfied by
  a genuine signature from that key. `Challenge` copies the enrolled mechanism
  into `MethodData["mechanism"]` alongside the key. `Verify` reads it from
  there and nowhere else: it refuses when that mechanism is inconsistent with
  the enrolled key's algorithm, and refuses when `response.Metadata["mechanism"]`
  names a different mechanism than the enrolled one — even when the signature
  itself is otherwise valid. Verify never selects *how* it checks a signature
  from anything the response supplies; the enrolled mechanism only ever
  gates a refusal, never a choice.
- **The verification key comes from the challenge, never the response.** Each
  factor's `Challenge` copies `enrollment.PublicKey` into `MethodData`
  (`enrolled_cert_pem` for `piv` and `mtls`, `enrolled_public_key_der` for
  `pkcs11`, `enrolled_cose_public_key` for `fido2`). `Verify` reads the key
  from there and nowhere else, and returns
  `*qrdbsdk.AuthFactorVerificationFailedError` when it is absent. A response
  that could supply its own key could pass with any key the caller holds.
- **FIDO2 assertions are checked against the enrollment's RP.** `Verify`
  requires `authenticatorData[0:32] == SHA-256(rp_id)` (the `rp_id` carried in
  the challenge from the enrollment), the user-present flag, and a
  clientDataJSON of type `webauthn.get` whose `challenge` is the issued nonce
  (base64url). It then verifies the signature over
  `authenticatorData || SHA-256(clientDataJSON)`. It does not require
  user verification, because no enrollment records that requirement, and it
  does not check the clientDataJSON `origin`, because no enrollment records an
  origin.
- **`ChallengeTTLSeconds` applies to all four factors uniformly** when set on
  `factor.Config`. There is no per-factor override at that level.
- **Concurrency.** Factors are safe for concurrent verification; they hold no
  per-request state.

## Error semantics

Factor errors surface through go-qrdb's authentication path, not through a
go-xkms transport. Within go-xkms the hardware layers return their own typed
errors — `pkg/pivcert`, `pkg/pkcs11`, `pkg/fido2` — and the factor adapters wrap
them.

**Fail closed, in every case:**

| Condition | Result |
|---|---|
| challenge expired | verification fails; no partial credit |
| signature does not verify against the enrollment | fails |
| hardware absent or unreadable | fails — never falls back to a software check |
| PKCS#11 mechanism differs from the enrolled one, or is inconsistent with the enrolled key's algorithm | fails |
| FIDO2 RP id mismatch (`authenticatorData` rpIdHash) | fails |
| FIDO2 user-present flag clear | fails |
| FIDO2 clientDataJSON not `webauthn.get`, or not bound to the nonce | fails |
| enrolled key missing from the challenge | fails — no key is ever read from the response |
| enrollment record missing | fails |

There is no "degraded" verification result. A factor either verified or it did
not.

## Configuration

Injected in-process at composition time, not by config file — this is a tier-2
capability. The four knobs are `factor.Config` above. What to set in practice:

- **`PIVGenerator`** — inject a PKCS#11- or TPM2-backed generator for hardware
  PIV. Leaving it nil in production means the "PIV factor" proves possession of
  a software key.
- **`RequirePIVGenerator`** — set it wherever the deployment named PIV expecting
  hardware. A nil `PIVGenerator` then yields a `piv` factor that reports itself
  unavailable (`piv.NoGeneratorReason`) and whose `Enroll` returns
  `*piv.GeneratorUnattachedError`, instead of substituting software. The
  administrator-enrollment path sets it by default; see
  [init-ceremony/engineering.md](../init-ceremony/engineering.md).
- **`FIDO2RPID`** — set it to your actual relying-party id. It is recorded on
  every enrollment, so changing it later invalidates them.
- **`PKCS11Mechanism`** — override only with reason; the default
  `CKM_ECDSA_SHA256` is the safe choice for ECDSA enrollments. It applies only
  when the enrolled key is ECDSA-family; an RSA key enrolled without an
  explicit `"mechanism"` MethodParam gets the package's own RSA default
  (`CKM_SHA256_RSA_PKCS`) instead of inheriting an ECDSA mechanism it is
  inconsistent with.
- **`ChallengeTTLSeconds`** — shorter is safer. The five-minute default is
  already generous for interactive use.

### PIV login attestation (`auth.piv_login`)

The cert-login exchange is configured by file (`auth.piv_login`) and, in
process, by `rest.PIVLoginOptions` (`ServiceModulePIVLoginOptions` on the
SDK). Beyond `enabled` and `trusted_issuers`:

- **`attestation_roots`** (`AttestationRoots *x509.CertPool`) — the PIV
  attestation CA bundle a login must prove its key against. Required when the
  exchange is enabled, unless the opt-out below is set; the config refuses to
  validate otherwise, and a bundle that names a file that does not load fails
  the daemon at composition rather than mounting an exchange that refuses
  every card.
- **`attestation_intermediates`** (`AttestationIntermediates`) — vendor
  intermediates the device does not present itself. Optional.
- **`allow_unattested`** (`AllowUnattested`) — accept logins nothing attests,
  minting `attest_level: unattested`. Off by default; the zero value is
  strict.

The proof is evaluated by `pivcert.VerifyAttestation` over every certificate
the client presents, with the others as path-building material and the anchors
only from configuration, and a chain that verifies counts only if its subject
key equals the login certificate's `RawSubjectPublicKeyInfo`. The result is
recorded on the token (`attest_level`, carried through refresh) and on the
audit event.

## Persistence

Enrollment records live in go-qrdb's user store, through `go-qrdb/sdk/go`.
go-xkms persists nothing for this feature — there is no local user model and no
local cert-binding scheme, by ownership rule.

## Test strategy

- **Unit** — `pkg/factor/registry_test.go` and `registry_wiring_test.go`. The
  wiring test is the one that matters: it asserts that the registry actually
  contains the four factors `DefaultFactors` names, which is what catches a
  composer that stopped calling it.
- **Per factor** — suites under `pkg/factor/{piv,pkcs11,fido2,mtls}`.
- **Helpers** — `pkg/auth_factors/{piv,pkcs11,webauthn}_test.go`,
  `auth_factors_extra_test.go`.
- **Integration** — `test/integration/fido2`, `test/integration/pkcs11`,
  `test/integration/webauthn-browser`, `test/integration/logins`.
- **Fault injection** — expired challenges and mechanism mismatches are covered
  in the per-factor suites; both must fail closed.

## Observability

Factor verification outcomes are audited by go-qrdb's authentication path, not
here. go-xkms logs hardware-level failures (device absent, PIN required, session
error) with the correlation ID, which is the layer where a "login failed" is
actually diagnosable.
