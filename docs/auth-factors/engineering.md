# Auth Factors — Engineering Contract

> **Status: NORMATIVE** · Feature: `auth-factors` · Repo: `go-xkms` · Last verified: 2026-10-12

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
func NewNodeRegistry(cfg Config) (*qrdbsdk.AuthFactorRegistry, error)
```

`DefaultFactors` (`pkg/factor/registry.go:68`) returns, in order: `piv.New`,
`pkcs11.New`, `fido2.New`, `mtls.New`. It is the **single authoritative
definition** of the four factors. `NewDefaultRegistry` (`:93`),
`NewNodeRegistry` (`:114`) and every downstream composer call it rather than
building their own slice.

`NewDefaultRegistry` registers all four. It is the administrator-enrolment
registry: the xkms `mtls` factor enrols a `cert_pem` certificate and records
its `cert_spki_thumbprint` (`qrdbsdk.ComputeSPKIThumbprint`).

`NewNodeRegistry` registers every factor except `mtls`. An embedded go-qrdb
node is built with it (`server.NewNodeFactorRegistry`,
`pkg/server/server.go:1778`). The node's quorum ceremony enrols an mTLS share
holder by its certificate's public key, binds it by `qrdbsdk.CertThumbprint`,
and has it answer with `qrdbsdk.SignQuorumChallenge`. go-qrdb's own `mtls`
factor verifies exactly that whenever the registry does not override it. The
xkms `mtls` factor verifies a signature over the bare nonce against a PEM
certificate, so registering it on a node would refuse every ceremony mTLS
holder. Leaving it out adds no second verify or binding scheme.

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

### Decoy enrollments

Each factor's `*Factor` has the method set of go-qrdb's
`authfactors.DecoyEnroller`:

```go
func (f *Factor) DecoyEnrollment(seed []byte, userID string, like []*qrdbsdk.AuthFactorEnrollment) (*qrdbsdk.AuthFactorEnrollment, error)
```

`go-qrdb/sdk/go` does not re-export the interface yet. Each factor's
`decoy_test.go` therefore asserts the method set against a local interface of
the same shape.

What each decoy derives, and from what:

| Factor | Key | Other values |
|---|---|---|
| `piv` | predominant `algorithm` (`rsa2048`, `rsa4096`, `ecdsap256`, `ecdsap384`, `ed25519`) | predominant `slot`; self-signed certificate with `NotBefore` inside the span of `like`'s certificates |
| `pkcs11` | predominant PKIX key shape (ECDSA P-256/384/521, RSA 2048–8192 with e = 65537) | predominant `mechanism` of the key's family, `token_label`, `slot`; `key_id` in the predominant encoding and length |
| `fido2` | predominant COSE shape (EC2 P-256/384/521, OKP Ed25519, RSA) in canonical CTAP2 encoding | `credential_id` in the predominant base64 variant and length; `rp_id` and `origins` as a pair; `require_uv`, `aaguid` |
| `mtls` | the predominant certificate shape (key, issuer, signature algorithm) | the template's subject, SANs and extensions in order, with the holder's user id replaced (percent-encoded in IA5 names); derived serial of the predominant length; derived subject key id: truncated SHA-256 when the template's is, otherwise random bytes of the same length; validity period kept |

All four copy `ttl` from `like` when present, else use their own
`ChallengeTTLSeconds`. An empty `like` gives the form `Enroll` records under the factor's own
defaults:
- PIV: its configured algorithm and slot.
- PKCS#11: its default mechanism over a P-256 key (RSA-2048 when that
  mechanism is RSA).
- FIDO2: ES256 with a 32-byte credential id and the configured RP id.
- mTLS: a self-signed P-256 client certificate naming `userID`. Templates that cannot be
signed deterministically are skipped: RSA-PSS, and RSA public exponents other
than 65537.

Errors (`pkg/factor/internal/decoy`):

| Error | Cause |
|---|---|
| `*decoy.SeedError` | seed shorter than 16 bytes |
| `*decoy.UserIDError` | empty `userID` |
| `*decoy.RSASizeError` | RSA size outside 2048–8192 bits |
| `*decoy.DerivationError` | a derived value could not be built or encoded (names the purpose) |

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
  factor's `Challenge` copies the enrolled key into `MethodData`
  (`enrolled_cert_pem` for `piv`, `enrolled_public_key_der` for `pkcs11` and
  `mtls`, `enrolled_cose_public_key` for `fido2`). `Verify` reads the key
  from there and nowhere else, and returns
  `*qrdbsdk.AuthFactorVerificationFailedError` when it is absent. A response
  that could supply its own key could pass with any key the caller holds.
- **An mTLS challenge carries the enrolled key, never the certificate.**
  `mtls` stores the certificate PEM as `enrollment.PublicKey`, but `Challenge`
  exposes only its SubjectPublicKeyInfo (standard base64 PKIX DER). A
  CA-issued certificate verifies under its CA and a decoy's cannot (the decoy
  is signed by a derived key), so exposing the certificate would tell holders
  from decoys to anyone holding the CA certificate.
- **FIDO2 assertions are checked against the enrollment's RP, origin(s) and
  user-verification requirement.** `Verify` requires
  `authenticatorData[0:32] == SHA-256(rp_id)` (the `rp_id` carried in the
  challenge from the enrollment), the user-present flag, and a clientDataJSON
  of type `webauthn.get` whose `challenge` is the issued nonce (base64url)
  and whose `origin` exactly matches one of the enrollment's recorded
  `origins` (checked with the canonical `protocol.IsOriginInHaystack`
  comparator, per WebAuthn L2/L3 §7.2 step 9). It then verifies the signature
  over `authenticatorData || SHA-256(clientDataJSON)`.
  Enrollment records the origin(s) (`Enroll`'s `"origins"` MethodParam — a
  string or `[]string`, defaulting to `["https://" + rp_id]`) and the
  user-verification requirement (`"require_user_verification"`, a bool
  defaulting to **true** — the WebAuthn/CTAP2 best practice for a factor used
  to unseal or authenticate). When the recorded requirement is true, `Verify`
  also refuses an assertion whose `authenticatorData` user-verified flag is
  clear. An enrollment missing either field (e.g. one recorded before this
  requirement existed) is refused at `Verify`, the same as any other
  incomplete challenge — go-xkms is pre-release and carries no compatibility
  shim for it (go-xkms#1289).
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
| FIDO2 user-verified flag clear, and the enrollment requires verification | fails |
| FIDO2 clientDataJSON not `webauthn.get`, or not bound to the nonce | fails |
| FIDO2 clientDataJSON `origin` not one of the enrollment's recorded origins | fails |
| FIDO2 enrollment missing `origins` or `require_user_verification` (challenge carries no `require_uv`/`origins` MethodData) | fails |
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
  every enrollment, so changing it later invalidates them. The expected
  origin(s) and the user-verification requirement are per-enrollment
  `Enroll` MethodParams (`"origins"`, `"require_user_verification"`), not a
  `factor.Config` knob — see the FIDO2 bullet above.
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
  attestation CA bundle a login must prove its key against. Setting it puts
  the exchange in strict mode (below). Required when the exchange is enabled,
  unless the opt-out below is set; the config refuses to validate otherwise,
  and a bundle that names a file that does not load fails the daemon at
  composition rather than mounting an exchange that refuses every card.
- **`attestation_intermediates`** (`AttestationIntermediates`) — vendor
  intermediates the device does not present itself. Optional.
- **`allow_unattested`** (`AllowUnattested`) — accept logins nothing attests,
  minting `attest_level: unattested`. Off by default; the zero value is
  strict. It is mutually exclusive with `attestation_roots`: config
  validation refuses the pair, and `rest.NewServer` returns
  `ErrPIVLoginUnattestedWithAnchors`. Strict mode has no fallback.
- **`AttestationPolicy`** (`func(*pivcert.Attestation) error`, in process
  only) — a deployment profile run after the built-in one, on an attestation
  that already chains to the roots and attests the login key. Any error
  refuses the login. Use it for site rules such as "touch always" or a
  firmware floor. It is ignored without `AttestationRoots`.
- **`RecordedLevel`** — the server-side enrollment lookup. Without roots, a
  recorded `hardware` level is accepted and any other recorded level needs
  `allow_unattested`. With roots it is never evidence. It can only refuse a
  login whose record says the key is not hardware-backed.

#### Strict mode contract

With `AttestationRoots` set, `PIVLoginOptions.attestationLevel`
(`pkg/api/rest/handlers_auth.go`) admits a login as `hardware` only when one
certificate the client presents **after** the login certificate:

1. is not the login certificate itself (a login certificate that happens to
   chain to the roots is not evidence);
2. verifies through `pivcert.VerifyAttestation` to the configured roots. The
   other presented certificates, excluding the login certificate, are
   path-building material only;
3. carries the login certificate's `RawSubjectPublicKeyInfo`;
4. satisfies the built-in profile, which is the Yubico PIV attestation layout
   (arc `1.3.6.1.4.1.41482.3`): firmware version (`.3`), serial number
   (`.7`), and PIN and touch policy (`.8`) all present and parseable, with
   both policies known values. Form factor (`.9`) is not required;
5. passes `AttestationPolicy`, when one is set.

When several candidates fail, the refusal reports the one that got furthest
through these stages.

#### Refusal reasons

A refusal is an `*ErrPIVAttestationRefused{Reason, Cause}`. `Reason` is a
stable `PIVAttestationRefusal` code, and it goes on the `auth.login.piv` audit
event as `reason: "attestation: <code>"`. The client only ever sees `401
client certificate is not hardware-attested`.

| Code | Cause |
|---|---|
| `no_attestation_anchor` | No roots, no record, and `allow_unattested` is off |
| `recorded_level_not_hardware` | The enrollment record says the key is not hardware-backed, and the deployment does not accept that |
| `no_attestation_evidence` | Roots are set, but the client presented no certificate besides the login certificate |
| `attestation_chain_untrusted` | No presented attestation chains to the roots |
| `attested_key_mismatch` | An attestation chains, but for a different key |
| `attestation_profile_mismatch` | The attestation fails the built-in profile (`ErrPIVAttestationUnparseable`, `ErrPIVAttestationClaimMissing`, `ErrPIVAttestationPolicyUnknown`) |
| `attestation_policy_refused` | `AttestationPolicy` returned an error |

The result is recorded on the token (`attest_level`, carried through refresh)
and on the audit event.

### The client side of the `mtls` factor

`xkmsctl` presents a client certificate from PEM files (`--tls-cert`,
`--tls-key`, with `--tls-ca` for the server's CA; `cmd/xkmsctl/root.go:141-146`)
or from a PKCS#11 token (`--pkcs11-module`, `--pkcs11-slot`, `--pkcs11-pin`;
`root.go:161-166`). The token path goes through `NewPKCS11TLSConfig`
(`pkg/auth/pkcs11_tls.go:236`, re-exported at `sdk/go/tls.go:47`;
used at `cmd/xkmsctl/config.go:232`), which logs in as the user, finds the
certificate, then the private key with the same `CKA_ID`, and signs the
handshake on the token, so the key never leaves it. Its sentinels are
`ErrPKCS11ModulePathRequired`, `ErrPKCS11PINRequired`, `ErrPKCS11Login`,
`ErrPKCS11NoCertFound` and `ErrPKCS11NoKeyFound` (`pkcs11_tls.go:36-41`).

## Persistence

Enrollment records live in go-qrdb's user store, through `go-qrdb/sdk/go`.
go-xkms persists nothing for this feature — there is no local user model and no
local cert-binding scheme, by ownership rule.

## Test strategy

- **Unit** — `pkg/factor/registry_test.go` and `registry_wiring_test.go`. The
  wiring test is the one that matters: it asserts that the registry actually
  contains the four factors `DefaultFactors` names, which is what catches a
  composer that stopped calling it. `TestNewNodeRegistry_LeavesMTLSToQRDB`
  (`registry_test.go:47`) pins the node set, and
  `pkg/init/mofn_unseal_hw_factor_test.go` unseals a 2-of-3 barrier on it
  with PIV, mTLS and PKCS#11 share holders.
- **Per factor** — suites under `pkg/factor/{piv,pkcs11,fido2,mtls}`.
- **Helpers** — `pkg/auth_factors/{piv,pkcs11,webauthn}_test.go`,
  `auth_factors_extra_test.go`.
- **Integration** — `test/integration/fido2`, `test/integration/pkcs11`,
  `test/integration/webauthn-browser`, `test/integration/logins`.
- **Decoys** — `pkg/factor/{piv,pkcs11,fido2,mtls}/decoy_test.go` check:
  - determinism in (seed, userID);
  - challenge-shape parity with a real enrollment;
  - that `Verify` fails;
  - the empty-`like` default and the bad-input errors.

  `pkg/factor/internal/decoy/decoy_test.go` covers the shared derivation.
- **Fault injection** — expired challenges and mechanism mismatches are covered
  in the per-factor suites; both must fail closed.

## Observability

Factor verification outcomes are audited by go-qrdb's authentication path, not
here. go-xkms logs hardware-level failures (device absent, PIN required, session
error) with the correlation ID, which is the layer where a "login failed" is
actually diagnosable.
