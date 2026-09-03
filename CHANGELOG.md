# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **TPM and JWK ECDSA public keys are now validated as points on the curve**
  (#226). `pkg/tpm2` reconstructed `ecdsa.PublicKey` values from TPM ECC public
  areas by assigning the raw `X` and `Y` coordinates straight into the struct,
  across 11 sites in 8 production files; `pkg/encoding/jwk` did the same for
  the `x`, `y` and `d` members of an EC JWK. Assigning raw coordinates performs
  **no validation at all**: a point that is not on the curve, or the point at
  infinity, was accepted silently and then used as an EK, SRK, IDevID, IAK or
  attested-key identity. A broken, emulated or hostile TPM could therefore have
  an off-curve point accepted as an attestation identity.

  All of them now route through the new `pkg/crypto/ecpoint` helper, which
  assembles the SEC 1 uncompressed encoding and parses it with
  `ecdsa.ParseUncompressedPublicKey` / `ecdsa.ParseRawPrivateKey`. Those
  parsers reject an off-curve point and the point at infinity. Failures surface
  as `tpm2.ErrECCPublicArea` (wrapped as `ErrCertifyMalformed` on the certify
  path) and as `ecpoint.ErrInvalidPoint` / `ErrInvalidScalar` / `ErrCoordinateTooLong`,
  which remain reachable through `errors.Is` at every caller.

  **Operational impact.** This is a behaviour change on a security-critical
  path: a reconstruction that previously "worked" can now return an error.
  Anything that reports an invalid point was already producing a key that could
  not verify a signature, so an operator who sees `tpm2: ECC public area does
  not yield a valid public key` is looking at a device or emulator fault, not a
  new restriction — the EK / SRK read, IDevID and IAK issuance, TCG-CSR
  verification, `TPM2_Certify` verification and the attestation profile now fail
  loudly at the point of reconstruction instead of downstream at signature
  verification, or not at all.

  `pkg/crypto/ecpoint` **left-pads each coordinate to the curve's field size**
  before parsing. `TPM2B_ECC_PARAMETER` buffers and JWK members are not
  required to carry leading zero bytes, so a coordinate whose high byte is zero
  arrives short — roughly one in 256. Assembling `0x04 || X || Y` from those
  buffers without padding rejects perfectly valid keys, intermittently; this is
  the same failure mode fixed for the PKCS#11 EC point in #191. P-256, P-384
  and P-521 each have an explicit short-buffer regression test built from a
  deterministic fixture rather than a random key, because a round-trip test
  using only random keys passes ~99.2% of the time and hides it.

  One further hardening on the JWK path: `ToPrivateKey` now derives the public
  key from the `d` member and refuses a JWK whose `x`/`y` describe a different
  point, instead of returning an `ecdsa.PrivateKey` whose `PublicKey` field
  contradicts its own scalar.


- **`golang.org/x/crypto` v0.55.0 -> v0.56.0 across all four modules** (#201).
  Clears GO-2026-6355 and GO-2026-6354, both reachable from this repository —
  govulncheck names the trace as `pkg/ssh/session/dial.go:217:50`,
  `session.DialClient` calling `ssh.NewClientConn`. The failure was
  deterministic, so it turned Security Scan red on `main` and on every open PR
  simultaneously.

### Fixed
- **Software backend: `validateKeyType` no longer blesses ECDSA/Ed25519
  mismatches** (#53). The validator checked RSA only; ECDSA and Ed25519 fell
  through a `default:` arm commented *"basic validation is sufficient"* — the
  fail-open comment pattern — so an **Ed25519 private key declared as
  ECDSA-P256 imported successfully**, exactly as a consumer measured. Those two
  are the algorithms the signing policy uses (ed25519 by default, ECDSA-P256
  under FIPS), so the unvalidated pair was the pair that mattered: everything
  downstream reasons from the declaration rather than from the key — the
  storage identifier, the reported key spec, the algorithm a later operation
  selects — and a key stored under a false description poisons all of them.

  Every supported key type now has an arm (RSA, ECDSA, Ed25519, X25519), public
  keys of every algorithm are refused rather than only RSA ones, and a key type
  no arm recognises is refused instead of admitted. The declared EC curve is
  deliberately **not** compared against the key's own: `PKCS8Backend.ListKeys`
  reconstructs attributes from an identifier that carries no curve and reports
  P-256 for every ECDSA key, so copy, migrate and `C_UnwrapKey` all reach the
  validator through attributes built that way and a curve comparison would
  refuse working paths rather than catch wrong ones (#156 carries the caveat
  and the `ListKeys` fix it needs).

  Surveyed the other backends that import asymmetric material: `azurekv` is
  already fail-closed by type assertion, `awskms` restricts asymmetric import to
  RSA, and `tpm2`/`pkcs11`/`gcpkms`/`phone` do not parse caller-supplied PKCS#8
  on this path. `software` was the outlier.

- **MCP `xkms.importKey` can name the algorithm of the key it imports** (#53).
  `ImportKeyParams` had no key-algorithm field — its `Algorithm` is the
  *wrapping* algorithm — so the handler built attributes from the key ID alone
  and imported through the process default backend. The key was stored under an
  identifier ending in `unknown` that nothing else constructs, and the backend's
  check of material against its declared type had nothing to check against. The
  tool now takes `key_type` (required), `key_size` and `curve`, the same fields
  and vocabulary the REST and gRPC imports already use, and routes through
  `XKMSService.ImportKey` so all three transports build key attributes in one
  place and the request's backend is the backend written to.

- **PKCS#11 `C_UnwrapKey` carries the curve the template names** (#53). The
  unwrap request never set `TargetCurve`, and the service substitutes P-256 for
  an empty curve, so every EC key unwrapped through the module reached the
  backend described as P-256 — stored under attributes that misstate the key
  and reported as `ECC_NIST_P256` by `determineKeySpec`. `CKA_EC_PARAMS` is now
  resolved through the same `extractCurveFromParams` that `C_GenerateKeyPair`
  uses, and a value the module does not recognise is answered with
  `CKR_CURVE_NOT_SUPPORTED` rather than silently defaulted. An absent
  `CKA_EC_PARAMS` stays legal — v3.2 Table 13 footnote 6 says an EC private
  key's must not be specified on unwrap — and leaves the previous behaviour
  unchanged.

- **`web/desktop` module pins are no longer stale** (#205). The release path
  enumerated three modules and this repository has four, so `web/desktop` was
  left on the pre-release tags by both v0.9.0-alpha and v0.9.1-alpha and `make
  vet` failed, taking `main` red on Lint. The durable fix for the release path
  itself is tracked separately.

- **PKCS#11: exporting an ECDSA public key no longer fails for 1 key in 256**
  (#191). `exportECDSAPublicKey` decided whether `CKA_EC_POINT` held a bare
  X9.62 uncompressed point or a DER OCTET STRING wrapping one by testing
  `ecPoint[0] == 0x04 && ecPoint[1] == len(ecPoint)-2`. `0x04` is both the
  OCTET STRING tag and the uncompressed-point marker, so the first half of that
  test is true of every bare point and the whole thing reduced to "does the
  first byte of X happen to equal len-2?" — 0x3f on P-256, 0x5f on P-384, which
  is 1 key in 256 on each. When it hit, two bytes of X were discarded as a
  phantom DER header and the export failed with `invalid EC point encoding`;
  which keys were affected depended only on the key, so the failure looked
  intermittent. (P-521 was never affected: its len-2 is 0x83 and the first byte
  of a 66-byte P-521 X never exceeds 0x01.)

  The encoding is now decided by length, which is exact rather than
  probabilistic: a bare point on a curve over a `byteLen`-byte field is always
  `1 + 2*byteLen` bytes, and any DER wrapper is strictly longer, so no content
  byte of a point can move it from one case to the other. The curve is already
  known from `CKA_EC_PARAMS`. An attribute value that is neither form now
  returns a typed `ErrInvalidKeyAttributes` naming what it found instead of
  falling through to a best guess.

  Affects any PKCS#11 module that stores `CKA_EC_POINT` unwrapped. No
  configuration change; the wrapped encoding is decoded exactly as before.

- **`cert_der` PIV factor metadata is decoded as base64** (#199 follow-up).
  `pkg/auth_factors.decodeCertificate` named its variable `derB64` but passed
  the value straight to `x509.ParseCertificate` with no decode. Because
  `AuthFactor.Metadata` is a `map[string]string` that round-trips through
  JSON, and raw DER is not valid UTF-8, `cert_der` was a form that could
  either be stored faithfully or parsed — never both — while
  `MissingChallengeFieldError{Field: "cert_pem|cert_der"}` advertised it as an
  equal alternative to `cert_pem`. A caller who followed that message got a
  PIV factor that resolved normally and failed verification at login. The
  value is now standard base64 of the DER, and the doc comment says so.

  Raw DER in `cert_der` is now **rejected** rather than accepted, deliberately:
  accepting both forms would restore the ambiguity the defect is about, and a
  raw-DER value that has crossed any encoded transport is already corrupted.
  Nothing in the stack emits `cert_der` — go-xkms's own PIV factor records the
  certificate as PEM in `Enrollment.PublicKey`, and go-quicbaas requires
  `cert_pem` — so the accepted form is now unambiguous and that downstream
  narrowing can be lifted.


### Changed

- **`make release-alpha` cuts a correct release, and takes the version as an
  argument** (#58). The old seven-line recipe had four defects, every one of
  them measured while releasing v0.7.8-alpha and v0.8.0-alpha by hand: it could
  only ever bump PATCH, so a breaking pre-1.0 release was not expressible; it
  wrote `VERSION` and nothing else, leaving all nine reciprocal `go.mod` pins
  at the previous version, which no in-repo build can notice because they all
  resolve through local `replace` directives; a bare `git tag` aborted under
  the `tag.gpgsign=true` that `agent-git.sh` sets, so the target was unusable
  by the only thing that releases these repos; and `git push --tags` published
  every local tag rather than the three it created.

  The target is now `scripts/release-alpha.sh`, and the version is **stated**:
  `make release-alpha VERSION=0.9.2-alpha [BUMP=minor]`. Deriving it asks an
  open question — what is the greatest version anywhere? — whose answer depends
  on local tags, remote tags, reachability, malformed tags and three lockstep
  namespaces. Validating a stated one asks a closed question against a fixed
  checklist. `BUMP` is a declared intent, refused unless it agrees with
  `VERSION`, and it is what makes a breaking release expressible.

  The nine pin edges are **declared**, not counted. Comparing a count of pins
  found at the current version with a count at the next fails open twice over:
  a stale edge is in neither total and a deleted one is absent from both, so
  the totals match and the release ships a module that no longer pins its
  sibling. Each edge is checked by name at the current version before anything
  is written and at the new version after. Tags are annotated, explicitly
  signed with the signature confirmed on the object before any push, and
  published with `--atomic` so a lockstep release cannot half-publish immutable
  module tags.

  Two bounds rather than guards: the script refuses to start on a dirty tree,
  which deletes the "unrelated edits swept into the release commit" class
  outright, and its CHANGELOG preflight is anchored to the line start exactly
  as `release.yml` requires, so a heading the workflow would reject is caught
  before the tags become permanent. Hardening the remaining seams between the
  first read and the final push is #211, which needs an owner ruling.

- **BREAKING: `webauthn.allow_public_registration` now defaults to disabled**
  (#184, owner ruling 2026-09-01). An unset flag used to mean open self-service
  sign-up; it now means invite-only, aligning go-xkms with the stack-wide
  registration model (canonical flag `iam.self_service_registration.enabled`,
  default off) and the company secure-by-default convention: a setting that can
  silently produce an open surface is a defect.

  **Operator impact.** A deployment that relied on omitting the key now refuses
  WebAuthn registration for unknown emails; add
  `allow_public_registration: true` to restore open sign-up. Accounts
  provisioned through the authorized user-creation path still enrol their first
  passkey through the same endpoint — only implicit account creation is
  withheld, and the refusal now carries its documented wire contract
  (REST `403 registration_disabled`, gRPC/Unix `PermissionDenied`) instead of
  falling through to a 500/`Internal`.

  When xkms runs as a ServiceModule under go-quicbaas, the host-projected
  registration decision passes through verbatim and is authoritative; the
  secure default applies only when the host never decided.

- **FLAG DAY: device attestation is now challenge-response (protocol version 2)**
  (#129, #93, owner ruling 2026-08-24). Supersedes the embedded-challenge
  freshness model.

  A phone now holds ONE persistent hardware-attested key. Its
  SubjectPublicKeyInfo hashes to the stable `DeviceFingerprint`, and freshness
  is proved by a LIVE signature over the verifier's nonce rather than by a
  nonce baked into the attestation certificate.

  The old model could not work on Android and this is not a preference:
  Keystore fixes the attestation challenge at key GENERATION and offers no
  re-attest-existing-key API, so a per-pairing challenge forces a per-pairing
  key. A stable device identity and embedded-challenge freshness are mutually
  exclusive there, which made the per-device binding #93 required
  unimplementable as specified. Version 2 separates the two properties the old
  one conflated, and works unchanged on TPM devices, removing the asymmetry.

  **Operator impact.** After upgrading, a *new* pairing requires an xkey-android
  build that speaks version 2; an older app is refused rather than accommodated,
  because a peer that could decline the check by claiming an older version would
  choose its own security level. **Existing pairings keep working** under their
  recorded binding until re-paired, and are not reported as though they had the
  stronger one. `xkey device attest-device` upgrades a record in place.

  Wire contract, including byte-exact interop vectors:
  `xkey/docs/device/pairing.md` and go-xkms#129. A change to any published
  vector is a wire break, not an edit.

- **Device attestation is verified in one place** and consumed by every
  surface — pairing, reconnect, `device attest-device`, the FIDO2 and
  backend-based CLI commands, and the desktop GUI (#130 (a)).

  It previously lived in `cmd/xkey/cmd`, which the GUI cannot import, so the
  two surfaces established device trust by different rules. That is not a
  hypothetical cost: pairing verified chains `attest-device` did not (#95), the
  two derived the device identity differently (#93), the GUI performed no
  pairing attestation at all, and the GUI's record mirror silently dropped the
  attestation protocol version so a CLI-paired device read as unbound. The
  decision now lives in `xkey/pkg/attestation`.

  The GUI proves liveness **before** publishing a connection, and refuses a
  version 2 record when no trust store is configured.

### Fixed

- **BREAKING (display): `certstore.ToString` no longer prints a SHA-1
  fingerprint** (#197). It prints a SHA-256 fingerprint instead.

  `crypto/sha1.Sum` panics rather than erroring in FIPS 140-only mode, so every
  FIPS-activated process that formatted a certificate for display through
  `ToString` — exported by the SDK as `CertToString` — died on a human-readable
  thumbprint.

  The line is **removed, not conditioned on a FIPS check**. No predicate
  available can answer "is this a FIPS artifact": `GODEBUG=fips140=off` turns
  `fips.Compiled()` false even on a `GOFIPS140`-built binary (#219), so a guard
  would fail open for exactly the artifacts the policy cares about. Deleting the
  line leaves no predicate to get wrong, and `crypto/sha1` is no longer imported
  by the package at all.

  **Operator impact:** anything comparing this block against
  `openssl x509 -fingerprint` must switch to `openssl x509 -fingerprint -sha256`.
  Anything indexing the block by line offset must be updated. Nothing in this
  repository parses the value — `SHA-1 Fingerprint` occurred exactly once, at the
  print site — and both callers only print the result.


### Added

- **`fido2-attestation` certificate profile** (#232). The CA can now issue a
  FIDO2 authenticator attestation certificate that satisfies WebAuthn Level 2
  §8.2.1: Subject-C and Subject-O stamped from the issuing CA's own subject (the
  device cannot credibly assert its vendor's country or legal name), the literal
  Subject-OU `Authenticator Attestation`, Basic Constraints CA:false, and the
  `id-fido-gen-ce-aaguid` extension copied from the request. Select it with
  `SignOptions.Profile` / `SignCSRRequest.Profile` = `fido2-attestation`, which
  is what `xkey fido2 provision-attestation --profile` names.

  Before this, `SignCSR` dropped every CSR extension and asserted only the
  subject the CSR carried, so an attestation certificate had no Subject-C, no
  Subject-O and no AAGUID extension — a relying party rejects that, and the
  xkey provisioning command refuses it at install.

  The profile **refuses** rather than issuing something short: a request with no
  AAGUID, a malformed AAGUID, no common name, or an issuing CA whose subject
  lacks a country or organisation is rejected.

  **Trust assumption.** The AAGUID is copied verbatim; the CA does not check it
  against a registry of operator-vouched authenticator models, because none
  exists. The binding rests on the provisioning ceremony (device possession plus
  the Security Officer PIN) and on the CA being the operator's own.

- **`CertificateRequest.CSRExtensions`** carries the extensions a certificate
  signing request asked for through to `Profile.Apply`. The CA still copies no
  CSR extension by itself — a requester that could name its own basic
  constraints or key usage would be issuing to itself — so a profile opts into
  the specific extensions it understands. `fido2-attestation` is the only
  profile that does.

- **The version 2 `local.attestDevice` request carries no channel binding.**
  Each side derives it from its own Noise session; the transcript still commits
  to it. Sending it would make a prover that signs the supplied value
  indistinguishable from one that derived its own until the exact relay attack
  the binding prevents.

- **Pairing protocol error code `-32037`
  (`ErrorCodeAttestProtocolDowngrade`)**, reserved for a prover refusing a
  device-attestation request that does not ask under protocol version 2. It is
  the prover's half of the downgrade refusal: the verifier refuses a version 1
  answer, so the prover refuses a version 1 request. go-xkms never sends it —
  this repository is the verifier — but the number is reserved so a future
  method family cannot claim it.

- **`sdk/go`: `AndroidKeyAttestationOID` and `BuildAndroidAttestationExtension`.**

  Consumers verify Android key attestation through `sdk/go`, but could not
  BUILD an attestation extension through it — so a consumer testing its own
  verifier had to reach past the SDK into `pkg/attestation/android`, which the
  architecture boundary forbids and CI enforces. `BuildAndroidAttestationExtension`
  is deliberately a test-support API on the SDK surface: `pkg/attestation/android`
  already exported it for exactly that purpose, and it simply was not reachable
  through the boundary. A nil `RootOfTrust` builds a chain that verifies while
  claiming nothing about boot state — a case that exists to be REFUSED, so it
  has to be constructible on purpose.

### Security

- **MCP resolves a key by common name within the caller's tenant** (#166).
  `export_key` performed no tenant check: it resolved the key through an
  unscoped backend and took the first common-name match. A common name is
  unique only within a tenant, so one tenant could export another tenant's
  wrapped key material by naming its key ID — a read of key material across the
  tenant boundary.

  Both shared lookups (`findKeyInBackend`, `findKeyByCN`) now resolve through a
  backend scoped to the authenticated caller's tenant, which fixes every caller
  of them — export, delete, decrypt, encrypt, sign, verify, and the asymmetric
  and TLS-certificate paths — not just the export handler. `listKeys` is scoped
  by the same view, so a listing can no longer show a key the lookup then
  reports as missing, and `seal` / `unseal`, which each carried their own inline
  copy of the same first-match-on-CN scan, now resolve through the one shared
  lookup.

  The system tenant remains unscoped and still sees every key, matching the
  service layer's existing `resolveTenantBackend` predicate. A caller with no
  identity is unaffected.

  New on the service layer: `XKMSService.LookupTenantBackend` and
  `xkms.ScopeBackendToTenant`, so a transport that holds a backend name (or a
  backend) and a tenant gets the same scoped view the service's own request
  paths use, rather than reimplementing the predicate.


## [0.9.1-alpha] - 2026-09-02

### Fixed

- **The default backend was chosen by Go's randomized map iteration** (#171).
  Both `xkms.Initialize` — exported to embedders as
  `xkmssdk.ServiceInitialize` — and the daemon's `initializeKeyStore` took
  "the first" entry of the backend map when they had no usable configured
  default. Go randomizes that order by design, so the same binary on the same
  configuration resolved a different default on each start: 500 constructions
  over four backends selected all four (318/63/62/57).

  The default is not cosmetic. It decides where keys generated or imported
  without an explicit backend are stored, and therefore their `StoreType`
  segment in `KeyAttributes.ID()`, so a key written before a restart could be
  looked for in a different store after one, with nothing logged to explain it.

  Resolution is now one rule, `xkms.ResolveDefaultBackend`, already applied on
  the auto-configuration path and now shared by all three: the requested
  backend when it is loaded, then the software backend, then the alphabetically
  first name — every step a function of the backend names alone.

  Reached differently by each caller, deliberately. `xkms.Initialize` still
  fails closed on a default that was configured but not loaded
  (`ErrDefaultBackendNotFound`) and consults the rule only when none was
  configured. The daemon keeps starting in that case — a `default_backend`
  naming a backend absent from the build is not fatal — but now logs a warning
  naming the configured and resolved backends instead of substituting one
  silently. Embedders who relied on an arbitrary default with several backends
  loaded and none named will see a stable choice, which may differ from the one
  a given run happened to make.

- **Release `v0.8.0-alpha` did not contain the fix it was cut for** (#195).
  The tag pointed at `3b227eee`, which predates `efdf8d76` (#190,
  "resolve logins by the canonical email key"), so every consumer
  resolving a tag still got the broken email resolution. Nothing in the
  repo could see this: the fix was on `main`, the tag looked current, and
  only `git merge-base --is-ancestor <fix> <tag>` distinguishes them.
  Downstream, go-quicbaas#359 stalled against it.

  `v0.9.0-alpha` carried the fix but was rejected by `Release / Validate
  tag` for having no CHANGELOG section; this release supersedes it. The
  two are identical in code — the published `v0.9.0-alpha` module is
  usable, it simply has no release pipeline behind it.

### Changed

- go-qrdb pinned to `v0.16.0-alpha` (from `v0.15.0-alpha`), which brings
  go-quicraft `v0.9.0-alpha`. A zero-source-change bump here: all three
  modules build and `pkg/auth`, `pkg/apimodule`, `pkg/storage`, `pkg/api`
  and `pkg/webauthn` pass under the full tag set.

  Pinned deliberately rather than left to drift. go-quicbaas requires
  go-qrdb `v0.16.0-alpha`, so MVS hands it to go-xkms regardless of what
  this module declares — better that the pin is tested here than
  discovered at a consumer's integration. It also resolves the
  `seal.StorageBackend` / `CompareAndDelete` break that `v0.8.0-alpha`
  presented to consumers on qrdb v0.15.

- Cross-module requires bumped to `v0.9.1-alpha` in all three `go.mod`
  files. `make release-alpha` does **not** do this (Makefile:4342 tags the
  submodules but never rewrites the requires), and the local `replace`
  directives hide the omission because a `replace` inside a dependency
  module is ignored by consumers. Releases are cut by hand until PR #73
  lands.

## [0.8.0-alpha] - 2026-08-20

**MINOR, not PATCH**: this carries a breaking API change, and pre-1.0 that is
what MINOR means ([release-versioning.md](https://198.51.100.91:3001) §1).
`make release-alpha` only increments PATCH, so this was tagged by hand.

**`agent.Session.Stop` now takes a context and returns a `ShutdownReport`.**
v0.7.8-alpha bounded shutdown with a fixed internal constant and returned
nothing — the silent bounded stop: it re-introduced, as an *undocumented*
surprise, the thing the connection drain was built to prevent, with the bound
chosen by the library rather than by whoever is shutting down.

Upgrading from v0.7.8-alpha: `defer sess.Stop()` becomes
`defer sess.Stop(context.Background())`, or pass a deadline and read the
report. `connect.Session`'s `Stop`, `Sync` and `SyncAndStop` take one too.

The hardening below is mostly in code v0.7.8-alpha did not change. What
changed is that its errors and bounds became *meaningful*: making an error
real is a change to every caller that ignores it, and bounding a call is not
free, because every fail-open beneath it turns a timeout into a silent
success.

### Changed

- **BREAKING: `agent.Session.Stop` takes a context and returns a
  `ShutdownReport`** (#55, owner ruling on #52). v0.7.8-alpha bounded shutdown
  with a fixed internal constant and returned nothing, which is the silent
  bounded stop: it re-introduced, as an *undocumented* surprise, the very thing
  the connection drain was built to prevent, with the bound chosen by the
  library rather than the caller.

  Neither pure horn is acceptable — an unbounded `Stop` hands control of a
  worker's lifetime to a wedged TPM, and a silent bounded one hides a real
  residual. So `Stop(ctx) ShutdownReport`: the listener closes and every
  attached client is disconnected **unconditionally**, before any waiting, so
  no new client can attach and no new signing operation can start; the
  connection handlers are then joined within `ctx`, and the report names how
  many were abandoned. Never a bare nil.

  The residual, documented rather than discovered: an abandoned handler may
  still deliver a signature to a client that attached *before* `Stop` began. No
  new authorization occurs — that client was already served by an authorized
  session. Re-exported as `AgentShutdownReport`.

  Callers upgrading from v0.7.8-alpha change `defer sess.Stop()` to
  `defer sess.Stop(context.Background())`, or pass a deadline and act on the
  report. `connect.Session.Stop` takes a context and returns the same report
  for the same reason — a layer that picks the bound on a caller's behalf is
  choosing when to give up on their behalf too.

## [0.7.8-alpha] - 2026-08-20

**Agent-only SSH sessions**: an xkms-held key served over an ephemeral
in-process SSH agent socket with no connection target, for tools that speak
the ssh-agent protocol without dialing a host. The motivating consumer is git
commit signing under `gpg.format=ssh`; `ssh-keygen -Y sign` and `age` use the
same socket.

This also hardens `pkg/ssh/agent` considerably, and most of that hardening is
in code this release did not otherwise change. Nothing about that code moved —
what moved is its exposure: it stopped being an internal detail of one call
path and became a primitive any consumer can point at any key, which raises
the security bar it has to meet. The Security section below is the cost of
that promotion, paid here rather than inherited.

Two behaviour changes worth reading before upgrading: an RSA key served over
an agent socket **no longer signs with SHA-1**, so a server accepting only
legacy `ssh-rsa` will not authenticate with one; and `agent.Listen` no longer
clears a stale socket, so a leftover from a crashed run is the directory
owner's to remove.

### Added

- **SSH SDK: agent-only sessions (`xkmsssh.StartAgent`)** (#52). Serves
  xkms-held keys over an ephemeral in-process SSH agent socket with **no
  connection target**, for tools that speak the ssh-agent protocol without
  dialing a host — `git commit -S` under `gpg.format=ssh`, `ssh-keygen -Y
  sign`, `age`. `Keys().Signer` returns an in-process `ssh.Signer`; those
  tools need a socket. `StartConnect` had the agent machinery but demanded a
  Host/Port/User and known_hosts seeding that a signature has no use for.
  The socket is bound synchronously (connectable when `StartAgent` returns,
  bind failures typed as `*AgentListenError`) and dies at the first of
  `Stop()` or context cancellation, taking an owned work directory with it.
  No host-key semantics are implied: `StartAgent` neither seeds nor consults
  `known_hosts`. Only the public half ever reaches disk. Documented in the
  new [`docs/ssh-agent-sessions/`](docs/ssh-agent-sessions/) feature folder,
  which is normative for this capability; the rest of `docs/ssh/` remains
  unconverted legacy.

### Changed

- `pkg/ssh/agent` gained an internal listen/serve split (`Serve` is unchanged
  and now composes them) so the socket can be bound before serving begins. The
  raw binder stays unexported: `net.Listen` binds before the mode is applied,
  so for an arbitrary path there is a window in which the socket carries
  whatever the umask left it, and only a 0700 containing directory closes it —
  which `StartSession` can promise and a raw path cannot.
  Shutdown closes every attached client and joins its handler, and unlinks the
  socket exactly once — by closing the listener — so a successor session on the
  same `WorkDir` cannot have its live socket deleted by a predecessor's late
  cleanup. **`Listen` no longer clears a stale socket** — an
  occupied path is refused with `ErrSocketInUse` (an agent answers there) or
  `ErrPathOccupied` (anything else), re-exported by the SDK as
  `ErrAgentSocketInUse` and `ErrAgentPathOccupied`. Clearing one needs
  inspect-unlink-bind, and between those steps another process can bind its
  own live agent at that path, which the unlink then destroys. A leftover from
  a crashed run is now the directory owner's to remove. This is a behaviour
  change to the pre-existing `Listen` / `Serve` path, which had no in-repo
  callers.
- `pkg/ssh/connect.Start` drives the new `agent.StartSession` instead of
  carrying its own copy of the agent plumbing; its 3-second socket poll (and
  the `time.Sleep` in it) and the `LaunchError{Op: "agent socket"}` it could
  return are gone, because the bind is now synchronous. Its error contract is
  unchanged: agent setup failures are still `*connect.LaunchError`
  (`Op: "agent session"`), with the cause reachable through `Unwrap`. `WorkDir`
  still means "create the scratch area here", so `connect` creates it — the
  agent deliberately will not conjure a directory it would not own — and every
  path derived from it is absolutised, because the socket and the seeded
  `known_hosts` both leave this process for a child with its own working
  directory.

### Security

- **RSA keys served over an agent socket never sign with SHA-1.** An unflagged
  `SIGN_REQUEST` is an ssh-agent client's default rather than a deliberate
  choice, and x/crypto's default for an RSA signer is the legacy `ssh-rsa`.
  With `StartAgent` making the agent reachable by any ssh-agent client, that
  would hand out a non-approved primitive on request under the project's FIPS
  140-3 requirement. RSA requests now get `rsa-sha2-256` (or `-512` when
  flagged), and an RSA signer that cannot select an algorithm is refused with
  `*UnsupportedAlgorithmError`. **Behaviour change**: a server that accepts
  only legacy `ssh-rsa` will no longer authenticate with an RSA key served
  this way.
- **`StartAgent` has no `WorkDir` option**; the session always creates its own
  private directory. A socket's 0600 mode does not protect its *pathname* — the
  containing directory governs who may replace it — and validating a
  caller-supplied directory is inherently check-then-use, because an attacker
  controlling any ancestor redirects the path between the check and the bind.
  Closing that needs an anchored no-follow bind, which
  `net.Listen("unix", path)` cannot express. The option is absent rather than
  guarded by a check that looks like a guarantee and is not. `pkg/ssh/agent`
  still accepts a directory for `pkg/ssh/connect`, which supplies one it
  created itself, and validates it (`*InsecureWorkDirError`: symlink, foreign
  owner, group/world-writable).
- **Shutdown terminates even when a signer does not.** Closing the listener and
  disconnecting every attached client are unconditional; joining the connection
  handlers afterwards is bounded. A handler stuck inside an uninterruptible
  `Signer.Sign` (a TPM awaiting touch, a stalled KMS) cannot be woken by
  closing its connection — but it also cannot answer anyone, because that
  connection is already closed. Waiting forever would hang `Stop()` and leave
  the work directory unreaped to guard against an oracle with nobody to talk
  to.
- **Typed-nil signers are rejected.** A nil pointer boxed in an `ssh.Signer`
  passes an interface nil check, and the first `PublicKey` call would panic in
  the serving goroutine, taking the process down.
- **`agent.Serve` validates the socket's parent directory** on the same terms
  `StartSession` applies. It takes an arbitrary path, so without that a caller
  could bind a signing socket in a shared directory — where the bind-to-chmod
  window is reachable and the pathname can be replaced outright.
- **Off Unix, a caller-supplied work directory is refused.** The isolation this
  package relies on is expressed in Unix mode bits; Windows ACLs are inherited
  rather than implied by a `Mkdir` mode, invisible to `fs.FileInfo`, and not
  comparable against a uid. A check that cannot see the permissions it is
  checking must not return "safe". Sessions that create their own directory are
  unaffected — `os.MkdirTemp` lands under the platform's per-user temp
  location, which is the OS's isolation rather than a claim made here.
- **`connect.Session` teardown is synchronised, and cannot be held hostage.**
  `Sync` and `Stop` touched `knownHostsFile` and the agent handle unguarded
  while `Sync`'s own doc says the GUI polls it on a live session — a data race,
  and one that could delete the known_hosts out from under a running import,
  losing exactly the first-contact pins `Sync` exists to capture. `Stop` now
  stops the agent first and independently: the import runs against a
  caller-supplied store over a context this session does not control, so
  holding a lock across it would let a stalled backend keep a signing agent
  alive. Removing the work directory waits for an in-flight `Sync`, but only
  briefly.

## [0.7.7-alpha] - 2026-08-20

A dependency release: **go-qrdb v0.6.0-alpha → v0.9.0-alpha**, with
go-quicraft v0.6.2-alpha → v0.8.0-alpha and go-objstore v0.2.2-alpha →
v0.3.0-alpha arriving through minimal version selection. Root, `sdk/go` and
`xkey` all move together.

### What this release does and does not change

**No behaviour of go-xkms itself changes** except where the adopted version
required it, described below. No API is added, removed or migrated, and no
custody path is altered.

**The exception is an adaptation you should understand, because it looks
like a one-line error change and is actually a protocol fix.** Since go-qrdb
v0.8.0-alpha, `pkg/dao` *negotiates* index capability: it calls
`RegisterEntityIndexes` when a DAO is constructed and reads the reply. An
error matching go-qrdb's `ErrKVIndexUnsupported` means "this store has no
index subsystem, plan full scans"; **any other error means construction
failed**. Previously the refusal was ignored.

`pkg/storage/kvadapter` cannot maintain secondary indexes — it bridges an
opaque byte-oriented `storage.Backend` and never decodes entity payloads —
and it refuses index operations for that reason. But it reported only its
own sentinel, which go-qrdb does not recognise, so a *capability signal* was
read as a *hard failure* and every DAO built over the adapter refused to
construct. `IndexingNotSupportedError` now matches both sentinels: the local
one, so existing callers keep working, and go-qrdb's, so the DAO plans scans.
The same value is re-exported as `xkms.ErrIndexingNotSupported`, and
consumers may test for either.

### Known gaps, stated plainly

**The deprecated Shamir share API is suppressed, not migrated.** quicraft
v0.8.0-alpha deprecates `Split` and `Share.Value` in favour of
`SplitProtected`/`ProtectedShare`, because a Go string cannot be wiped and a
ceremony holding all N shares is the widest exposure in the scheme. Eight
call sites — all in test helpers, no production path — carry per-line
`//nolint:staticcheck` directives rather than being migrated, because
changing key custody inside a dependency bump would be the wrong place to do
it. Tracked separately; closing that work means deleting every directive.

### Fixed

- `kvadapter.IndexingNotSupportedError` now satisfies `errors.Is` against
  go-qrdb's index-capability sentinel as well as its own, restoring DAO
  construction over `KVStoreAdapter` under go-qrdb ≥ v0.8.0-alpha.
- The ACME remote-transport adapter (`pkg/acme/qrdb`) had the same defect on
  all five of its index methods, and it was **not** latent: `NewProvider(svc,
  nil)` — the documented default — installs that adapter, so the default
  remote ACME path could not construct a DAO at all under v0.9.0-alpha. All
  five now refuse with an error the go-qrdb DAO recognises, and a regression
  test asserts this **through `NewProvider(svc, nil)`** rather than only
  through a hand-built adapter.
- `release.yml` installs Go in its `Validate tag` job. Without it the job
  died at `go: command not found` and **no release after v0.7.4-alpha
  produced a release object, binaries or checksums**.
- `release.yml` gained a `workflow_dispatch` tag input so an already-published
  tag can be rebuilt without moving it, and now stamps binaries with the
  released commit rather than the branch HEAD a dispatch ran from.

### Changed

- go-qrdb v0.6.0-alpha → v0.9.0-alpha (root, `sdk/go`, `xkey`)
- go-qrdb/sdk/go v0.6.0-alpha → v0.9.0-alpha
- go-quicraft v0.6.2-alpha → v0.8.0-alpha (via MVS)
- go-objstore v0.2.2-alpha → v0.3.0-alpha (via MVS)

## [0.7.6-alpha] - 2026-08-19

### What this release does and does not guarantee

Read this before the entries below, because the headline is easy to
over-read.

**Closed: the lifetime axis.** A Noise static key held in protected memory is
now owned by exactly one component, and nothing reads it while it is being
destroyed. Every reader synchronises against the destroyer; every generated
key has an owner that frees it; no path frees a key another goroutine is
still decrypting through. That is what the ~35 fixes in this release are.

**NOT closed: the escape axis.** The phone-pairing Noise private key is still
persisted as a base64 string in YAML, and `LocalNoisePrivateKey string` is
still an ordinary Go string for the whole life of a loaded config. Go strings
are immutable, so that copy cannot be wiped, and the file is plaintext at
mode 0600 — protected by filesystem permissions only, not by protected
memory and not sealed at rest. This is pre-existing and unchanged by this
release; it is not a regression, and it is not fixed either.

So: **"Noise keys are held in protected memory" is true of their lifetime in
process and false of their persisted form.** Closing the second half needs a
config-format migration and a decision about whether that key should be
sealed rather than plaintext-0600. That is an open owner decision, tracked
separately. Anyone relying on this release for at-rest protection of the
phone-pairing key does not have it.

**Third thing, on the shutdown paths.** When a shutdown cannot confirm that
every reader has stopped, it keeps the protected key rather than freeing it,
and reports `ErrShutdownIncomplete`. **That retention is permanent for the
life of the process, not deferred.** Nothing reclaims the key afterwards:
the component is closed, its references are cleared, and there is no retry.
memguard's only reclamation is `secure.Purge`, which destroys every locked
buffer in the process at once — a shutdown operation, not a way to recover
one leaked key while the program runs. `xkmsd` arms it; the `xkey` binaries
do not arm it at all. So repeated shutdown timeouts accumulate locked pages
against the process memlock limit for as long as the process lives. It is
still the right trade against freeing pages a live goroutine is decrypting
through, but it is a real cost and it is stated here rather than implied
away.

### Changed

- **BREAKING — `go-truststrap` protected-memory Noise API adopted**
  (`v0.1.3-alpha` -> `v0.2.0-alpha`). Static Noise keys are now
  `*noise.StaticKey` values living in guard-paged, swap-locked memory rather
  than `[]byte` and `string`. The wrapper layer in `xkey/pkg/pairing` follows
  the same shape, so the encode direction writes into a caller-supplied
  buffer instead of returning a string that can never be wiped:

  ```go
  // before
  func EncodeStaticKey(key *DHKey) string
  // after
  func EncodeStaticKey(dst []byte, key *StaticKey) error
  ```

  `GenerateStaticKey`, `LoadStaticKey` and `DecodeStaticKey` now return
  `*StaticKey`, and `NoiseSessionConfig.LocalStaticKey` is a `*StaticKey`.
  Callers own what they generate and must `Destroy()` it.
- **`go-qrdb` `v0.5.9-alpha` -> `v0.6.0-alpha`** across all three published
  modules, in lockstep.
- **`xkmsctl bootstrap noise-key` writes to a file and no longer prints the
  private key to stdout.** `--output` is now required. The file is created
  `O_EXCL` at mode 0600, a short write is treated as an error, and a partial
  file is removed rather than left behind. The encoded key is staged in a
  protected buffer that is destroyed on return. (Owner ruling: writing the
  key to a file is acceptable; printing it to a terminal, scrollback and
  shell history is not.)

- **BREAKING — shutdown can now report that it did not finish cleanly.**
  `(*phone.PhoneKeyBackend).Close` and `(*phone.BLEPeripheral).Stop` return
  `phone.ErrShutdownIncomplete` when a reader could not be confirmed stopped
  within the shutdown window. Both were previously `nil`-always on that path.
  The component IS shut down either way and needs no second call. The error
  says the component could not prove it finished — for `Close`, and for
  `Stop` when a connection did not drain, that means the protected key was
  retained; `Stop` also returns it when an advertisement could not be taken
  down, which does not retain the key because nothing reachable through an
  advertisement reads it. **A caller that supplied the key and kept ownership
  must not destroy it after seeing this** — that is exactly the
  use-after-free the retention avoids.

### Added

- **`sdk/go/transport/usb` re-exports `ErrDirtyState`**, the sentinel
  `Connect` now returns when the transport still holds state from a previous
  connection. It was added to the implementation in this release and left out
  of the SDK, so an SDK consumer could see the refusal and not identify it.
  A test pins every sentinel in that package as the same value the transport
  returns, since a re-export that drifted into a separate `errors.New` would
  compile and pass every in-repo test.
- **`sdk/go/bootstrap` re-exports the whole Noise key surface**, not most of
  it: `NoiseHexKeySize`, `NoiseServerStaticKey` and `WipeNoiseBytes` join the
  generate/encode/decode helpers that were already there. Consumers are
  required to use the SDK boundary rather than `pkg/trust/bootstrap`, and
  without these three an SDK-only caller could generate a protected key,
  could not size a buffer to encode it, could not hand it to
  `NoiseServerConfig`, and could not wipe the buffer afterwards. The same
  composition gap appeared one layer down earlier in this release; each half
  compiled on its own, and nothing exercised the combination. There is now a
  test that walks generate → adapt → encode → decode → wipe using only what
  this package exports.

### Removed

- **BREAKING — `(*pairing.NoiseSession).LocalStaticPrivateKey()` is gone**,
  and with it the same method on the `phone.NoiseSession` alias. It handed
  the protected static scalar back to any caller as an ordinary `[]byte`,
  which is precisely the guarantee the rest of this release implements —
  a public accessor that copies protected material out of protection
  contradicts holding it in protection at all. It had no non-test caller in
  the tree. Removed under the pre-1.0 MINOR breakage allowance
  (`release-versioning.md` §1) because leaving it costs more than removing
  it. `LocalStaticPublicKey()` is unaffected: the public half is what callers
  legitimately need, and it identifies the scalar in use without exposing it.

### Security

- **The Noise bootstrap server's static key is no longer freed while the
  server is running.** `startNoiseBootstrap` destroyed it on the way out, on
  the stated premise that `Start` blocks until shutdown. It does not:
  `noiseboot.Server.Start` binds the listener, launches its accept loop in a
  goroutine, and returns. The protected pages were therefore freed while the
  published server and every subsequent handshake still aliased them, so any
  client connecting afterwards read freed memory. The key now belongs to the
  `Server` and is destroyed in `Shutdown`, and only when `Stop` both returns
  nil AND its deadline has not expired. Neither alone is proof: upstream
  `Stop` returns nil whether it drained or timed out, and it also returns
  immediately without waiting for anything when it does not consider itself
  started, which leaves the deadline unexpired. Without both the key is
  retained.
- **Shutdown results are propagated, not logged and dropped.** The components
  learned to report an incomplete drain earlier in this release, and every
  layer above them discarded it: `PhoneService.Disconnect` returned nil over a
  timed-out teardown, `Server.Shutdown` swallowed both the Noise drain timeout
  and its own global deadline, and `xkey device listen` exited 0 after a
  handler-drain timeout. A contract that is correct and unread is the same
  fail-open one layer up. `Server.Shutdown` and the CLI now return the
  incomplete result; `PhoneService.closeActiveConnectionLocked` returns an
  error its three callers act on.
- **`Server.Shutdown` is latched.** Concurrent callers raced into
  `close(s.shutdownCh)` and panicked on close-of-closed, and each independently
  stopped the bootstrap server and could destroy the same protected key twice.
- **The bootstrap server is published only after it starts.** Publishing
  first left a window where `Shutdown` could snapshot a server that had not
  started, call `Stop` on it — which returns immediately without waiting for
  anything — read that as a clean drain, and destroy the key before the
  accept loop ever ran. Publication and the shutdown check now happen under
  one lock, so either `Shutdown` sees a started server or the startup path
  sees the cancelled context and stops the server itself.
- **`TCPPairingServer.Stop` bounds its wait and no longer holds the lifecycle
  lock across it.** Connection workers call a caller-supplied handler
  synchronously, so closing the socket does not interrupt one that ignores
  cancellation — the wait could never return. Holding the lock across it also
  deadlocked any handler that called `LocalStaticPublicKey`. `Stop` now
  returns `ErrShutdownIncomplete` and retains the key when the join times out.
- **Every retention path keeps the key reachable rather than clearing the
  field.** The pages survive either way — memguard pins every live buffer in
  a package-level list, and has no finalizer — but "we are retaining this"
  and "we dropped the only pointer to it" should not look identical in the
  source, and holding the owner is what a future reclamation path would need.
  A test pins the upstream assumption so a change to it fails there rather
  than in a shutdown path nobody runs.
- **A supplied key whose ownership transfers is consumed from the config.**
  `OwnsStaticKey` recorded the backend as owner but left the pointer in the
  caller's config, so a second construction from the same config produced two
  owners of the same protected pages and whichever closed first freed pages
  the other's session was reading. This is the mirror of the write-back
  hazard fixed earlier in this release: that one added a key the caller never
  supplied, this one failed to remove one the caller gave away.
- **Connection teardown detaches its generation before draining.** The
  bounded drain releases the connection mutex — that is what lets in-flight
  operations finish — and a concurrent `Connect` could publish a new
  transport, session and key in that window. Teardown then cleared the new
  session and destroyed the new key. It now snapshots what it is tearing down
  before the wait and destroys only that.
- **`MessageRouter.Start` registers under the router mutex, and `Join`
  refuses to report a drain before `Stop`.** The single-waiter join latches
  whatever it first observes, so a `Join` running before `Start` could latch
  "drained" on an empty wait group and keep reporting success while the
  receive loop was alive — telling the owner it was safe to destroy a key
  being actively read. `Start` is now a no-op on a stopped or already-started
  router, which is also what a `WaitGroup` requires: an `Add` from zero must
  happen before any `Wait`.
- **Every Noise static key now has exactly one owner.** Previously a
  generated key could be destroyed by a component that had merely borrowed
  it, or leaked because no component considered itself responsible. Ownership
  is decided once, at construction: a backend destroys the key it generated,
  or the one a caller explicitly transferred to it, and never one it
  borrowed.
- **The constructor no longer writes a generated key back into the caller's
  config.** A reused config would otherwise hand the next backend a key the
  first one owns and destroys, leaving the second reading freed protected
  pages. Ownership is now tracked in an unexported field the caller cannot
  observe or reuse.
- **Readers are synchronised against destruction, everywhere.** The USB
  transport serialises its whole `Connect`/`Close` lifecycle under one lock
  rather than checking a flag and acting on it later; `Connect` re-checks the
  closed state in-lock; the TCP pairing server and the BLE peripheral join
  their connection goroutines before releasing key material; the phone
  backend drains outstanding session leases before destroying anything.
- **`Close` retains an owned key rather than freeing it under an unjoined
  reader.** If the message-router join cannot be confirmed within its
  timeout, the key is deliberately NOT destroyed. Leaking protected pages is
  the safe failure mode; freeing pages a live goroutine is decrypting through
  is not.
- **`bootstrap.NoiseServerStaticKey` replaces an alias that no longer
  composed.** `NoiseStaticKey` became a protected `StaticKey` while
  `NoiseServerConfig.StaticKey` still took a `*noise.DHKey`, so the two
  re-exports could not be used together by an outside caller even though
  both compiled in isolation. The adapter returns a pair that aliases the
  protected pages rather than copying them.
- **Decoded key buffers are wiped on every path**, including the failure
  paths that previously returned early with the buffer live.

### Fixed

- **Every shutdown drain is bounded, not just the router join.** Three waits
  added by this release waited without a bound on work the package does not
  control, so each was a shutdown that could hang forever:
  `PhoneKeyBackend.Close` (waiting for session leases, while holding the
  mutex every other method needs), `BLEPeripheral.Stop` (waiting on a
  caller-supplied `RequestHandler` with a context it neither owns nor
  cancels), and the GUI phone service's teardown (waiting on a BLE round trip
  with a handset that may never answer).

  The bounded-join lesson had been applied at exactly one site and not
  carried to the shape. All four now go through one primitive, and all four
  take the same branch on timeout: retain the protected key, report it, do
  not free pages a reader may still be using.
- **The USB transport drops its bus handle when it closes it.** `Close` shut
  the underlying transport down but left it installed, and `Connect` only
  builds a new one when the field is nil. The production USB transport treats
  `Close` as terminal, so `ErrDirtyState`'s own advice — close, then
  reconnect — could not be followed: the dirty check passed and every
  reconnect handshaked over a dead bus. `Connect`'s own failure paths drop it
  too. The lifecycle tests missed this because their fake is reusable; there
  is now one whose `Close` is terminal.
- **A failed bridge setup no longer leaks the xkmsd client and TPM
  enroller.** `EnableBidirectional` gained an error return in this release,
  which gave `newPhoneBackendWithBridge` a failure path it never had, and
  the resources acquired above it have no other owner until the wrapper is
  built. It now mirrors the cleanup the adjacent `NewBridge` failure already
  did.
- **`xkmsctl bootstrap noise-key` no longer deletes a file it did not
  create.** The failure cleanup called `os.Remove(path)`, which unlinks
  whatever holds the name at that moment rather than the file the failure
  produced. Anything with write access to the parent directory could rename
  the partial key away and drop an unrelated file at the same path in
  between, and the cleanup would delete that instead. The removal is now
  gated on `os.SameFile` against a stat taken while the descriptor is still
  open; when identity cannot be established the file is left alone, because
  a stranded partial key is reported and refused by the next run's `O_EXCL`
  while a wrong unlink is silent and irreversible.
- **`MessageRouter` shutdown is split into `Stop()` and `Join(timeout)`.**
  `SendRequest` now registers on the wait group with a check-and-`Add` under
  the router mutex, so a request in flight cannot race a shutdown that has
  already observed an empty group. The previous unconditional wait could hang
  indefinitely, because `receiveLoop` blocks in an uncancellable
  `Transport.Receive` and only observes shutdown between messages. Making
  `Receive` cancellable is tracked as go-xkms#30 and is NOT required for
  memory safety — see the retention behaviour above.
- **`EnableBidirectional` returns an error, requires a connected backend, and
  is idempotent** instead of silently starting a second router.
- **`e2eprobe` tears down in order** — signal, unblock, join, then release —
  rather than relying on three LIFO defers whose order was wrong.
- Corrected a comment in `message_loop.go` that claimed `receiveLoop` manages
  its own lifecycle via the done channel. It does not; that claim is what
  made the original unconditional join look safe.

### Known limitations

- The phone-pairing Noise private key is persisted as base64 in YAML and held
  in an unwipeable Go string while loaded. See the guarantee note at the top
  of this release.
- `usb.NoiseConfig.LocalStaticPrivateKey` remains a public `[]byte`. It is
  caller-supplied rather than produced by this package, so it is part of the
  same storage-format question rather than a separable fix.
- **Which parts of this release are backed by execution, and which are not.**
  Worth knowing, because it is not uniform:
  - `xkey/pkg/phone`, `xkey/pkg/pairing`, `xkey/internal/lifecycle` and
    `pkg/trust/bootstrap` pass under `-race`, under the default tags and
    under `-tags ble`, and every behavioural fix in them has a test that
    fails against its own regression.
  - `xkey/cmd/xkey/cmd` **cannot compile its test binary under `-tags ble`**
    (go-xkms#31) — pre-existing on the v0.7.5-alpha tag, but it means that
    package's ble-tagged tests have never run.
  - `-tags usb` cannot be vetted or tested without libusb-1.0 headers, which
    CI does not install. That surface is verified by build and review only.
  - Ten packages in the `xkey` module and eight in the root module fail their
    tests, identically on v0.7.5-alpha and on this release. Three of the root
    ones need `-tags codec_json` and are red without it. The `xkey` module is
    not wired into CI at all, which is why nobody noticed. Nothing here
    regressed them and nothing here fixed them.

## [0.7.5-alpha] - 2026-08-19

### Security

- **Post-quantum seeds are wiped on every return, not only the happy path.**
  `generateMLDSAKey` and `generateMLKEMKey` wiped their source seed only after
  `sealSeed` succeeded, so a protected-memory or `mlock` failure returned with
  32/64 bytes of live seed still on the stack or heap — precisely the path
  where fail-closed cleanup matters. Both now `defer secure.Wipe(...)` as soon
  as the seed exists. (Codex review of PR #16, blocking finding 1.)
- **The FIPS allowlist now names its validated boundary exactly.** The comment
  claimed only ML-DSA and Ed448 come from CIRCL; ML-KEM-512 does too, because
  `crypto/mlkem` ships only 768 and 1024 and `pkg/quantum/mlkem512` wraps CIRCL
  for the 512 parameter set. The permitted set is unchanged — whether FIPS mode
  should reject CIRCL-backed algorithms outright is an owner ruling (#21).
  (Codex review of PR #16, blocking finding 2: valid, escalated not silently
  resolved.)
- **PIN lockout could stop counting under contention, and an attacker
  controlled the contention.** This is a security fix, not a test fix.

  The PKCS#11 failed-attempt counter is server-authoritative precisely so that
  several remote-mode clients sharing one token count their failures against
  one durable budget. `IncrementFailedAttempt`'s compare-and-swap loop gave up
  after 16 lost races and returned an error; the caller
  (`SetAttemptPersistence` in `module.go`) reports `persisted=false` on error,
  so **that failed PIN attempt never advanced the durable budget** and fell
  back to a per-process in-memory counter. Concurrent PIN attempts from several
  clients are exactly what produces the contention, so the condition that
  disables the lockout is the condition an online guessing attack creates.
  A caller that keeps losing can therefore keep guessing.

  Two defects made the loop lose races it should have won. It discarded the
  current value that a failed `CompareAndSwap` returns — the
  `CompareAndSwapper` contract supplies it so a caller can recompute and retry —
  and re-read through a separate, unsynchronized `Get`, reopening the window
  between observing the counter and swapping it. And the 16-attempt budget was
  mismeasured: a losing writer's retry count is not a function of how many
  clients contend, because the loser is descheduled while the winner keeps
  incrementing, so one competitor can beat it an unbounded number of times in a
  row. Reproduced with only TWO writers under `-race` at `GOMAXPROCS=2`.

  Retries now recompute against the value the failed swap itself observed, the
  budget is 1024 with a yield on each loss, and a single `opContext` deadline
  bounds the whole loop instead of a fresh 10s timeout per attempt. Verified at
  5000 iterations with zero failures where 3000 iterations previously failed
  repeatedly.

### Fixed

- **`gofmt` compliance in `xkey/cmd/xkey/cmd/trust_fetch_test.go`.** `gofmt`
  does not respect module boundaries, so the root Lint job format-checks
  `xkey/` even though every other job treats it as the separate module it is.
  One unformatted file there failed CI's Lint job at its first step while
  passing every root-module-only local check.
- **Reciprocal cross-module pins refreshed to the released version.** `xkey`
  and `sdk/go` recorded `go-xkms` and each other at `v0.7.1-alpha` while the
  repo had released `v0.7.4-alpha`. The local-path `replace` directives resolve
  every in-repo build — and CI's own builds — through the working tree, so the
  stale requirement was invisible to `go list`, to zip inspection and to every
  local check, while a consumer resolving `sdk/go` or `xkey` at the new tag
  would have been handed `go-xkms v0.7.1-alpha`. This is the defect
  go-qrdb `v0.2.0-alpha` shipped; release-versioning.md §2 names go-xkms as
  carrying the same exposure.
- **Race Detector no longer dies on a busy runner**: the job passes
  `-timeout 30m` instead of relying on `go test`'s 10-minute per-package
  default. `pkg/pkcs11/module` is the only package the `pkcs11` build tag
  exercises, and its ~1400 tests each pay a production-cost Argon2id PIN
  derivation, so under contention the package alone exceeds ten minutes.
  The same commit passed on a quiet runner and failed on a loaded one,
  alternating across consecutive runs — starvation, not a hang.
- **Docker Build & Scan no longer fails on the BuildKit cache**: `type=gha`
  is now requested only on github.com. On Gitea the Actions cache server is
  advertised on an address buildx cannot route to (buildkit runs in its own
  container on the default bridge), and the build died on
  `connect: connection refused` before any layer was built.

### Changed

- **`GOPROXY` / `GOSUMDB` removed from the CI environment** (ci-template v1.1
  prohibition). The runners inject `GOPRIVATE`, which already exempts
  first-party modules from the proxy and the checksum database; the blanket
  `GOSUMDB: off` had disabled checksum verification for every third-party
  dependency as well.
- **`make trivy-image` matches the CI image gate** by passing
  `--ignore-unfixed` (devops.md §8), so the local target reproduces the gate
  it claims to mirror instead of failing on unfixable base-image advisories.
- **Integration Tests is advisory, not required** (ruled 2026-08-18, the same
  demotion go-quicbaas already carries). The job still runs on every commit and
  its result is still printed by the CI Gate; it simply no longer blocks. It has
  passed once in 40 executions and never on `main`, because `run_with_server`
  uses `[ -f /.dockerenv ]` to mean "am I the devcontainer" and that is true
  inside the Actions job container (#19). A required check that has never passed
  detects no regression and blocks every merge. It returns to required when
  #19's harness rebuild lands.
- **`go-luks2` bumped to v0.1.7-alpha.** `go-truststrap` is deliberately HELD at
  v0.1.3-alpha: v0.1.4-alpha reshapes `pkg/noiseproto` (`StaticKey` replaces
  `*noise.DHKey`, `EncodeStaticKey` takes a destination buffer), and
  `go-qrdb v0.5.9-alpha` consumes that package and has not caught up, so the
  bump breaks the build in a dependency this repo does not own.
- **A zero-byte `pkg/server/audit-events.ndjson` is no longer tracked.** It is a
  runtime artifact — `pkg/server/server.go` writes the audit sink to a relative
  path when no storage path is configured — and `.gitignore` already listed it.
- **CI no longer runs every commit twice**: `.github/workflows/ci.yml` scopes
  its `push` and `pull_request` triggers to `main` (ci-template v1.5), the sole
  trunk since `develop` was folded into it. A branch that was both
  push-triggered and a PR head produced two full runs of the same commit — one
  `push`, one `pull_request` — and this Gitea has no working supersession, so
  the duplicate ran to completion. `master` and `develop` no longer exist as
  branches, so nothing loses coverage. A `concurrency:` block is deliberately
  **not** used: on Gitea 1.27.1 a job carrying a concurrency group is cancelled
  even when the group is unoccupied.
- **Cross-repo dependencies bumped to their latest tags** (root, `sdk/go`,
  `xkey`): go-frost v0.1.7→v0.1.8-alpha, go-objstore v0.2.1→v0.2.2-alpha,
  go-qrdb v0.5.7→v0.5.9-alpha (and `go-qrdb/sdk/go` v0.5.7→v0.5.9-alpha),
  go-quicraft v0.4.2→v0.6.2-alpha, go-truststrap v0.1.2→v0.1.3-alpha.
  go-codec (v1.4.0) and go-luks2 (v0.1.6-alpha) were already current.
- **go-truststrap typed errors renamed at the source**: `ErrPinNotFound` →
  `PinNotFoundError` and `ErrNilPin` → `NilPinError`. Call sites in
  `pkg/trust/bootstrap` follow; the field shapes are unchanged. This repo's
  own `resolver.ErrPinNotFound` is a different type and keeps its name.
- **SPKI pin bootstrap verifies through `VerifyConnection`**, not
  `VerifyPeerCertificate`. go-truststrap made the switch because
  `VerifyPeerCertificate` is skipped on a resumed session, which would let a
  resumed connection bypass the pin; it also disables session tickets.
  `NewSPKIPinTLSConfig` is a passthrough, so this repo inherits the fix.

### Removed — BREAKING (Go SDK)

- **`sdk.QRDBCachedDiskBackend` and `sdk.QRDBNewCachedDiskBackend`** are gone.
  They were pass-through aliases for `qrdb.CachedDiskBackend` /
  `qrdb.NewCachedDiskBackend`, which go-qrdb removed in v0.5.9-alpha with no
  replacement. Nothing in this repo consumed either alias. Callers needing a
  read-through cache in front of a disk backend must supply their own.

## [0.6.0-alpha] - 2026-08-17

### Changed — BREAKING: login plane unified (mTLS + FIDO2 + PIV)

- **`auth.type: "adaptive"` is removed** and fails startup with a typed
  error naming the replacement. First boot provisions the administrator
  and their mTLS credential at startup, so there is no pre-credential
  window to bridge. All shipped configs use `type: "composite"`.
- **Composite derives the session-vehicle chain** when no methods are
  configured: jwt (the pairs the FIDO2/PIV login ceremonies mint; present
  when a verification key or the built-in issuer exists) + mtls (when TLS
  is enabled). Single-vehicle chains keep the concrete authenticator.
- **Authentication on the unified server is qrdb's, single-pass**: the
  module implements `qrdbsdk.ModuleAuthFallback` — qrdb's mTLS chain runs
  first, xkms's session-vehicle chain second, and qrdb's ONE authorizer
  (store-resolved roles) decides. `BindRoute` no longer applies inline
  authentication, ending the double-auth pass.
- **Embedded node auth is explicit**: `buildXKMSQRDBConfig` mirrors
  xkmsd's `auth.enabled` onto the node (qrdb ≥0.5.2 is fail-safe anyway),
  with SPIFFE pinning when configured. Requires go-qrdb v0.5.5-alpha.

### Added

- **SDK login plane** (`sdk/go/login.go`): `NewLoginClient` with
  `PIVLogin` (PIV slot certificate as the TLS client credential),
  `Refresh`, `Logout`, `Validate`. The WebAuthn (FIDO2) ceremony remains
  the six-transport Servicer surface; `WithXKMSFactorVerifiers` remains
  the canonical verifier export for embedders.
- **Chained-file audit fallback** (`pkg/audit.ChainedFileLogger`):
  deployments without a qrdb client audit to a local tamper-evident
  chained file with the identical record shape — never a silent NoOp.

## [0.5.0-alpha] - 2026-08-16

### Changed
- **Re-pinned go-qrdb to v0.5.1-alpha.** The embedded node now enforces
  authentication and authorization on every unified-server route (qrdb
  `pkg/auth/wiring`), and carries the sealed-store crash-durability fix
  (a killed node previously lost its root key and orphaned all encrypted
  data). Do not use qrdb v0.5.0-alpha (truncated SDK error surface).
- **Adaptive authentication now composes JWT and mTLS.** A JWT-only chain
  locked out the first-boot administrator the moment their own creation
  flipped adaptive mode to enforced: cert-based enrollment is the
  bootstrap plane, so the SPKI-bound admin certificate must authenticate.
- **The system tenant is no longer a storage scope.** The tenant-scoped
  backend resolvers treat the system tenant like the platform scope via
  qrdb's canonical `IsSystemTenant` predicate; previously a system-scoped
  caller's sign/encrypt could not see keys the unscoped create had stored.
- **Local IPC stays plaintext and xkmsd-owned.** The Unix socket is no
  longer mapped onto the embedded node (qrdb transports are TLS-only, and
  the local plaintext clients — the PKCS#11 module, the CLI, the SDK unix
  transport — depend on the filesystem-permission trust model). xkmsd
  serves its own socket in every storage mode.
- **Unified server TLS honors `tls.client_auth`** with a rotating
  client-CA pool: operator files seed it and the embedded CA's bundle
  replaces it after composition, so admin-mTLS clients verify without
  operator-managed files.
- **Server certificates cover the deployment's names.** Locally issued
  serving certificates (bootstrap and CA-issued) now carry the machine
  hostname, the configured listen host, and — because the CA-issued
  certificate replicates cluster-wide keyed by CN — every cluster peer's
  hostname.

### Added
- **Module role grants** (`pkg/apimodule/module_grants.go`): at module
  construction xkms derives its full permission set (REST route table ∪
  MCP method specs ∪ gRPC proto options), registers it into qrdb's global
  permission registry, and grants it to the Admin and Owner built-in
  roles. Without this every xkms operation would be denied on the
  authenticated unified server, including to the first-boot admin.
- **Boot-time leader retry** (`pkg/server/leader_retry.go`): first boot,
  TLS certificate issuance, and JWT signing-key provisioning retry
  not-leader failures while a cluster's initial election settles.

### Fixed
- **First-boot Path A now delivers the admin key.** `GenerateAdminCert`
  generates the administrator's key pair locally and has the CA sign a
  CSR — the credential never enters platform key custody, and the
  generate-and-distribute pair is actually distributable (previously the
  CA path never returned a private key and the credential was silently
  dropped).
- **Trust bootstrap defaults to the public first-contact route**
  (`/v1/ca/bootstrap`); the authenticated `/api/v1/ca/bundle` default
  only ever worked through the adaptive-auth anonymity window that
  mandatory first boot now closes.
- **CA root and CSR key generation tolerate lost creation races** in a
  cluster: on `ErrKeyAlreadyExists` the winner's key is fetched instead
  of failing boot.
- The 3-node cluster integration harness authenticates as the first-boot
  administrator over mTLS, probes the qrdb admin plane (`/peers`) for
  leadership, and passes 17/17 including leader failover and killed-node
  rejoin.

## [0.4.0-alpha] - 2026-08-14

### Changed — BREAKING: network serving is the unified API server; legacy transport stacks removed (Phase 4 complete)
- **The legacy "MCP" line-framed JSON-RPC-over-TCP plane is replaced by the real Model Context Protocol.** The server side is qrdb's Streamable HTTP MCP endpoint (`https://host:mcp_port/mcp`); every xkms JSON-RPC method is an MCP tool (`xkms_<method>` with dots as underscores, one optional `params_json` string argument carrying the params object verbatim). `pkg/api/mcp` retains only the dispatch core (`NewServer` + `InvokeMethod` + the tenant/authorization gates) backing the module's tools; the TCP/UDS listener, wire framing, and the `xkms.subscribe` notification plane are deleted. The MCP client transport (`pkg/api/transport/mcp`) now speaks real MCP (mcp-go Streamable HTTP with mTLS) — its ~120 typed methods and their payloads are unchanged.
- **Enabling any network protocol (`rest`, `grpc`, `quic`, `mcp`) now requires `storage.backend: qrdb` and `tls.enabled: true`** (enforced by config validation): the embedded qrdb node's multi-protocol server takes xkmsd's ports and serves the capability plane through the registered `ServiceModule`. The legacy per-transport network listeners are deleted (`pkg/api/quic` removed wholesale; the in-process gRPC/MCP/REST network listeners in `pkg/server` removed). Local IPC is exempt: the Unix socket still serves in-process for non-qrdb storage, and the desktop loopback engine still serves its injected listener. **QUIC is now HTTP/3 on the REST port** (advertised via `Alt-Svc`); the QUIC client transport dials the REST port. TLS material is operator `cert_file`/`key_file` when configured, otherwise a persisted node-local bootstrap certificate serves from first boot and is replaced in-place by the CA-issued certificate once the CA composes. The embedded web UI registers on the unified server (public prefix routes, lazy SPA binding). The QUIC client's stale legacy dialect was migrated to the shared `/api/v1` forms — including 12 previously broken routes (8 PIV paths missing the `/api` prefix, 4 TCG-CA paths on a removed route family).

### Added
- **Unified API server — full module surface (Phase 3 waves 2+3) + cutover switch (Phase 4)**: The xkms `ServiceModule` now carries all three unified-server surfaces. *HTTP*: the REST surface is table-driven — new `pkg/api/rest/routes.go` (`RouteSpec`/`Routes()`) is the single source for both the legacy chi router and `Module.RegisterHTTP`, which registers every route through qrdb's permission-recording registrar (public → `HandlePublic`, authenticated-session → `identity:gated`, permission routes → `resource:action`), late-binding handlers via `pkg/server.ModuleRESTServer()` (503 while composing, 501 for absent subsystems) with legacy group middleware reapplied per route (`rest.BindRoute`). *MCP*: every xkms JSON-RPC method (including the frost namespace) registers as a real mcp-go tool (`xkms_*`, `params_json` parity argument) dispatched through the new connectionless `mcp.Server.InvokeMethod`, which runs the same tenant + authorization gates as the wire path. *Cutover*: new `server.unified_api` config hands the embedded qrdb node's server xkmsd's REST/gRPC/Unix/MCP ports and stands the corresponding legacy listeners down (QUIC/Noise stay legacy pending a qrdb `RegisterQUIC` hook); the composition-time `XKMSService` publish is now mutex-synchronized. At go-qrdb `v0.3.0-alpha`, module MCP tools remain fail-closed under qrdb auth middleware until qrdb exports a module tool-permission registry hook.

### Changed — BREAKING: cluster/auth-factor proxy planes replaced by the qrdb SDK (unified API server Phase 2)
- **xkmsd no longer ships its own cluster/rebalance proxy surface.** The hand-authored cluster plane (`pkg/xkms/servicer_cluster.go` mutation surface, `pkg/api/rest/handlers_cluster.go`, `pkg/api/grpc/service_cluster.go`, the `Cluster*` proto RPCs, `pkg/auth/permissions_cluster.go`, and the per-transport cluster handler/tests) is deleted; xkmsd hosts go-qrdb's own control plane on the embedded node (`pkg/server/qrdb_control_plane.go`) and `xkmsctl cluster|rebalance|factors` drive the `qrdbsdk.Client` directly. The internal `ClusterLeaderEndpoint` + NotLeader redirect behavior is retained. Wire consumers of the removed `Cluster*` KeystoreService RPCs must move to the qrdb control-plane surface.

### Added
- **Unified API server seam — go-xkms as a qrdb `ServiceModule` (Phase 3 wave 1)**: New `pkg/apimodule.Module` registers the wholesale `KeystoreService` gRPC surface (lazy service binding; `Unavailable` until composition completes) into the embedded qrdb node's multi-protocol server under the module name `xkms`, wired via `qrdbsdk.WithModule` in `pkg/server/qrdb_node.go`. Per-RPC authorization rides `option (qrdb.v1.permission)` annotations on all 143 RPCs (locked by `authz_proto_option_test.go`; unannotated ⇒ default-deny). The stack convention is one module per provider project, named after the project; the module is re-exported through `sdk/go` (`NewServiceModule`, `ServiceModule`, `ServiceModuleName`) so downstream hosts (go-quicbaas, go-trusted-platform) register it without importing `go-xkms/pkg`. Registration is additive: the legacy transport stacks keep serving until the Phase 4 cutover.

### Changed
- **go.work machinery fully removed (dependency-resolution cutover completion)**: Deleted `scripts/gen-gowork.sh`, `.devcontainer/scripts/ensure-gowork.sh`, every sibling bind-mount/`additional_contexts` block, and every `GOWORK=/tmp/go.work` reference across the Makefile, devcontainer, root `Dockerfile`, and all integration Dockerfiles/compose files. Container builds now resolve first-party modules from Gitea tags: runtime lanes get the `GOPRIVATE` + `insteadOf` environment (token from the gitignored `.devcontainer/.env`), image-build-time fetches use an optional `gomodauth` BuildKit secret (staged by `make stage-gomodauth`; never a layer, never build context). First-party pins bumped and exercised workspace-free: go-qrdb `v0.3.0-alpha` (root + `sdk/go`), go-codec `v1.4.0`, go-quicraft `v0.3.1-alpha` — in the root, `sdk/go`, and `xkey` modules.

### Changed
- **Typed-error migration (~6,050 sites)**: Replaced ad-hoc `fmt.Errorf` construction across the entire repository with the house typed-error pattern -- the new `pkg/errs` package (`Message`, `Wrapped`, `Detail`, `Affix`, `Joined`, all `errors.Is`/`errors.As`-transparent via `Unwrap`) plus per-package sentinel and typed errors. Breakdown: xkey 1,573 sites, cmd/ + sdk 785, pkg/ 3,689, with the remainder in tests, integration suites, and examples. Rendered messages are preserved byte-for-byte; wrapped causes keep participating in `errors.Is`/`errors.As` chains.
- **Health/validation adoption onto the qrdb SDK**: xkms now consumes the go-qrdb SDK health-check and configuration-validation surfaces instead of carrying local copies; roughly 2,950 LOC of dead parallel implementation was deleted.
- **SSH SDK TLS dedup**: The SSH client transports now share a single TLS configuration builder in `sdk/go/transport/tls.go`, removing the per-transport duplicated TLS setup.
- **Raft mTLS onto the qrdb SDK boundary**: Inter-node Raft mTLS provisioning now flows through the go-qrdb SDK `WithRaftMTLS` option instead of a local wiring path, keeping the locked SDK boundary intact.
- **Stale go-trusted-ca header sweep**: Rewrote the stale `go-trusted-ca` license/attribution headers left from the CA merge across 652 files to the canonical go-xkms header.
- **Floci replaces LocalStack for AWS KMS emulation**: The `awskms` integration suite and the shared `docker-compose.emulators.yml` now use `floci/floci` (MIT-licensed, ~24ms startup, successor to the sunset LocalStack Community Edition) instead of `localstack/localstack`. Floci is a drop-in on port 4566; the full asymmetric matrix (ECC P-256/P-384/P-521, RSA 2048/3072/4096, RSASSA-PSS, sign/verify/GetPublicKey) was validated against the emulator. `LOCALSTACK_ENDPOINT` is replaced by `FLOCI_ENDPOINT` (`AWS_ENDPOINT_URL` remains the primary override). The Azure Key Vault emulator and HashiCorp Vault services are unchanged — floci-az implements Key Vault secrets only (no `/keys` crypto operations), so it cannot replace the Azure emulator.

### Added
- **Local system SSH integration (xkey as a GUI over your local SSH setup)**: New `pkg/ssh/local` (re-exported via `sdk/go/client/ssh`) parses `~/.ssh/config` + `/etc/ssh/ssh_config` read-only (Host/HostName/User/Port/IdentityFile/IdentityAgent, Include, `%h/%d/%r/%p` tokens), discovers default `~/.ssh` identities (`id_rsa` … `id_ed25519_sk`), and signs through the system SSH agent (`$SSH_AUTH_SOCK`) — the only signing path for FIDO2 `sk-` keys — falling back to parsing unencrypted identity files. xkey's SSH view gains a read-only **Local** key source (agent + file keys) and a **"From ~/.ssh/config"** connections section; connecting to a config host honors the selected console mode (embedded console with agent signing, or system-terminal **passthrough** that runs plain `ssh <alias>` with zero overrides so native ProxyJump/IdentityFile/known_hosts semantics apply). CLI parity: `xkey ssh local hosts|keys`, `xkey ssh connect --local [--ssh-config-alias]`, profile `--key-source`/`--ssh-config-alias`.
- **Embedded SSH console trust-on-first-use (TOFU)**: The WebSocket console protocol gained a host-key confirmation round trip (`{"type":"hostkey",...,"mode":"confirm"|"notify"}` / `{"type":"hostkey-response","accept":bool}`). Host-key policy (`yes`/`ask`/`accept-new`) and known-hosts policy (barrier store / `~/.ssh/known_hosts` / both) now apply to the embedded console exactly as to the system terminal: `ask` shows an in-console Accept/Reject fingerprint prompt (60s server timeout), `accept-new` auto-pins with an informational notice, and a **changed** host key always hard-fails regardless of policy. Implemented via `known_hosts.CallbackWithConfirm` + new `ConsoleTarget.HostKeyPolicy`/`KnownHostsExtraFiles`/`KnownHostsSkipStore` in the SDK; TypeScript SDK `SSHConsoleClient.onHostKey` is fail-closed (no handler ⇒ reject).
- **Searchable SSH key picker (any backend + local keys) in xkey's connect/profile dialogs**: The New Connection and Profile dialogs replace the managed-keys-only `<select>` with one type-to-search combobox (`SSHKeySelect.svelte`) listing **xKey keys** (unified SSH store, any backend, labeled with algorithm + backend) and **Local keys** (every system ssh-agent key plus `~/.ssh` identity files), filtered by name/comment/fingerprint/path/backend — built for machines with many keys. A local selection persists as `key_source: "local"` + a new `local_identity` field (`Profile.LocalIdentity`): an identity file path, or `agent:<SHA256-fingerprint>` for an agent-held key (e.g. FIDO2 `sk-`). System-terminal connects pass a file identity as `ssh -i`; embedded-console connects resolve the pinned signer via the agent/identity file. The shared resolver is `sdk/go/client/ssh.ResolveLocalSigners` (`LocalKeySelector{Identity|Alias|Host}`), consumed identically by the GUI console service and the CLI; multi-signer public-key auth (`session`/`console`/`ConsoleTarget.Signers`, `OpenConsoleWithSigners`) offers every candidate in order, OpenSSH-style. CLI parity: `xkey ssh connect|console --identity <path|agent:fp>` (implies `--local`), `xkey ssh console --local`, profile `--identity`.

- **Opt-in persistent console sessions**: Embedded-console sessions are memory-only by default; a session specifically started with **Persistent session** enabled (New Connection checkbox, the *Persistent console session* profile option, or `xkey ssh profile add --persist-session`) is recorded in the shared barrier-routed SSH store (`pkg/ssh/sessions`, re-exported as `sdk/go/client/ssh.ConsoleSessionStore`) — title + reconnect origin only, never key material or live connection state. Persisted tabs are restored disconnected (Reconnect one click away, never auto-dialing at startup) whenever the SSH view loads: after navigation, a webview reload, or a full app restart; closing a persisted tab deletes its record. CLI parity: `xkey ssh sessions list|rm`. Coverage: store CRUD unit tests, console-service session tests, CLI integration tests proving GUI↔CLI store compatibility, Vite Playwright specs for the opt-in surfaces (default OFF), and live Playwright E2E proving a persisted session survives a reload and reconnects while a default session leaves no record.
- **Tabbed multi-session embedded SSH console**: The embedded console panel now manages multiple simultaneous sessions as tabs, like a system terminal. Every embedded connection (one-time, profile, or ssh_config host) opens its own tab with a `user@host` title, live/ended status dot, and per-tab close; a `+` in the tab strip opens the New Connection dialog. Inactive tabs stay mounted so their WebSocket/SSH sessions keep running with scrollback intact; an ended session's tab offers an in-place **Reconnect** (a fresh one-time ticket minted from the tab's remembered origin — reconnects to a pinned host are prompt-free). Backend hygiene: the console service purges abandoned (issued-but-never-connected) tickets after 2 minutes. Coverage: service-level concurrent-session WS test (`TestSSHConsoleE2E_ConcurrentSessions`) + ticket-TTL test, a concurrent two-process CLI integration test (`TestSSHConsoleConcurrentSessions`), Vite Playwright specs for the tab mechanics, and live Playwright E2E driving two real SSH sessions across tab switches plus the reconnect flow.

### Fixed
- **`ssh/console` Close returned io.EOF on peer-first teardown**: `Console.Close` closes stdin before closing the SSH session; when the remote command exits on that EOF first, `x/crypto/ssh` reports the already-closed channel as `io.EOF`. Close now treats that as a clean close (the session is terminated either way) instead of surfacing a spurious error.
- **Embedded SSH console dead on first contact (strict host-key default + unapplied Settings)**: `SSHConsoleService`'s built-in host-key policy was strict (`"yes"`) while the Settings page *displayed* "ask" without ever applying or persisting it — the value only reached the backend when the dropdown was touched, and reset on every restart. On a fresh install (empty pin store) every first-contact embedded connection therefore hard-failed before the TOFU prompt could appear, while the system terminal worked (its service already defaulted to "ask"). The console service default is now `"ask"` (invalid values also reset to it), and the host-key checking + known-hosts policies are persisted (`localStorage`) and re-applied to both SSH services at app startup, so the backend always enforces what Settings shows. Coverage that proves the console *works* end-to-end: service-level WS tests (`TestSSHConsoleE2E_*` — first-contact prompt/accept/reject, strict-policy regression, no-key agent flow), CLI integration tests (`TestSSHConsoleLocalIdentityFile`, `TestSSHConsoleNoKeyAgentFallback`, updated no-key semantics), and a live Playwright E2E (`SSH Embedded Console — live E2E`) that drives the real GUI against a real SSH server (`xkey/test/e2esupport/sshechod`): key picker → TOFU accept → live terminal echo → pinned reconnect, plus a reject path.
- **SSH connections without a key failed instead of using agent/password auth**: With an empty key store (or "No key" selected) the system-terminal connect tried to resolve a nameless xkey-managed key and failed before any terminal opened, and the embedded console opened a dead panel whose signer failure surfaced only as an opaque WebSocket 403. A key-less connection now behaves like typing `ssh user@host`: the system terminal runs a plain passthrough `ssh` (system agent or interactive password prompt), and the embedded console offers every local agent/identity signer, OpenSSH-style. Embedded-console signer resolution moved from the WebSocket upgrade to `OpenConsole` time, so a bad key reference (missing managed key, unknown agent fingerprint, passphrase-protected identity) surfaces as a real error notification in the dialog instead of a dead console panel; `openConsole`/`connectOneTime` failures now report the underlying reason. Same fallback in the CLI: `xkey ssh connect|console` without `--key` uses local identities instead of erroring.
- **xkey SSH store: wrong location, no encryption, GUI/CLI split**: The GUI opened its SSH store at a CWD-relative `"ssh"` path (ignoring the data directory) and never routed it through the barrier; the CLI used a separate hardcoded `~/.xkey-store/ssh`. Both now share one store via `xkey/pkg/sshstore` — barrier-routed (encrypted at rest, with one-shot migration of legacy plaintext stores to `*.pre-barrier.bak`) when the barrier is active, otherwise an engine store at `<data-dir>/ssh`. SSH wiring moved from `NewApp` into `initializeDataDir` so it no longer races the barrier unseal. First-contact embedded console connections no longer hard-fail with `pin not found` (see TOFU above).
- **Duplicate xterm.js in the xkey bundle**: `sdk/ts` (imported as source) pinned xterm v5 while the frontend shipped v6, so two Terminal implementations could bundle; unified on `@xterm/xterm@^6` + `@xterm/addon-fit@^0.11` with Vite `resolve.alias`/`dedupe` guaranteeing a single copy.
- **Unix gRPC socket server Stop/Start shutdown race**: If `Shutdown` ran while `startUnix` was still inside `unix.GRPCServer.Start` (before the gRPC server was assigned), `Stop` found a nil server, did nothing, and the subsequent `Serve` blocked forever — hanging daemon shutdown until the 30s force-stop and leaking the serving goroutine. `Stop` now records a stopped flag that `Start` checks under the same lock before serving, releasing the listener and socket as a clean shutdown. Regression test: `TestGRPCServer_StopBeforeStart`.

- **Real GCP Cloud KMS emulator lane (floci-gcp)**: The `gcpkms` integration suite now runs `TestGCPKMSEmulator` against `floci/floci-gcp` over genuine gRPC — real, locally verified RSASSA-PKCS1 and ECDSA P-256 signatures, symmetric AES-256-GCM round-trips, and key lifecycle — replacing mock-only coverage for those algorithms. Algorithms floci-gcp does not implement (EC P-384, RSA-PSS) remain covered by the mock and opt-in real-cloud suites. The GCP KMS backend gains an `Insecure` config option (requires a custom `Endpoint`; plaintext unauthenticated gRPC for local emulators only), also exposed as the `insecure` backend-registration key.
- **Pluggable cluster CA key custody (`ca_key_strategy`) — any node can issue**: A new `ClusterCAKeyStrategy` seam (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) decides where the cluster CA signing key lives and which nodes issue node certificates, so every product (xkmsd, quicbaasd) behaves identically from a one-line config choice. `barrier` (default) bootstraps the key node-local, then promotes it into the qrdb-routed replicated barrier-encrypted datastore — every node loads it (each decrypting with its own barrier), so **any node can issue**, not just the first. `hsm` keeps the key inside a shared PKCS#11 HSM that every node signs through by reference (key material never leaves the HSM; FIPS-grade). `tpm-kek` wraps the replicated CA key under a KEK derived from a cluster seed that the bootstrap node seals to its local TPM and delivers to each joining node via **TPM credential activation** (`MakeCredentialWithExternalEK`/`ActivateCredential`) during attested enrollment — hardware-rooted without a shared HSM. Seed delivery is intentionally decoupled from enroll-01 via a neutral `NodeSecretProvider` seam, an optional `EnrollmentSecretStrategy` interface (type-asserted, so `barrier`/`hsm` are unaffected), and a reusable post-enrollment `SecretDeliveryService` fetch — all re-exported through `sdk/go/clusterca`. All three strategies are wired live in both xkmsd and quicbaasd: the shared TPM (from the seal strategy) supplies the credential activator, the delivery endpoint is mounted on each node's server, and a joining node fetches + activates its wrapped seed after enrollment. A `tpm_simulator` integration test validates the real credential-activation round-trip. `tpm-kek` requires every node to have a TPM and fails closed otherwise. See `docs/cluster/README.md`.
- **Touch-free ACME-attested Raft cluster enrollment**: A new `cluster.raft_enrollment.acme` mode provisions inter-node Raft mTLS with the runtime TrustedCA as the single cluster trust anchor. The first node pre-stages the CA hierarchy, issues its own transport leaf, and caches the full CA certificate set (adopted on later boots so `Load` finds every intermediate without forking a second root); joining nodes prove TPM residency via enroll-01 to an existing node's ACME directory (no shared CA private key distributed). Node certificates carry their SPIFFE identity (`spiffe://<trust-domain>/node/<raft-address>`) as a URI SAN, and transport issuance routes through a dedicated cluster intermediate (`cluster_ca_cn`) — root signs intermediates only (FedRAMP/PCI posture). The shared provisioning toolkit (`pkg/trust/clusterca`, re-exported via `sdk/go/clusterca`) — including `NewNodeLocalBackends` for pre-node cluster CA key protection — is consumed identically by every product in the stack. enroll-01 (attestation-gated self-enrollment) and endorse-01 (EAB-admin-gated admission) remain distinct admission models. See `docs/cluster/README.md`.
- **Cluster CA key protection at rest**: The node-local cluster CA signing keystore (which must exist before the replicated datastore, so it lives outside the barrier) is protected via the canonical seal strategies through `cluster.raft_enrollment.ca_key_protection` (`""` auto → TPM/HSM → passphrase → refuse; `tpm2`/`pkcs11`; `passphrase`; or `none`). Auto mode never silently falls back to plaintext, and `config.ComplianceGaps` refuses a plaintext (`none`) cluster CA key unless the daemon is started with `--insecure`.
- **Node-barrier data-plane encryption (encrypted-at-rest key stores)**: On an embedded qrdb deployment (`storage.backend: qrdb`) with the barrier enabled and an auto-unseal credential (a boot passphrase or a TPM/HSM seal strategy), xkms now uses the qrdb node's own barrier, which `encfs`-encrypts the entire PebbleDB data plane — so the crypto backends' key stores (TLS, ACME, and general keys) are encrypted at rest, closing a plaintext-on-disk gap. This mirrors go-quicbaas so both products drive the identical shared seal mechanism (`pkg/server/node_seal.go`, `qrdb_node.go`). Falls back to xkms's own barrier for non-qrdb storage or when no auto-unseal credential is present.
- **Unified seal provisioning (config / CLI / env)**: `barrier.strategy`/`barrier.passphrase` config, `XKMS_SEAL_STRATEGY`/`XKMS_SEAL_PASSPHRASE` env vars, and the `xkmsd --seal-passphrase` flag (precedence CLI > env > config) provide the boot-time auto-unseal secret. TPM/hardware strategies auto-unseal from the device with no boot secret; the TPM open is shared with the general TPM2 backend (single device open).
- **Canonical hardware-seal autodetect (SDK)**: `sdk/go.BuildBestSealStrategy` / `ProbeSealStrategies` (`pkg/seal/autodetect.go`) are the single stack-wide implementation of the non-provisioning, single-open TPM probe; go-quicbaas's `seal_autodetect.go` now delegates to it (removing a duplicate).
- **Secure-by-default gap for un-unsealable barriers**: `config.ComplianceGaps` now flags a `qrdb` + barrier deployment that cannot auto-unseal (a passphrase strategy with no boot secret), so the daemon refuses to start it (leaving backend keys plaintext) unless `--insecure` is set. The canonical seal vocabulary (`awskms`/`gcpkms`/`azurekv`/`passphrase`) is now accepted across xkms credential-seal validation and go-trusted-platform's barrier config, with backward-compatible aliases.
- **Embedded SDK tenant-scope enable-encryption**: The qrdb SDK now exposes `node.WithTenantIsolation()` and `node.EnableEncryption(ctx, scope, opts)` for standalone and clustered nodes; embedded nodes now have full daemon parity for per-tenant encryption migration via the shared `pkg/server.BuildTenantInfra` composer.
- **Credential-free enable-encryption sources**: Tenants starting with `StrategySystemBarrier` (system-managed auto-unseal) or `StrategyNone` can now transparently migrate to keyed strategies (passphrase / shamir / hardware) without supplying unlock credentials; truly-shared-barrier tenants are rejected via `ErrSharedBarrierImmutable`.
- **qrdb SDK re-exports for entitlement errors**: `go-qrdb/sdk/go` now re-exports `ErrSharedBarrierImmutable`, `EntitlementError`, migration error sentinels, and the `EncryptionMigrator` interface for downstream integration.
- **Standalone DKEK Package**: New `pkg/dkek/` package provides backend-agnostic Device Key Encryption Key support using Shamir's Secret Sharing. Works with any storage backend, no longer tied to PKCS#11.
- **SymmetricKeyProvider parity**: All symmetric-capable backends (AWS KMS, GCP KMS, Azure KV, Vault, PKCS#11, TPM2, Software, Symmetric) now implement `SymmetricKeyProviderWithTracking` with `GetTracker()` for AEAD safety tracking.
- **TPM2 Backend SymmetricKeyProvider**: The TPM2 backend (`pkg/backend/tpm2/`) now implements `SymmetricKeyProvider` interface, exposing `GenerateSymmetricKey()`, `GetSymmetricKey()`, and `SymmetricEncrypter()` through the Backend layer.
- **XKMSServicer unit tests**: Comprehensive test suite for `pkg/xkms/` servicer (368+ tests, 80.5% coverage) covering keys, crypto, certificates, sealing, barrier, PIN, user, platform store, shares, custodian, policy, and password operations.
- **GUI CustodianService**: New `xkey/pkg/gui/services/custodian_service.go` wrapping the SDK CustodianGroupService for Wails frontend with event emission, input validation, and 30 unit tests.
- **GUI TenantService**: New `xkey/pkg/gui/services/tenant_service.go` wrapping the SDK TenantService for Wails frontend with event emission, barrier init/unseal support, and 29 unit tests.
- **Custodian/Tenant events**: New event types for custodian group lifecycle (created, deleted, member added/removed, shares distributed) and tenant lifecycle (created, deleted, barrier initialized/unsealed).

### Removed
- **YubiKey Backend**: Removed `pkg/backend/yubikey/` -- YubiKey PIV devices are now supported through the generic PKCS#11 backend with `libykcs11`. This eliminates redundant code and provides stronger cryptographic operations via native PKCS#11 AES-GCM instead of envelope encryption.
- **SmartCard-HSM Backend**: Removed `pkg/backend/smartcardhsm/` -- SmartCard-HSM devices are supported through the generic PKCS#11 backend. The DKEK (Device Key Encryption Key) functionality has been moved to the standalone `pkg/dkek/` package.
- **Secret Sharing Duplication**: Removed `pkg/crypto/secretsharing/` -- consolidated on `pkg/threshold/shamir/` as the single Shamir's Secret Sharing implementation.

### Migration Guide
- **YubiKey users**: Replace `backend: yubikey` configuration with `backend: pkcs11` and set `library: /usr/lib/libykcs11.so` (or appropriate path for your OS). All PIV slot operations work identically through the PKCS#11 interface.
- **SmartCard-HSM users**: Replace `backend: smartcardhsm` with `backend: pkcs11`. For DKEK functionality, use the `pkg/dkek` package directly or the `xkmsctl dkek` CLI commands which now work with any backend.

## [0.2.3-alpha] - 2026-01-15

### Added
- Go SDK (`sdk/go/`) with multi-protocol client support (REST, gRPC, QUIC, MCP, Unix)
- Virtual FIDO2 key binary (`cmd/xkey`) with Linux UHID support
- Linux UHID interface package (`pkg/uhid`) for virtual USB HID device emulation
- Native FIDO2 authenticator (`pkg/fido2/authenticator/`) with CTAP2 protocol support
- Virtual FIDO2 device factory and native enumerator in `pkg/fido2/`
- Integration tests for SDK, UHID, and xkey packages
- WebAuthn mock authenticator for integration testing
- CLI documentation (`docs/usage/cli/`) for all commands
- FIDO2 documentation (`docs/fido2/`)

### Changed
- Renamed `cmd/cli` to `cmd/xkmsctl` (CLI binary)
- Renamed `cmd/server` to `cmd/xkmsd` (daemon binary)
- Moved `pkg/cli/` to `cmd/xkmsctl/` (CLI is now a standalone command)
- Moved `pkg/client/` to `sdk/go/` (clients are now part of SDK)
- Moved gRPC proto files to `pkg/api/grpc/proto/`
- Updated all Dockerfiles to use `golang:bookworm` with `GOTOOLCHAIN=auto`
- Updated Go version to 1.25.6
- Improved devcontainer with UHID permissions for virtual FIDO2 testing
- Enhanced QUIC, MCP, and gRPC handlers with sealing operations
- Refactored TPM2 package to remove simulator build constraints

### Fixed
- Race conditions in gRPC server port field using atomic operations
- Race conditions in server instance field access with proper mutex locking
- FROST handler parameter validation across all API protocols
- UHID integration test permissions in devcontainer

## [0.2.2-alpha] - 2025-12-24

### Added
- **Unified Symmetric Backend**: New `pkg/backend/symmetric/` consolidating AES and ChaCha20-Poly1305
  - Single backend supporting AES-128-GCM, AES-192-GCM, AES-256-GCM
  - ChaCha20-Poly1305 and XChaCha20-Poly1305 support
  - Password-protected key storage with Argon2 key derivation
  - AEAD nonce tracking and bytes limit enforcement
  - Import/export functionality for key portability
- **Algorithm Type System**: New `pkg/types/algorithms.go` with comprehensive type definitions
  - `KeyAlgorithmString` for asymmetric key algorithm identifiers (RSA, ECDSA, Ed25519)
  - `EllipticCurve` constants (P224, P256, P384, P521, Curve25519)
  - `HashName` constants matching Go crypto standards
  - `SignatureAlgorithmName` for signature algorithm identifiers
  - `AEADAlgorithm` and `KeyWrapAlgorithm` for encryption operations
  - `CLIKeyType` for CLI key type parsing
  - Parsing and validation functions for all algorithm types
- **FROST Protocol Stubs**: Infrastructure for future FROST threshold signature support
  - Handler stubs for REST, gRPC, QUIC, Unix, and MCP protocols
  - Backend factory stubs for FROST initialization
  - CLI command stubs for FROST operations

### Changed
- **Test Coverage Improvements**: Increased coverage across 7 packages to 90%+ target
  - `pkg/types`: 66.6% → 97.0% (+30.4%)
  - `pkg/xkms`: 86.8% → 90.6% (+3.8%)
  - `pkg/backend/symmetric`: 88.4% → 90.0% (+1.6%)
  - `pkg/client`: 86.3% → 90.1% (+3.8%)
  - `pkg/crypto/ecies`: 89.6% (all reachable code covered)
  - `pkg/backup`: 89.7% → 91.0% (+1.3%)
  - `pkg/webauthn/http`: 87.9% (improved edge case coverage)
- **Consolidated AESAttributes**: Removed deprecated `AESAttributes` type, using `KeyAttributes` with `SymmetricAlgorithm` field
- **TPM2 Symmetric Tests**: Updated tests for symmetric key generation and encryption validation
- **Cloud Backend Tests**: Cleaned up symmetric encryption tests for AWS KMS, Azure Key Vault, GCP KMS, and Vault backends

### Removed
- **pkg/backend/aes/**: Deprecated AES-only backend (functionality moved to `pkg/backend/symmetric/`)
  - `aes.go`, `aes_test.go`, `aes_bench_test.go`
  - `aes_importexport_test.go`, `aes_tracking_test.go`
  - `errors.go`
- **test/integration/backend/aes_integration_test.go**: Replaced by symmetric backend integration tests

### Fixed
- **Code Formatting**: Fixed gofmt issues in test files blocking CI
- **Linting Errors**: Resolved staticcheck and ineffassign warnings
- **Build Errors**: Fixed undefined `AESAttributes` references after consolidation

## [0.2.1-alpha] - 2025-12-21

### Added
- **TPM2 ProdCaData**: New `ProdCaData` structure for carrying TPM attestation data (Quote, Signature, Nonce, PCRs) from client to server during IDevID enrollment
  - Enables server-side storage of client attestation state upon successful enrollment
  - Binary serialization with `PackProdCaData`/`UnpackProdCaData` functions
  - Conversion to/from `Quote` structure for TPM operations

### Changed
- **Unified Key ID Format**: Consolidated key ID parsing to 4-part format `backend:type:algo:keyname` with optional segments
  - Shorthand `my-key` now supported (equivalent to `:::my-key`)
  - All segments except keyname are optional
  - Refactored `ParseKeyID`, `ParseKeyIDToAttributes`, and validation to use unified format
- **XKMS Service API**: Refactored service functions to use unified key ID format
  - Added `BackendFor(attrs)` helper for backend resolution based on StoreType
  - Added `ParseCertificateID()` using unified format
  - Renamed `getKeystoreForKey` to `getKeystoreForKID` with proper 4-part parsing
  - `Signer()`, `Decrypter()`, `Key()` now use `BackendFor()` for backend resolution
- **TPM2 Provisioning**: Simplified golden measurement and platform policy handling
  - Removed deprecated file integrity monitoring code (use IMA via PCR 10 instead)
  - `Install()` now uses config's `EK.HierarchyAuth` for already-provisioned TPMs
  - Improved logging with INFO level for provisioning operations
  - `GoldenMeasurements()` returns empty if no PCRs configured (skip platform policy)
- **Client Config**: Changed default Unix socket path to `xkms-data/xkms.sock`, removed `APIKey` field (use JWT via FIDO2 flow)
- **Validation**: Updated `ValidateKeyReference()` to enforce 4-part key ID format

### Fixed
- **AWS KMS Lock Contention**: Fixed test timeout by implementing double-checked locking in `Backend.initClient()`
- **Azure Key Vault Lock Contention**: Applied same double-checked locking fix for consistency
- **CI Go Version**: Updated `Dockerfile.ci` from Go 1.24.4 to 1.25.5
- **TPM Test Config**: Added missing `GoldenPCRs` to `TestTPMOperations` config

## [0.2.0-alpha] - 2025-12-13

### Added
- **Key Versioning API**: Full key version lifecycle management across all client interfaces
  - `ListKeyVersions` - List all versions of a key with status and metadata
  - `EnableKeyVersion` / `DisableKeyVersion` - Enable or disable specific key versions
  - `EnableAllKeyVersions` / `DisableAllKeyVersions` - Bulk version state management
  - gRPC, REST, QUIC, and Unix socket client support
  - Proto definitions in `pkg/api/grpc/proto/xkmsv1/xkms.proto`
- **JWT Authentication Adapter**: `pkg/auth/jwt.go` for token-based authentication
  - Configurable issuer, audience, and signing key validation
  - Support for RS256, ES256, and EdDSA signing algorithms
- **Adaptive Authentication**: `pkg/auth/adaptive.go` for multi-method auth
  - Automatic fallback between authentication methods (mTLS → JWT → API Key)
  - Configurable authentication chain with priority ordering
- **WebAuthn JWT Generator**: `pkg/webauthn/jwt_generator.go` for token generation after FIDO2 authentication
- **CLI Certificate Commands**: `internal/cli/cert.go` for certificate management operations
- **TPM2 Backend Integration**: Server-side TPM2 backend factory and operations
  - `internal/server/backend_factory_tpm2.go` - TPM2 backend initialization
  - `internal/server/backend_tpm2.go` - TPM2 server operations
- **YubiKey Sealer Interface**: Hardware-backed data sealing for YubiKey PIV
  - `pkg/backend/yubikey/yubikey_sealer.go` - Envelope encryption sealing
  - RSA-OAEP key wrapping for DEK protection
  - AES-256-GCM authenticated encryption
- **YubiKey Symmetric Encryption**: AES-GCM envelope encryption using PIV keys
  - `pkg/backend/yubikey/yubikey_symmetric.go` - Full symmetric backend
  - DEK wrapping with RSA-OAEP, ECIES (P-256/P-384), and X25519
  - Ed25519 to X25519 key conversion for key agreement
- **Configurable Hardware-Backed RNG**: Support for TPM2 and PKCS#11 hardware random number generators
  - `pkg/crypto/rand/` Resolver interface now implements `io.Reader` for crypto/rand compatibility
  - New `RNGConfig` in server configuration for RNG source selection
  - Modes: `auto` (default), `software`, `tpm2`, `pkcs11`
  - Fallback mode support when primary RNG fails
  - Environment variable overrides: `XKMS_RNG_MODE`, `XKMS_RNG_FALLBACK`, `XKMS_RNG_TPM2_*`, `XKMS_RNG_PKCS11_*`
- **Unix Socket Client Package**: `pkg/client/` for Go applications to communicate with xkms server
- **CLI Configuration Tests**: `internal/cli/config_test.go` with comprehensive config validation
- **Extended CLI Integration Tests**: Multi-protocol and complete lifecycle tests
- **User Documentation**: `docs/usage/user.md` for end-user documentation
- **Daemon Configuration**: Complete daemon operation support for `xkmsd`
  - Configuration file support (`--config`, `XKMS_CONFIG`)
  - Signal handling: SIGTERM/SIGINT for graceful shutdown, SIGHUP for config reload
  - PID file management with automatic creation and cleanup
  - Runtime configuration reload without restart
  - Unix socket protocol selection (gRPC or HTTP)
  - systemd service file with security hardening
  - Installation script and comprehensive documentation in `configs/`
- **Comprehensive Test Suites**: New test files for sealer and symmetric operations
  - `pkg/backend/yubikey/yubikey_sealer_test.go` (14 test functions)
  - `pkg/backend/yubikey/yubikey_symmetric_test.go` (20 tests)
- **Deployment Documentation**: systemd and OpenRC service files for production deployments
  - `deploy/systemd/` - systemd service unit, sysusers, and tmpfiles configurations
  - `deploy/openrc/` - OpenRC init script and configuration for Alpine Linux
  - `deploy/README.md` - Comprehensive deployment guide with installation steps
- **Enhanced README**: Expanded quick start guide with FIDO2 admin setup
  - Server Quick Start section with first-time setup instructions
  - Complete CLI examples for key, certificate, and admin management
  - XKMS Service API overview with all service functions documented
  - Multi-backend configuration examples
- **Admin CLI Commands**: `internal/cli/admin.go` for administrator management
  - Create, list, delete admin users
  - Role assignment and permissions management
- **FIDO2 CLI Commands**: `internal/cli/fido2.go` for passwordless authentication setup
  - Register and manage FIDO2 credentials
  - Authenticate using hardware security keys
- **RBAC Middleware**: `internal/rest/rbac_middleware.go` for role-based access control
  - Permission-based route protection
  - Role hierarchy support
- **User Management API**: `internal/rest/user_handlers.go` for user operations
  - REST endpoints for user CRUD operations
  - Integration with RBAC system
- **Unix Socket HTTP Server**: `internal/unix/` for local IPC
  - HTTP server over Unix domain sockets
  - Handlers for all xkms operations

### Changed
- **Test Coverage Improvements**: Increased coverage across multiple packages
  - `pkg/versioning`: 76.1% → 93.9%
  - `pkg/client`: 79.1% → 86.1%
  - `internal/config`: 83.1% → 96.0%
  - Testable code (excluding hardware) now at 93.4% average coverage
- Extended environment variable configuration support for RNG, rate limiting, and logging
- **API Naming**: Renamed `XKMSFacade` to `XKMSService` for clarity
  - `FacadeConfig` → `ServiceConfig`
  - `facade.go` → `service.go`
  - Updated all documentation, tests, and code references
- **Documentation**: Updated terminology from "facade" to "service" throughout
- **Typed Errors**: Replaced all `fmt.Errorf` with typed errors in PIV backends
  - YubiKey: 37 typed error variables, ~139 replacements
  - Enables proper `errors.Is()` and `errors.As()` error handling
- Extended `Resolver` interface with `Read(p []byte) (n int, err error)` method for `io.Reader` compatibility
- Hardware RNG (TPM2/PKCS#11) can now be used as drop-in replacement for `crypto/rand.Reader`
- Updated example configurations with RNG settings documentation
- **Documentation Cleanup**: Streamlined architecture documentation
  - `docs/architecture/unified-keyid-jwk-integration.md` reduced from 1,580 to 245 lines
  - Removed all legacy/migration content, kept only current API documentation
- **CI/CD**: Added FIPS 140-2/3 compliant builds to CI and release workflows
  - BoringCrypto-enabled binaries for environments requiring FIPS certification

### Fixed
- **Makefile**: Fixed `bc` dependency error in coverage calculation (replaced with pure shell/awk)
- **Ed25519 to X25519 Conversion**: Fixed SHA256 → SHA512 for RFC 7748 compliance in YubiKey symmetric
- **TestMCPStreamingNotifications**: Fixed flaky integration test for async MCP notifications
- **PlatformPassword Race Condition**: Fixed concurrent cache access in `pkg/tpm2/password.go`
  - Multiple goroutines calling `Bytes()` could bypass cache and trigger excessive TPM unseal operations
  - Implemented double-checked locking pattern to ensure only one goroutine performs unseal when cache is empty
  - `TestPlatformPassword_CacheConcurrency` now passes with race detector enabled
- Improved error handling and logging for ignored HTTP write errors
- Integration test stability improvements across all backends
- **Configuration**: Server socket path now defaults to `/var/run/xkms/xkms.sock` to match client defaults
- **Configuration**: Added `xkmsd-dev.yaml` for development/testing with `/tmp` paths
- **Configuration**: Added `xkms-client.yaml` example client configuration
- **Scripts**: Moved test scripts from `scripts/` to `test/scripts/`

### Removed
- **API Key Authentication**: Removed `pkg/auth/apikey.go` (replaced by JWT adapter)
- **Logo**: Removed `logo.svg` from repository root
- `test/integration/encoding/README_FIX.md` - Development-only fix notes
- `pkg/metrics/implementation-summary.md` - Development-only implementation notes

### Known Limitations (Alpha)
- **TPM2 Server Integration**: The `pkg/tpm2` library is fully functional for direct Go usage, but server-side integration (REST/gRPC/CLI/MCP) is not yet complete. Use `pkg/tpm2` directly for TPM2 operations.
- **Vault Import/Export**: HashiCorp Vault Transit backend does not support key import/export operations
- **PKCS#11 Attestation**: Some attestation methods are not yet implemented

## [0.1.9-alpha] - 2025-12-07

### Added
- **WebAuthn/FIDO2 Server Support**: Complete server-side passwordless authentication
  - `pkg/webauthn/` - Core WebAuthn service with user, session, and credential management
  - `pkg/webauthn/http/` - HTTP handlers for REST API integration
  - Registration flow: begin/finish ceremonies with session management
  - Authentication flow: discoverable credentials and user-specific login
  - Pluggable store interfaces for UserStore, SessionStore, CredentialStore
  - Memory-based stores for development and testing
  - Full test coverage with testify mocks
- **WebAuthn REST API Endpoints**:
  - `GET /api/v1/webauthn/registration/status` - Check registration status
  - `POST /api/v1/webauthn/registration/begin` - Start registration ceremony
  - `POST /api/v1/webauthn/registration/finish` - Complete registration
  - `POST /api/v1/webauthn/login/begin` - Start authentication ceremony
  - `POST /api/v1/webauthn/login/finish` - Complete authentication
- **Shared Mock Infrastructure**: `pkg/xkms/mocks/mock_keystore.go` for unit testing
- **WebAuthn Integration Tests**: Docker-based tests in `test/integration/api/`
- **WebAuthn Documentation**: `docs/usage/webauthn.md`
- **Unified Rate Limiting**: Consistent rate limiting across all public APIs
  - Integrated rate limiting into REST server via middleware
  - Added gRPC unary and stream server interceptors for rate limiting
  - QUIC/HTTP3 server rate limiting via HTTP middleware
  - MCP JSON-RPC server connection-level rate limiting
  - New configuration options: `burst`, `cleanup_interval_sec`, `max_idle_sec`
  - Environment variable overrides: `KEYSTORE_RATELIMIT_ENABLED`, `KEYSTORE_RATELIMIT_REQUESTS_PER_MIN`, `KEYSTORE_RATELIMIT_BURST`

### Changed
- Refactored REST server tests to use shared mock infrastructure
- Improved test organization with centralized mocks
- Extended `RateLimitConfig` with additional options for burst and cleanup intervals

## [0.1.8-alpha] - 2025-12-06

### Changed
- **Storage Independence**: Removed go-objstore dependency, go-xkms now has its own storage implementations
  - Local `pkg/storage/memory.go` provides in-memory storage backend
  - Local `pkg/storage/file/` provides file-based storage backend
  - Storage interface remains compatible with go-objstore for higher-level app integration
- **Docker Cleanup**: Removed all GOPRIVATE workarounds from integration test Dockerfiles
  - Cleaned up main Dockerfile (removed sed/GOPRIVATE/GOPROXY hacks)
  - All integration tests now use standard Go module proxy

### Removed
- `pkg/storage/objstore_adapter.go` - go-objstore adapter (no longer needed)
- `pkg/tpm2/store/objstore_*.go` - All go-objstore adapters for TPM store
- `pkg/tpm2/store/factory.go` - go-objstore factory (replaced with local implementations)
- `pkg/tpm2/store/testing.go` - go-objstore test helpers
- GOPRIVATE environment variables from all Dockerfiles

### Dependencies
- Removed go-objstore dependency entirely (go-xkms is now self-contained for storage)

## [0.1.7-alpha] - 2025-12-05

### Added
- **Unified Sealer Interface**: Backend-agnostic sealing abstraction across all backends
  - `pkg/tpm2/sealer.go` - TPM2 sealer with PCR policy support
  - `pkg/backend/pkcs8/sealer.go` - Software sealer using HKDF + AES-256-GCM
  - `pkg/backend/pkcs11/sealer.go` - HSM hardware-backed AES-GCM sealing
  - `pkg/backend/awskms/sealer.go` - AWS KMS cloud-managed encryption
  - `pkg/backend/azurekv/sealer.go` - Azure Key Vault symmetric key sealing
  - `pkg/backend/gcpkms/sealer.go` - GCP KMS cloud-managed encryption
  - `pkg/backend/vault/sealer.go` - HashiCorp Vault Transit engine encryption
- **JWT SigningMethodSigner**: Hardware-backed JWT signing via `crypto.Signer` interface
  - Supports RS256/384/512, PS256/384/512, ES256/384/512, EdDSA
  - `SignWithSigner()` and `SignWithSignerAndKID()` convenience methods
- **Certificate Display Functions**: `pkg/certstore/types.go` with OID parsing, key usage display
- **Composite Sealing**: `pkg/xkms/composite_seal.go` for multi-backend seal operations
- **TPM2 Enhancements**: Certificate conversion, type re-exports, store abstraction
- **Logging Package**: Structured logging infrastructure (`pkg/logging/`)
- **Architecture Documentation**: Storage interfaces and BlobStorer refactoring guides

### Changed
- Extended `pkg/types/types.go` with Password, SealData, and Sealer interfaces
- Refactored internal TPM store with cleaner interfaces and helpers
- Improved overall test coverage from 85.8% to 91.2%

### Fixed
- Test coverage gaps across multiple packages:
  - `pkg/certstore`: 46.1% → 90.2%
  - `pkg/encoding/jwt`: 59.5% → 94.3%
  - `pkg/types`: 62.0% → 96.1%
  - `pkg/backend/threshold`: 72.5% → 81.7%
  - `pkg/storage/file`: 86.8% → 92.3%

## [0.1.6-alpha] - 2025-11-22

### Added
- Unified service pattern for simplified multi-backend management
- Backend factory pattern with auto-detection and configuration
- Comprehensive test coverage for service and factory (40+ test cases)
- Input validation for all API endpoints to prevent injection attacks
- Path traversal protection in file storage backend

### Changed
- Simplified API: `server.Initialize()` instead of `server.InitializeService()`
- Refactored xkms initialization with auto-backend detection
- Updated documentation and examples to reflect simplified API
- Improved code coverage from 72.8% to 92.5% in xkms package

### Security
- Centralized validation at service layer protects ALL public APIs (REST, gRPC, QUIC, CLI, MCP)
- All user inputs validated before reaching any backend or storage layer
- Created shared `pkg/validation` package for consistent validation across codebase
- Service layer validates all keyIDs, backend names, and key references
- Defense in depth: Storage layer also validates (though service should prevent bad input)
- Rejects special characters, null bytes, and directory traversal attempts
- Backend names: whitelist pattern `[a-z0-9\-]+` only (max 64 chars)
- KeyIDs: whitelist pattern `[a-zA-Z0-9_\-\.]+` only (max 255 chars)
- Key references support "backend:key-id" format with validation of both parts
- File storage protected against path traversal attacks
- Log injection prevention via sanitization of all logged user input

### Fixed
- Test coverage gaps in service and backend factory code
- Documentation examples now demonstrate clean, simple API usage
- Potential path traversal vulnerability in file storage operations

## [0.1.5-alpha] - 2025-11-19

### Changed
- Replaced minimal TPM2 implementation with full production-grade TPM support
- Complete TPM 2.0 integration with hierarchies, policies, and provisioning
- Enhanced TPM attestation and cryptographic operations
- Updated all security-critical dependencies to latest versions
  - golang.org/x/crypto: v0.42.0 → v0.45.0
  - google.golang.org/grpc: v1.76.0 → v1.77.0
  - AWS SDK v2, Prometheus, OpenTelemetry, TPM libraries
- Updated golangci-lint to v2.6.2 with action v7 for Go 1.25 compatibility
- Fixed TPM2 backend API compatibility with new config structure
- Removed redundant release tarballs (direct binary downloads only)

### Fixed
- Fixed TPM2 integration test build tags to properly include `tpm2` tag requirement
- Fixed TPM2 event log parsing to use absolute paths
- Resolved all 51 linting errors preventing CI builds (17 errcheck, 34 staticcheck)
  - Added proper error handling for unchecked error returns
  - Fixed JSON marshaling of function types (SessionCloser)
  - Resolved duplicate package imports and syntax errors
  - Suppressed false positive style warnings for embedded field accessors

## [0.1.4-alpha] - 2025-11-18

### Changed
- Internal refactoring and optimizations

## [0.1.3-alpha] - 2025-11-18

### Changed
- Refactored KeyAttributes to common library for better code reuse
- Improved type organization and reduced import cycles

## [0.1.2-alpha] - 2025-11-18

### Added
- Threshold cryptography package with Shamir Secret Sharing
- Split and combine secrets with configurable threshold

## [0.1.1-alpha] - 2025-11-17

### Added
- Quantum-safe signing support (post-quantum cryptography)
- Key encapsulation mechanisms (KEM) for quantum resistance

## [0.1.0-alpha] - 2025-01-15

### Overview

Initial alpha release of go-xkms - a production-ready cryptographic key and certificate management library for Go with 10 backends, 5 client interfaces, and dual licensing (AGPL-3.0 + Commercial).

### Added

#### Core Features
- Unified KeyStore interface for consistent key and certificate operations across all backends
- CompositeKeyStore pattern combining backend storage with certificate management
- Thread-safe concurrent operations with proper synchronization primitives
- Pluggable architecture for easy backend and storage extension

#### Key Management
- **Asymmetric Keys**: RSA (2048/3072/4096), ECDSA (P-256/P-384/P-521), Ed25519
- **Symmetric Keys**: AES-GCM (128/192/256-bit) with AEAD support
- **Operations**: Generate, store, retrieve, rotate, delete, import/export, wrap/unwrap
- **Standards**: Implements Go's `crypto.Signer` and `crypto.Decrypter` interfaces
- **Protection**: Password-protected PKCS#8 key storage with secure key derivation

#### Cryptographic Backends (10 Production-Ready)
1. **PKCS#8**: File-based asymmetric key storage
2. **AES**: File-based symmetric encryption backend
3. **Software**: Pure Go implementation for testing
4. **PKCS#11**: Hardware Security Module (HSM) integration
5. **SmartCard-HSM**: CardContact SmartCard-HSM with DKEK support
6. **TPM2**: Trusted Platform Module 2.0 with hierarchies and policies
7. **YubiKey**: YubiKey PIV (Smart Card) support
8. **AWS KMS**: Amazon Key Management Service integration
9. **GCP KMS**: Google Cloud Key Management Service integration
10. **HashiCorp Vault**: Vault Transit Engine integration

All backends support symmetric encryption (AES-GCM) and AEAD operations.

#### Certificate Management
- **CRUD Operations**: Store, retrieve, delete, list X.509 certificates
- **Certificate Chains**: Full chain management, building, and validation
- **CRL Support**: Certificate Revocation List management and checking
- **Validation**: Certificate verification with configurable `x509.VerifyOptions`
- **Hardware Storage**: Native PKCS#11 HSM and TPM2 NV RAM certificate storage
- **Hybrid Mode**: Automatic failover between hardware and external storage
- **Capacity Monitoring**: Certificate storage capacity management

#### Client Interfaces (100% API Coverage)
- **REST API**: HTTP/HTTPS web services with Fiber framework
- **gRPC**: High-performance RPC with Protocol Buffers
- **QUIC**: HTTP/3 over QUIC for ultra-low latency
- **CLI**: Full-featured command-line interface with Cobra
- **MCP**: Model Context Protocol (JSON-RPC) for AI integration

All interfaces expose the complete KeyStore API (17/17 methods).

#### Cryptographic Operations
- **Signing**: RSASSA-PSS, RSASSA-PKCS1-v1_5, ECDSA-SHA2, Ed25519
- **Verification**: Multi-algorithm signature verification
- **Asymmetric Encryption**: RSA-OAEP, RSA-PKCS1v15
- **Symmetric Encryption**: AES-128/192/256-GCM with nonce and tag management
- **AEAD**: Authenticated Encryption with Additional Data support
- **Hash Functions**: SHA-256, SHA-384, SHA-512, SHA3

#### Encoding & Interoperability
- **JWK**: JSON Web Key encoding/decoding (RSA, ECDSA, Ed25519, symmetric)
- **JWT**: JSON Web Token generation and validation (RS256, RS384, RS512, ES256, ES384, ES512, EdDSA)
- **JWE**: JSON Web Encryption with key wrapping (RSA-OAEP, AES-GCM)
- **PKCS#8**: Private/public key encoding with password protection
- **PEM**: PEM format encoding/decoding
- **Cross-Library Testing**: Verified interoperability with jose-go, go-jose, jwt-go

#### Security & Access Control
- **Authentication**: mTLS, API Key, NoOp (configurable per interface)
- **Authorization**: RBAC (Role-Based Access Control) integration
- **Audit Logging**: Comprehensive audit trail with structured logging
- **Policy Engine**: Configurable security policies
- **Metrics**: Prometheus-compatible metrics export
- **Correlation IDs**: Request tracing across all interfaces

#### Storage Abstraction
- **File Storage**: Production file-based storage with atomic operations
- **Memory Storage**: In-memory storage for testing
- **Filesystem Interface**: Custom FS implementation support (similar to io/fs)
- **Atomic Operations**: Safe concurrent file operations

#### Testing & Quality
- **Unit Tests**: 93.3% average code coverage across 25+ packages
- **Integration Tests**: 151 passing tests across all 10 backends
- **Benchmark Tests**: Performance benchmarks for critical operations
- **Docker Integration**: Complete Docker Compose test environments
- **Security Scanning**: gosec integration for vulnerability detection
- **Linting**: golangci-lint with comprehensive rulesets

#### Build System
- **Makefile**: 50+ targets for building, testing, and deployment
- **Version Injection**: Automatic version embedding in binaries via ldflags
- **Build Tags**: Conditional compilation for optional backends
- **Binary Builds**: CLI and 5 server binaries with proper versioning
- **Shared Library**: CGO-based libxkms.so with version numbering
- **Cross-Platform**: Linux and macOS support (Windows experimental)
- **CI/CD Ready**: GitLab CI configuration included

#### Documentation
- Getting Started guide with step-by-step instructions
- Backend-specific configuration guides (10 backends)
- Certificate Management best practices
- Symmetric Encryption guide
- API Parity documentation (REST/gRPC/QUIC/CLI/MCP)
- Build System documentation
- 15+ working examples covering all features

#### Licensing
- **Dual Licensed**: AGPL-3.0 (open source) + Commercial License
- **Copyright**: Jeremy Hahn & Automate The Things, LLC
- **Source Headers**: All 502 Go files updated with dual-license notice
- **Commercial Options**: Available from Automate The Things, LLC
- **SPDX Compliant**: Proper license identifiers throughout

### Changed
- Updated from Apache 2.0 to dual licensing model (AGPL-3.0 + Commercial)
- Reorganized documentation structure to match standard patterns
- Consolidated type definitions into pkg/types to prevent import cycles
- Enhanced error handling with typed errors and proper error wrapping

### Fixed
- Import/export functionality across all backends
- Symmetric encryption support in cloud KMS backends (AWS, GCP, Azure)
- Test coverage gaps in backend implementations
- Race conditions in concurrent operations
- Memory leaks in long-running server processes

### Security
- All source code scanned with gosec
- No high-severity vulnerabilities
- Secure random number generation for all cryptographic operations
- Protection against timing attacks in key operations
- Safe handling of sensitive data with proper zeroing

### Known Limitations (Alpha Release)
- API may change before v1.0.0 (backward compatibility maintained where possible)
- Some cloud KMS operations require active network connectivity
- TPM2 integration requires hardware TPM or software simulator (swtpm)
- YubiKey support requires physical device
- Windows support is experimental and not fully tested
- Azure Key Vault backend requires valid Azure credentials

### Performance
- Key generation: <100ms for RSA-2048, <50ms for ECDSA-P256, <10ms for Ed25519
- Signing: <10ms for RSA, <5ms for ECDSA, <1ms for Ed25519
- Symmetric encryption: <1ms for AES-256-GCM (1KB payload)
- Certificate operations: <5ms for storage/retrieval

### Contributors
- Jeremy Hahn (@jeremyhahn)

### Links
- Repository: https://github.com/jeremyhahn/go-xkms
- Documentation: https://github.com/jeremyhahn/go-xkms/tree/master/docs
- Commercial Licensing: licensing@automatethethings.com
- AGPL-3.0 License: https://www.gnu.org/licenses/agpl-3.0.html

[0.2.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.3-alpha
[0.2.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.2-alpha
[0.2.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.1-alpha
[0.2.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.2.0-alpha
[0.1.9-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.9-alpha
[0.1.8-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.8-alpha
[0.1.7-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.7-alpha
[0.1.6-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.6-alpha
[0.1.5-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.5-alpha
[0.1.4-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.4-alpha
[0.1.3-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.3-alpha
[0.1.2-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.2-alpha
[0.1.1-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.1-alpha
[0.1.0-alpha]: https://github.com/jeremyhahn/go-xkms/releases/tag/v0.1.0-alpha

---

## Merged from go-trusted-ca (2026-04-16)

The go-trusted-ca repository was merged into go-xkms. All ACME-related
functionality now lives under `pkg/acme/`. The following sections are
imported from go-trusted-ca's CHANGELOG for historical reference.

# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

#### API Documentation
- **Swagger UI** at `/docs` for interactive API exploration
- **ACME API OpenAPI spec** (`/openapi/acme-api.yaml`) - Full RFC 8555 documentation
- **Admin API OpenAPI spec** (`/openapi/admin-api.yaml`) - Administrative endpoints
- Spec switching via query parameter (`?spec=admin-api`)

#### Monitoring & Observability
- **Grafana Dashboard** (`deploy/grafana/dashboard.json`)
  - SLO tracking (99.9% availability, 99% challenge success)
  - Error budget tracking
  - Request latency heatmaps (p50, p95, p99)
  - Certificate issuance metrics
  - Challenge validation rates by type
  - System resource monitoring (CPU, memory, goroutines, GC)

#### Multi-Arch Docker Builds
- GitHub Actions workflow for automated multi-arch builds
- Support for `linux/amd64` and `linux/arm64`
- Trivy security scanning on every build
- SBOM (Software Bill of Materials) generation
- Build provenance attestation

---

## [0.1.0-alpha] - 2026-01-02

### Added

#### ACME Server (RFC 8555 Compliant)
- Full RFC 8555 ACME protocol implementation
- Directory endpoint with capability discovery
- Account management (create, update, deactivate, key rollover)
- Order workflow with authorization and challenge validation
- Certificate issuance and revocation
- Nonce management and replay protection

#### Challenge Types
- **HTTP-01**: Standard domain validation via HTTP token
- **DNS-01**: Domain validation via DNS TXT records
- **device-attest-01**: TPM 2.0 device attestation per draft-acme-device-attest
- **enroll-01**: TCG-compliant IDevID enrollment for TPM-equipped devices
- **endorse-01**: Endorsement Key certificate provisioning

#### Multi-Tenancy
- Tenant isolation with dedicated CAs
- Per-tenant key management via go-xkms KMS
- RBAC role-based access control
- RBAC policies with CEL expressions

#### Admin API
- RESTful management interface
- Tenant lifecycle management
- Policy and role administration
- CA status and health monitoring

#### Storage Backends
- All go-xkms backends supported:
  - Local filesystem (PKCS#8)
  - TPM 2.0 hardware protection
  - PKCS#11 HSM integration
  - AWS KMS
  - GCP Cloud KMS
  - Azure Key Vault
  - HashiCorp Vault
- Certificate storage via go-objstore

#### Security
- JWT-based authentication
- TLS 1.3 support
- Rate limiting with RFC 8555 compliance
- Proxy header support (X-Forwarded-For, X-Real-IP)

#### Deployment
- Single-node embedded mode
- Raft-based clustering via QRDB
- Docker container support
- Prometheus metrics endpoint

#### Developer Experience
- Comprehensive test coverage (90%+ on core packages)
- Integration test suite with Docker
- Example configurations and quickstart guide

### Dependencies
- go-xkms v0.2.2-alpha
- go-objstore v0.1.4-alpha
- go-qrdb (local development)

### Known Limitations
- TCG-CSR-IDEVID parsing partially implemented
- Client package coverage at 74.8% (TPM functions require integration tests)

---

[0.1.0-alpha]: https://github.com/jeremyhahn/go-trusted-ca/releases/tag/v0.1.0-alpha
