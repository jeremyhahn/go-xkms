# AVR Device Backend — Engineering

> **Status: NORMATIVE** · Feature: `avr-device-backend` · Repo: `go-xkms` · Last verified: 2026-09-23

Package: `pkg/backend/avr` · Import path
`github.com/jeremyhahn/go-xkms/pkg/backend/avr`

Upstream: `github.com/jeremyhahn/arduino-generic/sdk/go v0.3.0-alpha`, a Layer 0
module whose only dependencies are `go.bug.st/serial` and `testify`. Importing
it from Layer 3 is permitted and is what it exists for.

## Exported surface

| Symbol | What it is |
|---|---|
| `NewBackend(ctx, *Config, *aggeneric.Device) (*Backend, error)` | Reads `CAPS` and caches it. Fails when the device is absent, silent, or speaks a protocol major this host does not. |
| `Backend.Type() types.BackendType` | `types.BackendTypeAVR` (`"avr"`). |
| `Backend.Capabilities() types.Capabilities` | Answers from the cached `CAPS`. No I/O, no allocation. |
| `Backend.Caps() aggeneric.Caps` | The device's `CAPS` reply verbatim. |
| `Backend.AttestLevel() (types.AttestLevel, error)` | Derived from `Caps.CryptoTier` and nothing else. |
| `Backend.Algorithms() Algorithms` | Derived from `Caps.Algorithms` and nothing else. |
| `Backend.AttestKey(ctx, attrs, nonce) (interface{}, error)` | `*Attestation`. The nonce is 32 bytes from `deviceattest01.DICENonce`. |
| `Backend.Identity(ctx) (*Identity, error)` | `PROV_INFO`: element serial, die revision, both zone lock states. Provisioning images only. |
| `Backend.Health(ctx) (*Health, error)` | `SYS_INFO`: uptime, free RAM, reset cause. Not a clock. |
| `Backend.GetKey(ctx, attrs) (crypto.PrivateKey, error)` | `*DeviceKey` carrying the element's public point. |
| `Backend.ListKeys(ctx)` | The one key the device holds, or none. No I/O. |
| `DeviceKey` | `Public()`, `Slot()`, `CN()`, `Equal()`. Deliberately not a `crypto.Signer`. |
| `Algorithms` | `Can`, `Named`, `Unnamed`, `Empty`, `Set`, `String`. |
| `Attestation` | Format, parsed leaf, DER, `dice.ClaimsSet`, nonce, attest level, crypto tier, `Anchored`. |
| `AttestationConfig` | `TrustStore *truststore.Config`, `Intermediates [][]byte`. |
| `Identity` | `Serial`, `SerialBytes`, `Revision`, `ConfigLocked`, `DataLocked`, `Provisioned()`. |
| `FormatDICE` | `"dice"`, the same string `device-attest-01` uses for this evidence. |
| `Config`, `DefaultConfig()`, `Config.Validate()` | `KeyCN`, `Slot`, `RequestTimeout`, `Attestation`, `Logger`. |

Every one of them is re-exported from `sdk/go/backends_avr.go` under an `AVR`
prefix — `AVRBackend`, `AVRConfig`, `NewAVRBackend`, `ErrAVR<Name>` — as type
aliases to these declarations rather than copies. A consumer subject to a layer
guard that refuses `go-xkms/pkg/...` reaches the backend there; `BackendTypeAVR`
on its own named a capability it could not construct. The device itself comes
from `arduino-generic/sdk/go`, which a consumer imports directly: it is another
project's Layer 0 SDK, and re-exporting it here would be this repository
speaking for an API it does not own.

`GenerateKey`, `Signer`, `Decrypter`, `DeleteKey` and `RotateKey` exist to
satisfy `types.KeyProvider` and always refuse. Each refusal names a permanent
property of the part or the protocol.

## Invariants

- **The backend holds no private key** and needs no locked memory. Nothing here
  reaches `go-enclave`, and if that ever changes the layering changes with it.
- **Attestation level comes from the crypto tier.** Not from the attestation
  feature bit, not from the algorithms on offer, not from whether a chain
  happened to verify.
- **Algorithms come from the capability bitmap.** The bitmap is not the
  algorithm identifiers that travel in an attestation frame: `HMAC-SHA256` is
  bit `0x0004` and identifier `0x10`. They are separate types upstream for
  exactly this reason.
- **A tier or an algorithm bit this host cannot name never negotiates up.**
  Unknown tier → `AttestLevelUnattested` plus `ErrUnknownCryptoTier`; unknown
  algorithm bit → reported by `Unnamed`, `Can` returns false.
- **`CAPS` is read once.** `Capabilities` returns no error, so a backend that
  re-read it would have to invent an answer — about the strength of a root of
  trust — whenever the device did not reply.
- **Nothing here may reach `PROV_GENKEY`.** It replaces the identity every
  other answer is about. `GetKey` uses `PROV_PUBKEY`, which recomputes the
  public point and generates nothing.
- **A refusal costs no round trip.** Every unsupported operation and every
  argument error answers before a frame is built.
- **This package never hashes a key authorization.** The challenge arrives
  already hashed, from `deviceattest01.DICENonce`. One place hashes; everything
  else compares.
- **The attestation nonce check is unconditional.** Anchoring is configurable;
  freshness is not. `Anchored` false means no roots were configured, never that
  anchoring ran and did not hold.
- **The two nonce widths never mix.** 32 bytes is enrolment (`eat_nonce` in the
  alias certificate); 16 is runtime freshness (the evidence frame). `AttestKey`
  refuses 16 before a frame is built, because a device handed the shorter one
  cannot tell it was truncated.
- **One device, one conversation.** Every command is issued under the backend's
  `wire` mutex, and `AttestKey` holds it across the whole of `AttestCert` —
  several `Do` calls that must stay contiguous, because the device regenerates
  its certificate pages for each nonce and keeps no copy. `aggeneric.Device` is
  a strict request/response client with no locking of its own (its
  documentation says so), and `types.KeyProvider` requires implementations to
  be thread-safe: two goroutines in `Do` at once consume each other's replies.
- **`Config.RequestTimeout` reaches the device.** `NewBackend` applies it to the
  attached device with `aggeneric.WithTimeout` as well as to each call's
  context. `Device.Do` computes its read deadline from the device's own timeout
  and notices a context only between reads, so without this a configured 30s
  still gave up at the SDK's 10s default on a blocking read. The device is the
  caller's, and this does change it: a backend that issues every command on that
  link owns the deadline those commands are given.
- **The alias certificate is ECDSA-SHA256 signed.** `dice.Verify` is called with
  `RequireDeviceSignedLeaf`, because the leaf's issuer is the DeviceID key in
  the same element and its certificate is not in the chain — so the generic
  device-residency rule has no certificate to check the algorithm on.
- **Element lock polarity is not re-inverted.** The element writes `0x55` for
  UNLOCKED; `ElementInfo` already decodes that, and `Identity` copies the fields
  through unchanged.

## Errors

All sentinels, all prefixed `avr backend:`. Grouped by what a caller should do:

- **Fix the call** — `ErrNilConfig`, `ErrNilDevice`, `ErrMissingKeyCN`,
  `ErrInvalidSlot`, `ErrInvalidKeyAttributes`, `ErrUnknownKey`,
  `ErrInvalidNonce`, `ErrTrustStoreInit`, `ErrBackendClosed`.
- **Refuse the evidence** — `ErrMalformedCertificate`, plus the `dice` package's
  own errors returned unwrapped so there is one vocabulary and one place each
  check lives: `ErrUnsupportedKeyType`, `ErrUnsupportedSignatureAlgorithm`,
  `ErrNonceMismatch`, `ErrChainVerificationFailed`, `ErrUccsEvidenceNotFound`,
  `ErrNonceClaimMissing`, `ErrCriticalEvidenceUnreadable`.
- **Stop asking** — `ErrSigningUnsupported`, `ErrDecryptionUnsupported`,
  `ErrGenerationUnsupported`, `ErrDeletionUnsupported`,
  `ErrRotationUnsupported`.
- **Refuse the device** — `ErrProtocolVersion`, `ErrUnknownCryptoTier`,
  `ErrNoDeviceKey`, `ErrInvalidDevicePoint`.
- **Retry, reconnect or read the firmware** — `ErrDeviceUnreachable`,
  `ErrDeviceProtocol`, `ErrDeviceRefused`, `ErrCommandUnavailable`,
  `ErrNotProvisioned`, `ErrDeviceCrypto`, `ErrAuthRequired`, `ErrDeviceBusy`,
  `ErrProtectedRegion`, `ErrDeviceInternal`, `ErrUnsupportedByDevice`,
  `ErrElementUnreachable`, `ErrInvalidArgument`.

`ErrUnsupportedByDevice` and `ErrCommandUnavailable` are deliberately separate.
A software-tier device asked to mint an alias certificate answers the first: it
knows what a certificate is and has no public half to certify. The second says
the feature was compiled out. One is a part to change and the other is a build
to change.

Device failures are returned as `errs.Joined`, so both sides stay reachable:
`errors.Is` against a sentinel above says what to do, and `errors.As` against
the SDK's own type — `*aggeneric.CRCError`, `*aggeneric.ShortReplyError`,
`*aggeneric.TimeoutError` — reaches the values that say why. `io.EOF` stays
reachable underneath a link failure, which is how a closed port is told from a
stalled one.

A status code this build has no mapping for becomes `ErrDeviceRefused`, never
the nearest known one: statuses extend and never renumber, so an unrecognised
one means this host is older than the firmware.

Context cancellation passes through unchanged, so `errors.Is(err,
context.Canceled)` still works across this layer.

## Configuration

| Field | Default | Notes |
|---|---|---|
| `KeyCN` | `"avr-device-id"` | Refused when empty rather than defaulted: an empty name would match every `KeyAttributes` that forgot to set one. |
| `Slot` | `aggeneric.SlotDeviceID` (0) | Any other value is refused. Slot 1 is the UDS; reading it as a public key would hand out a derivation secret's slot as an identity. |
| `RequestTimeout` | 30s | Generous on purpose — a device deriving a key in software spends seconds inside one command on a 16 MHz part. Applied to the attached device as well as to each call's context, so it is the deadline the read actually gets. |
| `Attestation` | nil | `TrustStore` and `Intermediates`. Nil is the unanchored profile: every check but anchoring still runs. |
| `Logger` | stderr text handler | |

## Tests

`make test-avr`, `make bench-avr`, `make coverage-avr`. Coverage is 99.6%.

There is no hardware and CI has none, so the tests drive a **fake link and the
real codec**: every byte a test sends is framed by the SDK's own
`EncodeResponse` and every byte the backend sends is parsed by the SDK's own
`Decode`. What is under test is this package against the protocol as
arduino-generic implements it. Mocking `*aggeneric.Device` would replace the one
thing worth exercising — a reply's layout, a status code's meaning, a command's
length — with this package's own opinion of it.

A command with no entry in the fake link's table is answered
`StatusErrUnknownCmd`, which is what firmware built without that feature really
does: the absence of a reply models the absence of a handler.

The link's read returns `io.EOF` when its buffer is exhausted, so a negative
test fails in microseconds instead of spinning to the SDK's read deadline.

`concurrency_test.go` holds the two tests about the link rather than the
protocol. One drives `Health`, `Identity`, `GetKey` and `AttestKey` from many
goroutines at once and requires every caller to get its own reply — without the
`wire` mutex the SDK's shared receive buffer panics, and `-race` reports the
unsynchronised sequence counter directly. The other attaches a link that blocks
until the read deadline, as a serial port does, and measures the wait: a
100ms `RequestTimeout` that never reached the device waits 10 seconds.

## Test vectors

`vectors_test.go` mirrors `arduino-generic`'s `testdata/uccs_vectors.h`: the
471-byte alias certificate a real device emits, frozen as a literal, with a real
ECDSA signature over its own TBS and a real point on P-256.
`TestAttestKeyVerifiesTheCertificateARealDeviceEmits` drives it through the
whole path.

**A failure there is a wire break, not a test to update.** Those are the bytes
every already-provisioned device puts on the wire. It is mirrored rather than
imported because the SDK does not export it — the vector lives beside the
firmware's contract file, not in the Go module — and that second copy is
acceptable only because neither copy is generated: both are frozen literals of
one fact, so drift is a failure rather than two implementations agreeing with
each other about something wrong.

## Resolved upstream gaps

Both blockers reported against `v0.2.0-alpha` are fixed in `v0.3.0-alpha`:
`ProvInfo` now receives the two lock bytes explicitly (a 38-byte reply; a
36-byte one from older firmware is refused as short rather than read past), and
`Attest`/`AttestCert` exist with internal paging and exported nonce widths.

The one remaining disagreement — `dice.Verify` requiring a `DiceTcbInfo` the
alias profile does not emit — was resolved in `dice` rather than worked around
here: §6.1.4 permits UCCS "in place of" `DiceTcbInfo`. See `architecture.md`.
