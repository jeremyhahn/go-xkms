# Phone as HSM — API

> **Status: NORMATIVE** · Feature: `phone-hsm` · Module: `go-xkms/xkey` · Last verified: 2026-09-25

Transport shapes:
[`../../../docs/key-management/api.md`](../../../docs/key-management/api.md).

## The seventh transport

`usb` is a **seventh, product-specific transport** alongside the portfolio's
six. The "all six transports" completeness rule does not apply to it: it carries
what its device protocol can and nothing else.

| Property | Value |
|---|---|
| Channel | USB AOA, TCP relay, or BLE |
| Session | Noise XX — `Noise_XX_25519_ChaChaPoly_SHA256` |
| Payload | JSON-RPC over the encrypted session |
| Streaming | none — the transport only implements `Connect`/`Close`/`Healthy`/`Request` |
| Concurrency | serialised; one request at a time per session |
| Implementation | `go-xkms/pkg/api/transport/usb`, `xkey/pkg/pairing` |

## What the channel carries

The pairing protocol, split by concern in `xkey/pkg/pairing`:

| Domain | Protocol file |
|---|---|
| core operations | `protocol.go` |
| attestation | `protocol_attestation.go` |
| PIV | `protocol_piv.go` |
| OATH | `protocol_oath.go` |
| backup | `protocol_backup.go` |
| sharing | `protocol_sharing.go` |
| sync | `protocol_sync.go` |
| device enrollment | `protocol_device_enrollment.go` |
| IDevID | `protocol_idevid.go` |
| local / remote mode | `protocol_local.go`, `protocol_remote.go` |

Each has a bridge on the desktop side (`bridge*.go`). `fragmentation.go` splits
messages the transport cannot carry whole.

## What it explicitly does not carry

`go-xkms/pkg/api/transport/usb/transport.go` implements the full method sets of
`PasswordService`, `SealStoreService` and `PolicyService` and returns
`ErrNotSupported` — *"operation not supported by this protocol"* — for **every
one**. The general server API does not travel over the phone channel; only the
pairing protocol does.

That is a design statement rather than a gap, which is why it is implemented as
an explicit error rather than a missing method.

## Connect is a security operation

`Connect` (`transport.go:145`):

1. Fails immediately with `ErrNoiseNotConfigured` if no pairing keys are set —
   **before touching the bus**.
2. Opens the AOA channel.
3. Runs the **identity exchange on every connection** — the phone's stream
   responder always expects it — binding the phone's attestation fingerprint
   into the Noise prologue.
4. Completes the Noise XX handshake against `ExpectedRemoteStatic` and
   `ExpectedDeviceFingerprint`.

Failure at any step closes the transport. There is no partially established
session.

**Where the local static key comes from is invisible on the wire, and that is
deliberate.** This host's Noise static private key is sealed at rest under
the barrier when one exists, or kept in the legacy plaintext form with a
warning logged when it does not (#42, see `engineering.md`'s
*`LocalNoisePrivateKey` custody* section); by the time `Connect` runs, the
caller has already resolved it into protected memory either way, and the
protocol above never carries or references which. `ErrNoiseNotConfigured`
above still means exactly "no pairing keys are set" — a caller that could not
unseal a genuinely sealed record (a barrier exists but could not be opened)
reports that failure before ever calling `Connect`, through its own error,
not this transport's.

## Requests are serialised, by necessity

`Request` takes a mutex across encrypt → send → receive → decrypt. The reason is
in the code: a Noise cipherstate advances a monotonic nonce per message, so
concurrent senders would put frames on the wire out of nonce order and the phone
would reject them.

This is not a conservative default to be tuned away. Removing the mutex breaks
the session.

## Error mapping

| Condition | Error |
|---|---|
| no pairing keys | `ErrNoiseNotConfigured` |
| not connected | `ErrNotConnected` |
| handshake or fingerprint mismatch | `transport.ErrConnectionFailed` (detail: `noise handshake: …`) |
| send failed | `transport.ErrConnectionFailed`; **transport marked disconnected** |
| decrypt failed | `transport.ErrInvalidResponse` |
| phone returned a JSON-RPC error | `ErrRequestFailed` with `[code] message` |
| any service method | `ErrNotSupported` |

A failed send disconnects rather than retrying: a Noise session cannot be
resumed mid-nonce-sequence.

### A `remote.*` method can be unavailable on a specific host

Several `remote.*` methods depend on a collaborator the desktop CLI wires in
optionally: `remote.oath*` needs an OATH store, `remote.pivListSlots`/
`pivGetCert` need PIV certificate storage, and `remote.sync*` needs a sync
service. A phone that calls one of these against a host where the
collaborator was never configured gets a JSON-RPC error with code `-32035`
(`ErrorCodeFeatureUnavailable`) rather than a fabricated empty success — treat
it as "not offered here," the same as a phone declining an operation its
hardware does not support. `remote.createBackup`/`restoreBackup`/`listBackups`
currently answer this way unconditionally: see
[`engineering.md`](engineering.md) §"Bridge collaborators are optional, and
say so honestly" for why.

## The cross-repo wire contract

The phone side is **xkey-android**, a separate Kotlin repository with no Go
import in either direction. The coupling is wire compatibility alone, which
makes it a standing constraint rather than a build-time one: **a change to this
protocol must stay wire-compatible with xkey-android, or be made on both sides
in the same change.** The canonical contract lives in the company documentation.

## Versioning

`NoiseProtocolName` is a constant and there is **no suite negotiation**. Both
sides must agree exactly, which is why changing it is a coordinated release
rather than a version bump — and why the non-FIPS-approved ChaChaPoly suite is a
cross-repo problem rather than a local one
([`engineering.md`](engineering.md) §"The cipher suite is fixed").
