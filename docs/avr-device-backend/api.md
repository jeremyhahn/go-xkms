# AVR Device Backend — API

> **Status: NORMATIVE** · Feature: `avr-device-backend` · Repo: `go-xkms` · Last verified: 2026-10-11

## Transports

| Transport | Reachable |
|---|---|
| Embedded Go API | **yes** |
| REST | no |
| gRPC | no |
| MCP | no |
| CLI | no |
| SDK (`sdk/go`) | **yes** — `NewAVRBackend`, `AVRConfig`, `AVRAttestation`, the `ErrAVR*` sentinels, and the `BackendTypeAVR` / `StoreAVR` constants |
| ACME `device-attest-01` | indirectly — the caller forwards `Attestation.CertificateDER` as `dice`-format evidence; the identifier is `hex(Attestation.Ueid)`. A physical device cannot sign the finalization CSR (see below) |

The backend is not served over a network transport, and that is a pending
decision rather than an omission. Serving it needs a daemon configuration that
names a device's serial port and the lifetime of the link over it — which port
belongs to which tenant, what happens when the device is unplugged mid-request,
whether one process may hold two devices. None of those are coding questions.

## Embedded Go API

```go
import (
    tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"
    "github.com/jeremyhahn/trusted-firmware/sdk/go/serialport"
    "github.com/jeremyhahn/go-xkms/pkg/backend/avr"
    "github.com/jeremyhahn/go-xkms/pkg/types"
)

port, err := serialport.Open("/dev/ttyUSB0", 115200)   // the caller's link
if err != nil {
    return err
}
defer port.Close()

backend, err := avr.NewBackend(ctx, avr.DefaultConfig(), tfw.New(port))
if err != nil {
    return err
}
defer backend.Close()

level, err := backend.AttestLevel()          // what the device's tier establishes
algs := backend.Algorithms()                 // what the element can actually perform
key, err := backend.GetKey(ctx, &types.KeyAttributes{CN: avr.DefaultKeyCN})
```

### Attestation

```go
// The challenge is SHA-256 of the ACME key authorization. Hash it HERE and
// nowhere else -- one function so a device, a provisioning tool and a verifier
// cannot each hash something slightly different.
nonce := deviceattest01.DICENonce(keyAuth)

result, err := backend.AttestKey(ctx, &types.KeyAttributes{CN: avr.DefaultKeyCN}, nonce)
if err != nil {
    return err                                // a device that cannot answer is not a pass
}
att := result.(*avr.Attestation)

att.CertificateDER        // forward these bytes verbatim; never re-encode them
att.Claims.Nonce          // the challenge, already matched in constant time
att.Ueid                  // the device identifier, type byte included (dice.DeviceUeid of claim 256)
att.Claims.Other[256]     // the same ueid, as the raw CBOR the device encoded
att.Claims.Other[273]     // the firmware measurement, likewise raw CBOR
att.AttestLevel           // from the device's crypto tier
att.Anchored              // false means no roots were configured -- not that anchoring failed
```

Anchoring is configured, not passed per call:

```go
cfg := avr.DefaultConfig()
cfg.Attestation = &avr.AttestationConfig{
    TrustStore:    &truststore.Config{ExternalRootPaths: []string{"/etc/xkms/avr-roots.pem"}},
    Intermediates: [][]byte{deviceIDCertDER},   // the device has nowhere to keep these
}
```

A trust store that will not load fails `NewBackend`, not the first attestation:
discovering it later would mean discovering it in front of a device waiting to
enrol.

`pkg/backend/avr` itself imports only the SDK's root package, which depends on
nothing outside the standard library. The `serialport` subpackage above is the
caller's choice and brings `go.bug.st/serial` into the caller's graph, not into
this one — any `io.ReadWriter` will do, including a pty or a subprocess pipe.

`backend` satisfies both `types.KeyProvider` and `types.AttestingKeyProvider`,
so it composes anywhere either interface is accepted. It is safe to use from
several goroutines: every command is serialised on the link, and a multi-frame
exchange such as `AttestKey` stays contiguous.

### Enrolling over ACME device-attest-01

The ACME server verifies the forwarded certificate with `dice.Verify` against
`challenges.device_attest.dice_roots` (`pkg/config/acme.go:810-820`), and
names the device by the hex of its UEID (`pkg/acme/challenges/device-attest-01/identity.go:162-171`),
which is `hex(att.Ueid)`.

Finalization needs a CSR signed by the device identity key, and
`backend.Signer` returns `ErrSigningUnsupported` (`pkg/backend/avr/backend.go:436-441`):
the wire has no command that signs a host-supplied digest. A physical AVR can
therefore answer the challenge but cannot finish enrolment. The flow is proven
end to end only against the `tfwsim` simulator, whose published test seed lets
the test sign the CSR (`pkg/acme/client/device_attest_dice_e2e_test.go`).

### From the SDK

A consumer under a layer guard that refuses `go-xkms/pkg/...` uses the same API
through `sdk/go`, which aliases these declarations rather than copying them:

```go
import (
    tfw "github.com/jeremyhahn/trusted-firmware/sdk/go"
    "github.com/jeremyhahn/trusted-firmware/sdk/go/serialport"
    xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

backend, err := xkms.NewAVRBackend(ctx, xkms.DefaultAVRConfig(), tfw.New(port))
if errors.Is(err, xkms.ErrAVRNoDeviceKey) {
    // a part with no crypto provider to hold an identity
}
```

The device comes from `trusted-firmware/sdk/go` directly. That module is another
project's Layer 0 SDK; re-exporting its types from here would be this
repository speaking for an API it does not own.

`Config.RequestTimeout` is applied to the device as well as to each call's
context, so a 60-second timeout waits 60 seconds on a device that is slow rather
than the SDK's own 10-second default.

## Type constants

`types.BackendTypeAVR` (`"avr"`) and `types.StoreAVR` (`"avr"`) are re-exported
from `pkg/backend`, `sdk/go` and `pkg/xkms` (as `xkms.BackendAVR`), and are
recognised by `types.ParseStoreType`, `types.StoreType.IsValid`,
`xkms.BackendType.IsValid`, `keyIDToBackendType` and `backendTypeToStoreType`.
