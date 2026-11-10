# Phone Backend Configuration

> **Status: REFERENCE** · Last verified: 2026-10-13
> Configuration background for the xkmsd phone backend; superseded by [phone-hsm/engineering.md](../../phone-hsm/engineering.md). Where they disagree, the feature folder wins.

## Overview

The phone backend is configured in the `backends.phone` section of the xkmsd
YAML configuration file. xkmsd only logs the configured transport at start-up
(`initPhoneBackend`, `pkg/server/backend_phone.go:32`); the backend is
registered when the embedder that owns the phone connection supplies a
`Sender` (`RegisterPhoneBackend`, `pkg/server/backend_phone.go:58`). Nothing
in this repository calls `RegisterPhoneBackend`.

## xkmsd Configuration

`PhoneConfig` (`pkg/config/config.go:1267`):

```yaml
backends:
  phone:
    enabled: true
    transport: "ble"                  # "ble" or "tcp" (USB via ADB forwarding)
    device_address: "AA:BB:CC:DD:EE:FF"   # BLE MAC, or host:port for tcp
    noise_static_key: "<secret reference>" # this host's Noise static private key
    phone_static_key: "<hex>"         # the paired phone's Noise static public key
    request_timeout: "30s"            # per-operation timeout; 0 = 30s default
    config_path: ""                   # declared, not read by xkmsd
```

## Go Configuration Struct

The backend's own `Config` (`pkg/backend/phone/config.go:76`) carries
`Transport`, `DeviceAddress`, `NoiseStaticKey`, `PhoneStaticKey`,
`ScanTimeout`, `ConnectTimeout`, `RequestTimeout`, `Attestation` and `Logger`.
`Attestation` (`AttestationConfig`, `config.go:52`) holds `platform`
(required, `android`), `trust_store`, `min_security_level`,
`verify_boot_state`, `status_list_url` and `status_list_file`; when nil,
attestation chains are returned unverified. `NewAndroidVerifier`
(`pkg/backend/phone/android/verifier.go:68`) builds the Android attestation
revocation status list source once (ruling 180): `status_list_file` when set,
else `status_list_url` (empty means Google's
`https://android.googleapis.com/attestation/status`), cached for the freshness
the response allows. Every chain certificate is checked against it, and the
check fails closed: an unreadable or stale list fails the chain with
`ErrChainVerificationFailed` wrapping `ErrStatusListUnavailable`, and a
verifier without a source refuses (`verifier.go:131`).
`RegisterPhoneBackend` copies only transport, device address, both static
keys and the request timeout, so a backend xkmsd registers has no
`Attestation` and no scan or connect timeouts.

## Pairing Setup

There is no `xkey phone pair` command. Pairing is a `device` verb, documented
in full in phone-hsm's [cli.md](../../phone-hsm/cli.md) and
[user.md](../../phone-hsm/user.md):

```bash
# On the laptop
xkey device scan
xkey device pair

# Follow prompts:
# 1. Enable Bluetooth on both devices
# 2. Open xKey app on phone and start advertising
# 3. Select the discovered device
# 4. The desktop prints a verification code; the Android app
#    does not yet display a matching code to compare it against
```

This appends a record to `devices.yaml` (resolved under the xkey data
directory), containing the device's name and BLE address, its Noise static
public key, this host's own Noise static private key (sealed under the
barrier when one is configured -- see [Security](security.md)), and, when
attestation succeeded, the device's attested fingerprint and security level.
There is no separate `phone.yaml`.

## Transport Configuration

### BLE Transport

- Default for wireless use
- Fragmentation for messages larger than the negotiated MTU
- Range: ~10 meters (varies by environment)

### TCP Transport (USB with ADB Port Forwarding)

```yaml
backends:
  phone:
    enabled: true
    transport: "tcp"
    device_address: "127.0.0.1:8444"
```

Setup:
```bash
# Enable USB debugging on phone
# Connect phone via USB cable
adb forward tcp:8444 tcp:8444
```

ADB tunnels the local port to the phone.

## Sharing Policy (Bidirectional)

Which laptop backends the phone may reach over `remote.*` is set in the xkey
config, not xkmsd's (`xkey/cmd/xkey/cmd/dial_xkmsd.go:88-99`):

```yaml
xkmsd:
  enabled: true
  protocol: "unix"
  address: "<path to xkms.sock>"
  sharing:
    allowed_backends:     # empty = all backends
      - "tpm2"
      - "software"
    denied_backends:
      - "vault"
```

## Timeouts

Defaults in `pkg/backend/phone/config.go:33-39`:

| Parameter | Default | Description |
|-----------|---------|-------------|
| `ScanTimeout` | 30s | BLE device scan duration |
| `ConnectTimeout` | 15s | Connection establishment timeout |
| `RequestTimeout` | 30s | Per-operation timeout (includes biometric wait) |

Only `request_timeout` is exposed in the xkmsd config.

## Environment Variables

None: the phone backend reads no environment variables.

## See Also

- [Architecture](architecture.md)
- [Security](security.md)
- [Phone Transport](../transport.md)
