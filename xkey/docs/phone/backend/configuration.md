# Phone Backend Configuration

## Overview

The phone backend is configured in the xkmsd YAML configuration file and reuses the pairing configuration from `xkey phone pair`.

## xkmsd Configuration

```yaml
backends:
  phone:
    enabled: true
    transport: "ble"              # "ble" or "usb"
    config_path: "~/.xkey/phone.yaml"  # Pairing config from xkey phone pair
    request_timeout: "30s"        # Per-operation timeout (includes biometric wait)
    scan_timeout: "30s"           # BLE device scan timeout (BLE only)
```

## Go Configuration Struct

```go
type Config struct {
    Transport       string        // "ble" or "usb"
    BLEAddress      string        // BLE MAC address (for BLE transport)
    USBPort         int           // ADB forwarded port (for USB transport, default 8444)
    NoisePrivateKey string        // Base64 Noise static private key
    PhonePublicKey  string        // Base64 phone's Noise static public key
    ScanTimeout     time.Duration // BLE scan timeout (default 30s)
    RequestTimeout  time.Duration // Per-operation timeout (default 30s)
    Logger          *slog.Logger
}
```

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
# 4. The desktop prints a verification code (go-xkms#1306); the Android app
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
- Automatic device scanning (uses saved BLE address)
- Fragmentation for messages larger than MTU (default 247 bytes)
- Range: ~10 meters (varies by environment)

### USB Transport (ADB Port Forwarding)

```yaml
backends:
  phone:
    enabled: true
    transport: "usb"
    usb_port: 8444               # ADB forwarded port
    config_path: "~/.xkey/phone.yaml"
```

Setup:
```bash
# Enable USB debugging on phone
# Connect phone via USB cable
adb forward tcp:8444 tcp:8444
```

The USB transport connects to localhost:8444, which ADB tunnels to the phone.

## Sharing Policy (Bidirectional)

For Phase 6 (bidirectional key sharing), the xkey binary configuration includes sharing policy:

```yaml
# ~/.xkey/config.yaml
xkmsd:
  enabled: true
  protocol: "unix"
  address: "xkms-data/xkms.sock"
  sharing:
    policy: "shared"              # "private", "shared", "ask"
    allowed_backends:
      - "tpm2"
      - "software"
    denied_backends:
      - "vault"
```

## Timeouts

| Parameter | Default | Description |
|-----------|---------|-------------|
| `scan_timeout` | 30s | BLE device scan duration |
| `request_timeout` | 30s | Per-operation timeout (includes biometric) |
| `connect_timeout` | 10s | Connection establishment timeout |
| `handshake_timeout` | 10s | Noise XX handshake timeout |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `XKEY_PHONE_CONFIG` | Override phone config file path |
| `XKEY_PHONE_TRANSPORT` | Override transport type ("ble" or "usb") |
| `XKEY_PHONE_TIMEOUT` | Override request timeout |

## See Also

- [Architecture](architecture.md)
- [Security](security.md)
- [xKey Phone Transport](../../../xkey/docs/phone/transport.md)
