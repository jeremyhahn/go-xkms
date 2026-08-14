# QR Code Pairing

QR code pairing allows instant device pairing by scanning a QR code displayed on a paired workstation or terminal.

## Payload Format

The QR code contains a JSON payload, base64url-encoded:

```json
{
  "v": 1,
  "type": "xkey-pair",
  "noise_pub": "<base64url Noise static public key>",
  "addr": "192.168.1.100:8444",
  "transport": "tcp",
  "name": "John's Workstation",
  "code": "ABCD1234"
}
```

| Field       | Description                                      |
|-------------|--------------------------------------------------|
| `v`         | Protocol version (currently `1`)                 |
| `type`      | Must be `xkey-pair`                              |
| `noise_pub` | Base64url-encoded Noise static public key        |
| `addr`      | Host and port of the TCP relay                   |
| `transport` | Transport type (`tcp`)                           |
| `name`      | Human-readable device name                       |
| `code`      | Short confirmation code for out-of-band verify   |

## URI Scheme

```
xkey-pair://<base64url-encoded-payload>
```

The URI can be copied and pasted directly when camera scanning is not available.

## CLI Usage

The QR code is **generated** by the workstation and **scanned by the phone**.
The desktop CLI has no scan-a-pairing-QR command; `xkey device pair` is the
BLE pairing path, not the QR path.

```bash
# Show QR code for pairing (starts the TCP relay; --listen defaults to :8444):
xkey device relay --qr
xkey device relay --qr --listen :8444
```

`xkey device relay` takes only `--listen` and `--qr`.

### Pairing over BLE instead

`xkey device pair` scans over Bluetooth, performs the Noise XX handshake and
verifies the phone through hardware attestation. Its flags are `--device`,
`--timeout` and `--force` — there is no `--scan` or `--uri`:

```bash
# Scan and interactively select a device to pair
xkey device pair

# Pair with a specific device by name
xkey device pair --device "John's Pixel"

# Extend the scan window
xkey device pair --timeout 60s

# Force re-pairing if already paired
xkey device pair --device "John's Pixel" --force
```

This command is behind the `ble` build tag; a binary built without it carries a
stub that reports BLE support is unavailable.

## Packages

- **`xkey/pkg/qrgen/`** -- QR code generation using gozxing (image output) and qrterminal (ASCII terminal output). `PairingPayload` is the struct behind the JSON above; `ToURI`/`FromURI` convert to and from the `xkey-pair://` scheme.
- **`xkey/pkg/qrscan/`** -- Screen scanning with configurable `Mode`: `ScanModeOTP` (the default), `ScanModePairing`, or `ScanModeAny`. Only the OTP mode currently has a CLI entry point, `xkey oath scan`; `ScanModePairing` is available to callers of the library but no command uses it yet.
