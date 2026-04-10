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

```bash
# Show QR code for pairing (starts TCP relay on default port):
xkey device relay --qr --listen :8444

# Scan QR from screen capture:
xkey device pair --scan

# Paste URI directly:
xkey device pair --uri "xkey-pair://..."
```

## Packages

- **`xkey/pkg/qrgen/`** -- QR code generation using gozxing (image output) and qrterminal (ASCII terminal output).
- **`xkey/pkg/qrscan/`** -- Screen scanning with configurable `ScanMode`: `OTP`, `Pairing`, or `Any`.
