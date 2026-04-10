# TCP Relay

The TCP relay server enables network-based device pairing as an alternative to Bluetooth.

## Architecture

- `phone.TCPPairingServer` listens for incoming TCP connections.
- Each connection performs a Noise XX handshake (3 messages).
- After the handshake completes, an encrypted JSON-RPC request/response loop begins.
- Framing uses 2-byte big-endian length prefixes, matching `pairing.TCPTransport`.
- Default port: `8444`.

## CLI Usage

```bash
xkey device relay                    # Start on default port :8444
xkey device relay --listen :9443     # Custom port
xkey device relay --qr              # Start + show QR code
```

## Wire Protocol

```
1. TCP connection established
2. Noise XX handshake:
   msg1: initiator sends (e)
   msg2: responder sends (e, ee, s, es)
   msg3: initiator sends (s, se)
3. Application data: encrypted JSON-RPC over length-prefixed frames
```

All application data after step 2 is encrypted with the negotiated Noise session keys.

## Use Cases

- **Wi-Fi/LAN pairing** between devices on the same network.
- **Remote agent enrollment** over the internet.
- **Docker E2E testing** with Go-to-MockPhone or Go-to-Android-emulator scenarios.

## Package

`xkey/pkg/phone/tcp_server.go`
