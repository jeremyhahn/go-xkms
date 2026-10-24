# BLE Protocol Specification

> **Status: REFERENCE** · Last verified: 2026-10-13
> Fragment framing and the core JSON-RPC key methods, from `xkey/pkg/pairing`; the [ble](architecture.md) feature folder is normative.

## Message Framing

### Fragment Header (7 bytes)

`FragmentHeaderSize` and the flag constants are in `pkg/pairingproto/fragmentation.go:22-33`.

```
┌─────────┬──────────┬─────────┬──────────┐
│  Flags  │ Sequence │  Total  │  Length  │
│ 1 byte  │ 2 bytes  │ 2 bytes │ 2 bytes  │
└─────────┴──────────┴─────────┴──────────┘
```

**Flags:**
- `0x01` - First fragment
- `0x02` - Last fragment
- `0x03` - Single fragment (first + last)
- `0x00` - Middle fragment

**Sequence:** Fragment index (0-based)

**Total:** Total number of fragments

**Length:** Payload length in this fragment

### MTU Handling

Default MTU: 247 bytes (`DefaultMTU`, `xkey/pkg/phone/phone.go:66`)
Minimum MTU: 23 bytes (`MinMTU`, `pkg/pairingproto/constants.go:18`)
Max payload per fragment: MTU - 7 (header)

Large messages are split across multiple fragments and reassembled in order.

## JSON-RPC 2.0 Protocol

All messages use JSON-RPC 2.0 format over the Noise-encrypted channel.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "methodName",
  "params": { ... }
}
```

### Response Format (Success)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": { ... }
}
```

### Response Format (Error)

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "error": {
    "code": -32000,
    "message": "error description",
    "data": "optional details"
  }
}
```

## Methods

The core methods are declared in `pkg/pairingproto/protocol.go:34-40` and
their parameter and result types at `protocol.go:151-249`. Byte fields
(`credentialId`, `publicKey`, `dataHash`, `signature`) are `[]byte` and
therefore standard base64 in JSON. Further method families (attestation,
sync, PIV, OATH, backup, sharing) live in the sibling `protocol_*.go` files.

### ping

Health check / keepalive.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "ping"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": { "pong": true }
}
```

### getInfo

Get device capabilities and status.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "method": "getInfo"
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 2,
  "result": {
    "version": "1.0.0",
    "deviceName": "Pixel 8 Pro",
    "supportedAlgorithms": [-7, -35, -36],
    "maxCredentials": 100,
    "currentCredentials": 5
  }
}
```

### generateKey

Generate a new signing key pair.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "method": "generateKey",
  "params": {
    "credentialId": "base64-encoded-credential-id",
    "algorithm": -7,
    "userVerificationRequired": true
  }
}
```

**Parameters:**
- `credentialId`: Base64-encoded credential identifier
- `algorithm`: COSE algorithm identifier (`protocol.go:27-29`)
  - `-7` (ES256): ECDSA with P-256 and SHA-256
  - `-35` (ES384): ECDSA with P-384 and SHA-384
  - `-36` (ES512): ECDSA with P-521 and SHA-512
- `userVerificationRequired`: Whether the phone must verify the user

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "publicKey": "base64-encoded-cose-key"
  }
}
```

### sign

Sign data with a stored key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "method": "sign",
  "params": {
    "credentialId": "base64-encoded-credential-id",
    "dataHash": "base64-encoded-hash",
    "userVerificationRequired": true
  }
}
```

**Parameters:**
- `credentialId`: Base64-encoded credential identifier
- `dataHash`: Base64-encoded hash to sign
- `userVerificationRequired`: Whether the phone must verify the user

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "signature": "base64-encoded-signature"
  }
}
```

### deleteKey

Delete a stored key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "method": "deleteKey",
  "params": {
    "credentialId": "base64-encoded-credential-id"
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 5,
  "result": { "deleted": true }
}
```

### loadKey

Load/verify a key exists.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "method": "loadKey",
  "params": {
    "credentialId": "base64-encoded-credential-id",
    "algorithm": -7
  }
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 6,
  "result": {
    "exists": true,
    "publicKey": "base64-encoded-cose-key"
  }
}
```

`publicKey` is omitted when `exists` is false.

### pairing.confirm

Confirms a pairing. Params carry `deviceName` and `publicKeyHex`; the result
carries `confirmed` and `deviceName` (`protocol.go:242-249`).

## Error Codes

### Standard JSON-RPC Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Invalid JSON-RPC request |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal server error |

Declared at `pkg/pairingproto/protocol.go:46-50`.

### Application Errors

The key-operation codes (`protocol.go:53-60`):

| Code | Constant |
|------|----------|
| -32000 | `ErrorCodeKeyNotFound` |
| -32001 | `ErrorCodeUserCancelled` |
| -32002 | `ErrorCodeBiometricFailed` |
| -32003 | `ErrorCodeKeyExists` |
| -32004 | `ErrorCodeUnsupportedAlg` |
| -32005 | `ErrorCodeInvalidCredID` |
| -32006 | `ErrorCodeStorageFull` |
| -32007 | `ErrorCodeOperationTimeout` |

Codes -32008 through -32040 cover backend denial, attestation, ECDH/HMAC,
pairing, sharing, backup, OATH, PIV, sync and the transport message limit
(`protocol.go:62-144`).

## COSE Key Format

Public keys are returned in COSE_Key format (CBOR encoded):

### EC2 Key (P-256, P-384, P-521)

```
{
  1: 2,      // kty: EC2
  3: -7,     // alg: ES256 (or -35, -36)
  -1: 1,     // crv: P-256 (or 2, 3)
  -2: h'...', // x: X coordinate (32/48/66 bytes)
  -3: h'...'  // y: Y coordinate (32/48/66 bytes)
}
```

## Timeouts

| Operation | Timeout |
|-----------|---------|
| BLE scan | 30 seconds (`ScanTimeout`, `xkey/pkg/phone/phone.go:69`) |
| Connection | 10 seconds (`ConnectTimeout`, `phone.go:72`) |
| Operation (sign, generate) | 60 seconds (`OperationTimeout`, `phone.go:75`) |

Operations requiring biometric may take longer as they wait for user interaction.
