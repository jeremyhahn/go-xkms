# BLE Protocol Specification

## Message Framing

### Fragment Header (7 bytes)

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

Default MTU: 247 bytes
Minimum MTU: 23 bytes
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
    "algorithm": -7
  }
}
```

**Parameters:**
- `credentialId`: Base64-encoded credential identifier
- `algorithm`: COSE algorithm identifier
  - `-7` (ES256): ECDSA with P-256 and SHA-256
  - `-35` (ES384): ECDSA with P-384 and SHA-384
  - `-36` (ES512): ECDSA with P-521 and SHA-512

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 3,
  "result": {
    "publicKeyCose": "base64-encoded-cose-key"
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
    "algorithm": -7,
    "data": "base64-encoded-data-to-sign"
  }
}
```

**Parameters:**
- `credentialId`: Base64-encoded credential identifier
- `algorithm`: COSE algorithm identifier
- `data`: Base64-encoded data to sign (typically clientDataHash)

**Response:**
```json
{
  "jsonrpc": "2.0",
  "id": 4,
  "result": {
    "signature": "base64-encoded-der-signature"
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
    "publicKeyCose": "base64-encoded-cose-key"
  }
}
```

## Error Codes

### Standard JSON-RPC Errors

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid request | Invalid JSON-RPC request |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid method parameters |
| -32603 | Internal error | Internal server error |

### Application Errors

| Code | Message | Description |
|------|---------|-------------|
| -32000 | Key not found | Credential ID not in keystore |
| -32001 | User cancelled | User declined biometric |
| -32002 | Biometric failed | Biometric authentication failed |
| -32003 | Unsupported algorithm | Algorithm not supported |
| -32004 | Invalid credential ID | Malformed credential ID |
| -32005 | Operation timeout | Operation timed out |

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
| BLE scan | 30 seconds |
| Connection | 10 seconds |
| Operation (sign, generate) | 60 seconds |

Operations requiring biometric may take longer as they wait for user interaction.
