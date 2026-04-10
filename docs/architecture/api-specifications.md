# Go-xKMS API Specifications

**Comprehensive API reference for all protocols**


## Table of Contents

1. [REST API](#rest-api)
2. [gRPC API](#grpc-api)
3. [MCP (Model Context Protocol)](#mcp-model-context-protocol)
4. [QUIC/HTTP3 API](#quichttp3-api)
5. [CLI Commands](#cli-commands)
6. [Common Data Types](#common-data-types)
7. [Error Codes](#error-codes)


## REST API

**Base URL:** `http://localhost:8443` (default)
**API Version:** `v1`
**Content-Type:** `application/json`

### Authentication

All API requests (except health) require cryptographic authentication:

```http
Authorization: Bearer <jwt-token>
```

or mutual TLS with a client certificate. See [Authentication Adapter Framework](../architecture/adapter-framework.md) for all supported methods.

### Endpoints

#### Health & Metadata

##### GET /health

Health check endpoint.

**Response (200 OK):**
```json
{
  "status": "healthy",
  "version": "0.0.1-alpha",
  "uptime": "1h30m45s"
}
```

##### GET /version

Version information.

**Response (200 OK):**
```json
{
  "version": "0.0.1-alpha",
  "commit": "abc123def",
  "build_time": "2025-11-05T12:00:00Z"
}
```

##### GET /api/v1/backends

List available backends.

**Response (200 OK):**
```json
{
  "backends": [
    {
      "name": "software",
      "type": "software",
      "description": "Software backend",
      "hardware_backed": false,
      "capabilities": {
        "signing": true,
        "decryption": true,
        "key_rotation": false
      }
    },
    {
      "name": "pkcs11",
      "type": "pkcs11",
      "description": "PKCS#11 HSM backend",
      "hardware_backed": true,
      "capabilities": {
        "signing": true,
        "decryption": true,
        "key_rotation": false
      }
    }
  ],
  "count": 2
}
```

##### GET /api/v1/backends/{name}

Get backend information.

**Response (200 OK):**
```json
{
  "name": "software",
  "type": "software",
  "description": "Software backend",
  "hardware_backed": false,
  "capabilities": {
    "signing": true,
    "decryption": true,
    "key_rotation": false
  },
  "config": {
    "key_dir": "/var/lib/xkms/keys",
    "cert_dir": "/var/lib/xkms/certs"
  }
}
```

#### Key Management

##### POST /api/v1/keys

Generate a new key.

**Request Body:**
```json
{
  "key_id": "my-signing-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048,
  "curve": "",
  "tags": {
    "environment": "production",
    "purpose": "signing"
  }
}
```

**Key Types:**
- `rsa` - Requires `key_size` (2048, 3072, 4096)
- `ecdsa` - Requires `curve` (P256, P384, P521)
- `ed25519` - No additional parameters

**Response (201 Created):**
```json
{
  "key_id": "my-signing-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA...\n-----END PUBLIC KEY-----",
  "fingerprint": "SHA256:abc123...",
  "created_at": "2025-11-05T12:00:00Z",
  "tags": {
    "environment": "production",
    "purpose": "signing"
  }
}
```

##### GET /api/v1/keys

List keys.

**Query Parameters:**
- `backend` (required) - Backend name
- `limit` (optional) - Maximum results (default: 100)
- `offset` (optional) - Pagination offset (default: 0)
- `tags` (optional) - Filter by tags (format: key=value)

**Example:**
```
GET /api/v1/keys?backend=software&limit=10&tags=environment=production
```

**Response (200 OK):**
```json
{
  "keys": [
    {
      "key_id": "my-signing-key",
      "backend": "software",
      "key_type": "rsa",
      "key_size": 2048,
      "fingerprint": "SHA256:abc123...",
      "created_at": "2025-11-05T12:00:00Z",
      "last_used": "2025-11-05T13:30:00Z",
      "tags": {
        "environment": "production",
        "purpose": "signing"
      }
    }
  ],
  "count": 1,
  "total": 1,
  "limit": 10,
  "offset": 0
}
```

##### GET /api/v1/keys/{id}

Get key details.

**Query Parameters:**
- `backend` (required) - Backend name

**Example:**
```
GET /api/v1/keys/my-signing-key?backend=software
```

**Response (200 OK):**
```json
{
  "key_id": "my-signing-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
  "fingerprint": "SHA256:abc123...",
  "created_at": "2025-11-05T12:00:00Z",
  "last_used": "2025-11-05T13:30:00Z",
  "tags": {
    "environment": "production",
    "purpose": "signing"
  }
}
```

##### DELETE /api/v1/keys/{id}

Delete a key.

**Query Parameters:**
- `backend` (required) - Backend name

**Example:**
```
DELETE /api/v1/keys/my-signing-key?backend=software
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Key deleted successfully",
  "key_id": "my-signing-key",
  "backend": "software"
}
```

#### Cryptographic Operations

##### POST /api/v1/keys/{id}/sign

Sign data.

**Query Parameters:**
- `backend` (required) - Backend name

**Request Body:**
```json
{
  "data": "SGVsbG8gV29ybGQ=",  // Base64-encoded data
  "hash": "SHA256",              // SHA256, SHA384, SHA512
  "pss": false                   // Use PSS padding (RSA only)
}
```

**Response (200 OK):**
```json
{
  "signature": "MEUCIQDxYz...",  // Base64-encoded signature
  "algorithm": "SHA256withRSA",
  "key_id": "my-signing-key",
  "backend": "software",
  "timestamp": "2025-11-05T14:00:00Z"
}
```

##### POST /api/v1/keys/{id}/verify

Verify signature.

**Query Parameters:**
- `backend` (required) - Backend name

**Request Body:**
```json
{
  "data": "SGVsbG8gV29ybGQ=",
  "signature": "MEUCIQDxYz...",
  "hash": "SHA256",
  "pss": false
}
```

**Response (200 OK):**
```json
{
  "valid": true,
  "algorithm": "SHA256withRSA",
  "key_id": "my-signing-key",
  "backend": "software",
  "timestamp": "2025-11-05T14:00:00Z"
}
```

##### POST /api/v1/keys/{id}/decrypt

Decrypt data (if backend supports).

**Query Parameters:**
- `backend` (required) - Backend name

**Request Body:**
```json
{
  "ciphertext": "encrypted-data-base64",
  "algorithm": "RSA-OAEP"
}
```

**Response (200 OK):**
```json
{
  "plaintext": "decrypted-data-base64",
  "algorithm": "RSA-OAEP",
  "key_id": "my-key",
  "backend": "software"
}
```

##### POST /api/v1/keys/{id}/rotate

Rotate key (if backend supports).

**Query Parameters:**
- `backend` (required) - Backend name

**Response (200 OK):**
```json
{
  "success": true,
  "old_version": "1",
  "new_version": "2",
  "key_id": "my-key",
  "backend": "awskms"
}
```

### Error Responses

All errors follow this format:

```json
{
  "error": {
    "code": "ERROR_CODE",
    "message": "Human-readable error message",
    "details": {
      "field": "additional context"
    }
  }
}
```

**Status Codes:**
- `400` - Bad Request (invalid input)
- `401` - Unauthorized (missing/invalid credentials)
- `403` - Forbidden (insufficient permissions)
- `404` - Not Found (key/backend not found)
- `409` - Conflict (key already exists)
- `500` - Internal Server Error
- `501` - Not Implemented (operation not supported)
- `503` - Service Unavailable (backend unavailable)


## gRPC API

**Address:** `localhost:9443` (default)
**Protocol:** HTTP/2
**Transport Security:** TLS 1.2+

### Protocol Buffer Definition

```protobuf
syntax = "proto3";

package xkms.v1;

option go_package = "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1";

// KeystoreService provides key management and cryptographic operations
service KeystoreService {
  // Health & Metadata
  rpc Health(HealthRequest) returns (HealthResponse);
  rpc ListBackends(ListBackendsRequest) returns (ListBackendsResponse);
  rpc GetBackendInfo(GetBackendInfoRequest) returns (GetBackendInfoResponse);

  // Key Management
  rpc GenerateKey(GenerateKeyRequest) returns (GenerateKeyResponse);
  rpc GetKey(GetKeyRequest) returns (GetKeyResponse);
  rpc ListKeys(ListKeysRequest) returns (ListKeysResponse);
  rpc DeleteKey(DeleteKeyRequest) returns (DeleteKeyResponse);

  // Cryptographic Operations
  rpc Sign(SignRequest) returns (SignResponse);
  rpc Verify(VerifyRequest) returns (VerifyResponse);
  rpc Decrypt(DecryptRequest) returns (DecryptResponse);
  rpc RotateKey(RotateKeyRequest) returns (RotateKeyResponse);
}

// Messages
message HealthRequest {}

message HealthResponse {
  string status = 1;
  string version = 2;
  string uptime = 3;
}

message GenerateKeyRequest {
  string key_id = 1;
  string backend = 2;
  string key_type = 3;  // rsa, ecdsa, ed25519
  int32 key_size = 4;   // For RSA
  string curve = 5;     // For ECDSA
  map<string, string> tags = 6;
}

message GenerateKeyResponse {
  string key_id = 1;
  string backend = 2;
  string key_type = 3;
  int32 key_size = 4;
  string public_key_pem = 5;
  string fingerprint = 6;
  google.protobuf.Timestamp created_at = 7;
  map<string, string> tags = 8;
}

message SignRequest {
  string key_id = 1;
  string backend = 2;
  bytes data = 3;
  string hash = 4;  // SHA256, SHA384, SHA512
  bool pss = 5;     // RSA-PSS padding
}

message SignResponse {
  bytes signature = 1;
  string algorithm = 2;
}

// ... more messages
```

### Usage Example

**Go Client:**
```go
import (
    pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
    "google.golang.org/grpc"
    "google.golang.org/grpc/credentials/insecure"
)

// Create client
conn, err := grpc.Dial("localhost:9443",
    grpc.WithTransportCredentials(insecure.NewCredentials()))
if err != nil {
    log.Fatal(err)
}
defer conn.Close()

client := pb.NewKeystoreServiceClient(conn)

// Generate key
resp, err := client.GenerateKey(ctx, &pb.GenerateKeyRequest{
    KeyId:   "my-key",
    Backend: "software",
    KeyType: "rsa",
    KeySize: 2048,
})
```

**grpcurl (CLI):**
```bash
# Health check
grpcurl -plaintext localhost:9443 xkms.v1.KeystoreService/Health

# Generate key
grpcurl -plaintext -d '{
  "key_id": "my-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048
}' localhost:9443 xkms.v1.KeystoreService/GenerateKey
```

### gRPC Error Codes

| gRPC Code | HTTP Equiv | Description |
|-----------|------------|-------------|
| OK | 200 | Success |
| INVALID_ARGUMENT | 400 | Invalid input |
| UNAUTHENTICATED | 401 | Missing or invalid authentication |
| PERMISSION_DENIED | 403 | Insufficient permissions |
| NOT_FOUND | 404 | Resource not found |
| ALREADY_EXISTS | 409 | Resource exists |
| UNIMPLEMENTED | 501 | Not supported |
| UNAVAILABLE | 503 | Service unavailable |


## MCP (Model Context Protocol)

**Address:** `localhost:9444` (default)
**Protocol:** JSON-RPC 2.0 over TCP
**Transport:** Newline-delimited JSON

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "method.name",
  "params": {
    "param1": "value1"
  },
  "id": 1
}
```

### Response Format

**Success:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "key": "value"
  },
  "id": 1
}
```

**Error:**
```json
{
  "jsonrpc": "2.0",
  "error": {
    "code": -32001,
    "message": "Error message",
    "data": {
      "details": "Additional info"
    }
  },
  "id": 1
}
```

### Methods

#### health

Health check.

**Request:**
```json
{"jsonrpc": "2.0", "method": "health", "id": 1}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "status": "healthy",
    "version": "0.0.1-alpha"
  },
  "id": 1
}
```

#### xkms.listBackends

List backends.

**Request:**
```json
{"jsonrpc": "2.0", "method": "xkms.listBackends", "id": 2}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "backends": [
      {
        "name": "software",
        "type": "software",
        "hardware_backed": false
      }
    ],
    "count": 1
  },
  "id": 2
}
```

#### xkms.generateKey

Generate key.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "xkms.generateKey",
  "params": {
    "key_id": "my-key",
    "backend": "software",
    "key_type": "rsa",
    "key_size": 2048
  },
  "id": 3
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "key_id": "my-key",
    "backend": "software",
    "key_type": "rsa",
    "key_size": 2048,
    "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
    "created_at": "2025-11-05T12:00:00Z"
  },
  "id": 3
}
```

#### xkms.sign

Sign data.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "xkms.sign",
  "params": {
    "key_id": "my-key",
    "backend": "software",
    "data": "SGVsbG8gV29ybGQ=",
    "hash": "SHA256"
  },
  "id": 4
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "signature": "MEUCIQDxYz...",
    "algorithm": "SHA256withRSA"
  },
  "id": 4
}
```

#### xkms.subscribe

Subscribe to events.

**Request:**
```json
{
  "jsonrpc": "2.0",
  "method": "xkms.subscribe",
  "params": {
    "events": ["key.created", "key.deleted", "key.rotated"]
  },
  "id": 5
}
```

**Response:**
```json
{
  "jsonrpc": "2.0",
  "result": {
    "subscription_id": "sub-123",
    "events": ["key.created", "key.deleted", "key.rotated"]
  },
  "id": 5
}
```

### Notifications (Server → Client)

After subscribing, server sends notifications:

```json
{
  "jsonrpc": "2.0",
  "method": "key.created",
  "params": {
    "key_id": "new-key",
    "backend": "software",
    "timestamp": "2025-11-05T12:00:00Z"
  }
}
```

### Batch Requests

Multiple requests in one call:

**Request:**
```json
[
  {"jsonrpc": "2.0", "method": "health", "id": 1},
  {"jsonrpc": "2.0", "method": "xkms.listBackends", "id": 2}
]
```

**Response:**
```json
[
  {
    "jsonrpc": "2.0",
    "result": {"status": "healthy"},
    "id": 1
  },
  {
    "jsonrpc": "2.0",
    "result": {"backends": [...], "count": 1},
    "id": 2
  }
]
```

### Error Codes

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON |
| -32600 | Invalid Request | Invalid JSON-RPC |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| -32603 | Internal error | Server error |
| -32001 | Resource not found | Key/backend not found |
| -32002 | Resource exists | Key already exists |
| -32003 | Operation not supported | Backend limitation |


## QUIC/HTTP3 API

**Address:** `https://localhost:8444` (default)
**Protocol:** HTTP/3 over QUIC (UDP)

### Overview

The QUIC/HTTP3 API shares the **exact same endpoints** as the REST API, but uses HTTP/3 transport.

**Key Differences:**
- Transport: UDP instead of TCP
- Protocol: HTTP/3 instead of HTTP/2
- Lower latency
- Better packet loss handling
- Requires TLS 1.3

### Usage

**Go Client:**
```go
import (
    "github.com/quic-go/quic-go/http3"
    "crypto/tls"
)

client := &http.Client{
    Transport: &http3.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // Development only!
        },
    },
}

resp, err := client.Get("https://localhost:8444/health")
```

**curl (with HTTP/3 support):**
```bash
curl --http3 https://localhost:8444/health
```

### All REST API endpoints work identically

See [REST API](#rest-api) section for complete endpoint documentation.


## CLI Commands

**Binary:** `xkmsctl`

### Global Flags

```bash
--config string       Config file path
--server string       Server URL (for remote mode)
--output string       Output format: json, yaml, table (default: table)
--log-level string    Log level: debug, info, warn, error
--no-color           Disable colored output
```

### Commands

#### version

Show version information.

```bash
xkmsctl version

# Output:
# xkmsctl version 0.0.1-alpha
# commit: abc123def
# built: 2025-11-05T12:00:00Z
```

#### backends list

List available backends.

```bash
xkmsctl backends list

# Output (table):
# NAME      TYPE      HARDWARE  SIGNING  DECRYPTION
# software  software  false     true     true
# tpm2      tpm2      true      true     false
# pkcs11    pkcs11    true      true     true

# JSON output:
xkmsctl backends list --output json
```

#### backends info

Get backend details.

```bash
xkmsctl backends info software

# Output:
# Name:           software
# Type:           software
# Description:    Software backend
# Hardware:       false
# Capabilities:
#   - Signing:      true
#   - Decryption:   true
#   - Key Rotation: false
```

#### key generate

Generate a new key.

```bash
# RSA key
xkmsctl key generate my-rsa-key \
  --backend software \
  --key-type rsa \
  --key-size 2048

# ECDSA key
xkmsctl key generate my-ecdsa-key \
  --backend software \
  --key-type ecdsa \
  --curve P256

# Ed25519 key
xkmsctl key generate my-ed25519-key \
  --backend software \
  --key-type ed25519

# With tags
xkmsctl key generate my-key \
  --backend software \
  --key-type rsa \
  --key-size 2048 \
  --tag environment=production \
  --tag purpose=signing

# Output:
# Key generated successfully
# ID:          my-rsa-key
# Type:        rsa
# Size:        2048
# Backend:     software
# Fingerprint: SHA256:abc123...
# Created:     2025-11-05 12:00:00
```

#### key list

List keys.

```bash
xkmsctl key list --backend software

# With filters
xkmsctl key list --backend software --tag environment=production

# Output (table):
# ID             TYPE    SIZE  BACKEND   CREATED
# my-rsa-key     rsa     2048  software  2025-11-05 12:00:00
# my-ecdsa-key   ecdsa   256   software  2025-11-05 12:05:00
```

#### key get

Get key details.

```bash
xkmsctl key get my-rsa-key --backend software

# With public key export
xkmsctl key get my-rsa-key --backend software --export-public > public.pem

# Output:
# ID:          my-rsa-key
# Type:        rsa
# Size:        2048
# Backend:     software
# Fingerprint: SHA256:abc123...
# Created:     2025-11-05 12:00:00
# Last Used:   2025-11-05 13:30:00
# Tags:
#   environment: production
#   purpose:     signing
```

#### key delete

Delete a key.

```bash
xkmsctl key delete my-rsa-key --backend software

# With confirmation
xkmsctl key delete my-rsa-key --backend software --confirm

# Output:
# Key deleted successfully
# ID:      my-rsa-key
# Backend: software
```

#### key sign

Sign data.

```bash
# Sign string
xkmsctl key sign my-rsa-key "Hello World" \
  --backend software \
  --hash SHA256

# Sign file
xkmsctl key sign my-rsa-key --file data.txt \
  --backend software \
  --hash SHA256 \
  --output signature.sig

# Output:
# Signature: MEUCIQDxYz...
# Algorithm: SHA256withRSA
# Signed:    2025-11-05 14:00:00
```

#### key verify

Verify signature.

```bash
# Verify with inline signature
xkmsctl key verify my-rsa-key "Hello World" \
  --signature "MEUCIQDxYz..." \
  --backend software \
  --hash SHA256

# Verify with file
xkmsctl key verify my-rsa-key --file data.txt \
  --signature-file signature.sig \
  --backend software \
  --hash SHA256

# Output:
# Signature valid: true
# Algorithm:       SHA256withRSA
# Verified:        2025-11-05 14:01:00
```

#### key rotate

Rotate key (if supported).

```bash
xkmsctl key rotate my-aws-key --backend awskms

# Output:
# Key rotated successfully
# ID:          my-aws-key
# Old Version: 1
# New Version: 2
# Backend:     awskms
```

#### server start

Start server (all protocols).

```bash
xkmsd --config /etc/xkms/config.yaml

# Or with inline config
xkmsd \
  --rest-address :8443 \
  --grpc-address :9443 \
  --mcp-address :9444 \
  --log-level info
```

#### server status

Check server status.

```bash
xkmsctl server status --server http://localhost:8443

# Output:
# Status:  healthy
# Version: 0.0.1-alpha
# Uptime:  2h15m30s
# Protocols:
#   REST:  :8443  (healthy)
#   gRPC:  :9443  (healthy)
#   MCP:   :9444  (healthy)
#   QUIC:  :8444  (healthy)
```


## Common Data Types

### KeyInfo

```json
{
  "key_id": "string",
  "backend": "string",
  "key_type": "rsa|ecdsa|ed25519",
  "key_size": 0,
  "curve": "string",
  "public_key_pem": "string",
  "fingerprint": "string",
  "created_at": "2025-11-05T12:00:00Z",
  "last_used": "2025-11-05T13:30:00Z",
  "tags": {
    "key": "value"
  }
}
```

### BackendInfo

```json
{
  "name": "string",
  "type": "string",
  "description": "string",
  "hardware_backed": false,
  "capabilities": {
    "signing": true,
    "decryption": true,
    "key_rotation": false
  }
}
```

### SignOptions

```json
{
  "hash": "SHA256|SHA384|SHA512",
  "pss": false
}
```


## Error Codes

### REST/HTTP Status Codes

| Code | Name | Description |
|------|------|-------------|
| 200 | OK | Success |
| 201 | Created | Resource created |
| 400 | Bad Request | Invalid input |
| 401 | Unauthorized | Authentication required |
| 403 | Forbidden | Insufficient permissions |
| 404 | Not Found | Resource not found |
| 409 | Conflict | Resource already exists |
| 500 | Internal Server Error | Server error |
| 501 | Not Implemented | Operation not supported |
| 503 | Service Unavailable | Backend unavailable |

### Application Error Codes

| Code | Description |
|------|-------------|
| INVALID_KEY_ID | Invalid key identifier |
| INVALID_KEY_TYPE | Invalid key type |
| INVALID_KEY_SIZE | Invalid key size |
| INVALID_CURVE | Invalid elliptic curve |
| INVALID_HASH | Invalid hash algorithm |
| KEY_NOT_FOUND | Key not found |
| KEY_ALREADY_EXISTS | Key already exists |
| BACKEND_NOT_FOUND | Backend not found |
| BACKEND_UNAVAILABLE | Backend unavailable |
| OPERATION_NOT_SUPPORTED | Operation not supported by backend |
| SIGNATURE_INVALID | Signature verification failed |
| DECRYPTION_FAILED | Decryption failed |
| ROTATION_NOT_SUPPORTED | Key rotation not supported |


## Rate Limits

Default rate limits (per client):

| Operation | Limit |
|-----------|-------|
| Key Generation | 10/minute |
| Signing | 100/minute |
| Verification | 100/minute |
| List Operations | 50/minute |
| Health Checks | No limit |

Rate limit headers in responses:

```
X-RateLimit-Limit: 100
X-RateLimit-Remaining: 95
X-RateLimit-Reset: 1699200000
```


## Examples

### Complete Workflow

```bash
# 1. Start server
xkmsd --config config.yaml

# 2. List backends
xkmsctl backends list

# 3. Generate key
xkmsctl key generate my-key \
  --backend software \
  --key-type rsa \
  --key-size 2048

# 4. Sign data
echo "Hello World" | xkmsctl key sign my-key - \
  --backend software \
  --hash SHA256 > signature.sig

# 5. Verify signature
echo "Hello World" | xkmsctl key verify my-key - \
  --signature-file signature.sig \
  --backend software \
  --hash SHA256

# 6. List keys
xkmsctl key list --backend software

# 7. Delete key
xkmsctl key delete my-key --backend software
```


**For complete implementation details, see [Server Architecture](./server-architecture.md)**
