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

#### Hardware-Capability Key Operations

These five operations delegate to the service layer and are available on every
transport (REST, gRPC, QUIC, MCP, Unix socket, embedded). A backend that lacks
the required capability reports the transport's "unimplemented" status
(HTTP 501 / gRPC `Unimplemented` / JSON-RPC `-32601`) rather than an error.

| Operation | REST route | Permission |
|-----------|-----------|------------|
| AttestKey | `POST /api/v1/attest` | `keys:get` |
| DeriveKeyECDH | `POST /api/v1/keys/derive-ecdh` | `keys:derive` |
| ExportKeyMaterial | `POST /api/v1/keys/{id}/export-material?backend=` | `keys:export` |
| WrapKeyByID | `POST /api/v1/keys/wrap-by-id` | `keys:wrap` |
| UnwrapKeyByID | `POST /api/v1/keys/unwrap-by-id` | `keys:unwrap` |

##### POST /api/v1/attest

Produce a cryptographic attestation proving a key was created in hardware
(TPM 2.0, PKCS#11 HSM) and never left the secure boundary. Requires a backend
whose key provider implements attestation; software and most cloud KMS
backends return 501.

**Request:**
```json
{
  "backend": "tpm2",
  "key_id": "idevid",
  "nonce": "Y2hhbGxlbmdl"
}
```

**Response (200 OK):**
```json
{
  "format": "tpm2",
  "certificate_chain": ["<base64 DER>"],
  "attestation_data": "<base64>",
  "signature": "<base64>",
  "signature_algorithm": "ECDSA-SHA256",
  "nonce": "Y2hhbGxlbmdl",
  "backend": "tpm2"
}
```

##### POST /api/v1/keys/derive-ecdh

ECDH key agreement against a peer public key, with the shared secret run
through a KDF. Requires a backend supporting key agreement.

**Request:**
```json
{
  "key_id": "ecdh-key",
  "backend": "tpm2",
  "peer_public_key": "<base64 DER>",
  "kdf_algorithm": "HKDF",
  "kdf_hash": "SHA-256",
  "key_length": 32
}
```

**Response (200 OK):**
```json
{"derived_key": "<base64>"}
```

##### POST /api/v1/keys/{id}/export-material

Export raw symmetric key bytes. Takes no request body; the backend is a query
parameter.

> **SECURITY:** returns plaintext key material with no cryptographic
> protection. Only succeeds for symmetric keys created with `exportable=true`.
> A non-exportable key returns 412.

**Response (200 OK):**
```json
{
  "key_material": "<base64>",
  "key_type": "AES-256-GCM",
  "key_size": 256
}
```

`key_size` is reported in **bits**.

##### POST /api/v1/keys/wrap-by-id

Wrap a server-side target key with a server-side wrapping key (PKCS#11
`C_WrapKey`). The target key must be extractable.

**Request:**
```json
{
  "wrapping_key_id": "kek",
  "wrapping_key_backend": "pkcs11",
  "target_key_id": "dek",
  "target_key_backend": "software",
  "algorithm": "RSAES_OAEP_SHA_256"
}
```

**Response (200 OK):**
```json
{"wrapped_key": "<base64>", "algorithm": "RSAES_OAEP_SHA_256"}
```

##### POST /api/v1/keys/unwrap-by-id

Unwrap key material with a server-side unwrapping key and import the result as
a new key (PKCS#11 `C_UnwrapKey`).

**Response (200 OK):**
```json
{
  "key_id": "restored-dek",
  "backend": "pkcs11",
  "success": true,
  "message": "key unwrapped"
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

**Address:** `https://localhost:9444/mcp` (SDK client default) -- shipped
configs bind `mcp_port: 8445`, see [Quick Reference](quick-reference.md#ports)
for the port disagreement.
**Protocol:** Real Model Context Protocol, Streamable HTTP, served by the
embedded qrdb node (not a standalone xkms listener).
**Transport:** HTTPS (TLS required)

Every xkms JSON-RPC method is registered as one MCP tool, named
`xkms_<method with dots replaced by underscores>` (e.g. `xkms_generateKey`,
`xkms_listBackends`). A tool call takes one optional `params_json` string
argument carrying the method's params object verbatim (JSON-encoded); the
tool result carries the method's JSON result back as text content. Dispatch
runs through the same `pkg/api/mcp` handler (`InvokeMethod`) as before, so
the method/param/result documentation below is unchanged -- only the
envelope around it changed, from a hand-rolled JSON-RPC-over-TCP frame to a
standard `tools/call` MCP request.

### Request Format

```json
{
  "jsonrpc": "2.0",
  "method": "tools/call",
  "params": {
    "name": "xkms_method_name",
    "arguments": {
      "params_json": "{\"param1\":\"value1\"}"
    }
  },
  "id": 1
}
```

### Response Format

**Success** (tool result content is the method's JSON result, as text):
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {"type": "text", "text": "{\"key\":\"value\"}"}
    ]
  },
  "id": 1
}
```

**Error** (`isError: true`, message text carries the failure):
```json
{
  "jsonrpc": "2.0",
  "result": {
    "content": [
      {"type": "text", "text": "key not found: my-key"}
    ],
    "isError": true
  },
  "id": 1
}
```

### Methods

Each entry below shows the underlying xkms method's params/result shape,
which goes into `params_json` verbatim and comes back as the tool result's
text content.

#### xkms_health

Health check. No params.

**`params_json`:** *(omit)*

**Result:**
```json
{
  "status": "healthy",
  "version": "0.0.1-alpha"
}
```

#### xkms_listBackends

List backends. No params.

**`params_json`:** *(omit)*

**Result:**
```json
{
  "backends": [
    {
      "name": "software",
      "type": "software",
      "hardware_backed": false
    }
  ],
  "count": 1
}
```

#### xkms_generateKey

Generate key.

**`params_json`:**
```json
{
  "key_id": "my-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048
}
```

**Result:**
```json
{
  "key_id": "my-key",
  "backend": "software",
  "key_type": "rsa",
  "key_size": 2048,
  "public_key_pem": "-----BEGIN PUBLIC KEY-----...",
  "created_at": "2025-11-05T12:00:00Z"
}
```

#### xkms_sign

Sign data.

**`params_json`:**
```json
{
  "key_id": "my-key",
  "backend": "software",
  "data": "SGVsbG8gV29ybGQ=",
  "hash": "SHA256"
}
```

**Result:**
```json
{
  "signature": "MEUCIQDxYz...",
  "algorithm": "SHA256withRSA"
}
```

#### Hardware-Capability Key Operations

The five service-layer key operations are exposed as MCP tools. Params are
the same request objects the other transports accept, and results are the
same response objects.

| Tool | Underlying method | Operation |
|------|--------------------|-----------|
| `xkms_attestKey` | `xkms.attestKey` | Hardware attestation statement for a key |
| `xkms_deriveKeyECDH` | `xkms.deriveKeyECDH` | ECDH key agreement + KDF |
| `xkms_exportKeyMaterial` | `xkms.exportKeyMaterial` | Raw symmetric key bytes (plaintext) |
| `xkms_wrapKeyByID` | `xkms.wrapKeyByID` | Wrap a server-side key with a server-side KEK |
| `xkms_unwrapKeyByID` | `xkms.unwrapKeyByID` | Unwrap and import as a new key |

> `xkms_exportKey` is a **different** tool: it returns a wrapped-envelope
> export via the backend's `ExportKey`. `xkms_exportKeyMaterial` returns raw
> plaintext bytes. Do not confuse the two.

A backend lacking the requested capability surfaces the same
"method not found" failure as an `isError` tool result. Validation failures
and unresolved backends/keys surface as an `isError` "invalid params"
result; the JSON-RPC-style codes in [Error Codes](#error-codes) below
still classify the failure inside the dispatch core, they are just no
longer wire-visible as a top-level JSON-RPC `error.code`.

**`params_json`:**
```json
{"backend": "tpm2", "key_id": "idevid", "nonce": "Y2hhbGxlbmdl"}
```

**Result:**
```json
{
  "format": "tpm2",
  "certificate_chain": ["<base64 DER>"],
  "attestation_data": "<base64>",
  "signature": "<base64>",
  "signature_algorithm": "ECDSA-SHA256",
  "nonce": "Y2hhbGxlbmdl",
  "backend": "tpm2"
}
```

> **Note:** authorization for MCP tool calls is layered: qrdb's MCP
> middleware authorizes each tool call against the permissions the xkms
> module declares (`Module.MCPToolPermissions`), and the xkms-internal
> tenant + RBAC gates still run inside `InvokeMethod`. At go-qrdb
> v0.3.0-alpha, module tools are fail-closed under qrdb's auth middleware
> until qrdb exports a module tool-permission registry hook.

#### Subscriptions and notifications

`xkms.subscribe` and its connection-bound server-push notification plane
were removed along with the legacy JSON-RPC-over-TCP server -- there is no
live subscription/watch equivalent on the real MCP path today.

### Batch Requests

The legacy plane's JSON-RPC array batching is gone with it. Real MCP tool
calls are invoked one `tools/call` request at a time.

### Error Codes

The codes below are the dispatch core's internal classification
(`pkg/api/mcp/types.go`); they no longer appear as a top-level JSON-RPC
`error.code` on the wire (see [Response Format](#response-format) above),
but they still determine whether a tool call succeeds or returns
`isError: true`.

| Code | Message | Description |
|------|---------|-------------|
| -32700 | Parse error | Invalid JSON in `params_json` |
| -32601 | Method not found | Unknown method |
| -32602 | Invalid params | Invalid parameters |
| -32603 | Internal error | Server error |
| -32001 | Resource not found | Key/backend not found |
| -32002 | Resource exists | Key already exists |
| -32003 | Operation not supported | Backend limitation |


## QUIC/HTTP3 API

**Address:** `https://localhost:8443` (default) -- the same address and port
as the REST API. There is no separate QUIC server package or port; QUIC is
HTTP/3 served directly on the unified REST listener and advertised via the
`Alt-Svc` response header. `quic_port` in `server:` config is vestigial.
**Protocol:** HTTP/3 over QUIC (UDP), same listener as REST

### Overview

The QUIC/HTTP3 API shares the **exact same endpoints** as the REST API --
literally the same route table on the same listener, just reached over
HTTP/3 instead of HTTP/1.1 or HTTP/2.

**Key Differences from plain REST:**
- Transport: UDP instead of TCP
- Protocol: HTTP/3 instead of HTTP/1.1 or HTTP/2
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

resp, err := client.Get("https://localhost:8443/health")
```

**curl (with HTTP/3 support):**
```bash
curl --http3 https://localhost:8443/health
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
#   QUIC:  HTTP/3 on :8443 via Alt-Svc  (healthy)
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


**For complete implementation details, see [Host Embedding](../host-embedding/engineering.md)**
