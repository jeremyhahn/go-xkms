# ACME API Reference

Complete HTTP API reference for the ACME server, compliant with RFC 8555.

## Overview

All ACME requests (except `/directory` and `/new-nonce`) must be signed using JSON Web Signature (JWS) with a Flattened JSON Serialization. Responses use standard HTTP status codes with ACME-specific error types.

## Common Headers

### Request Headers

| Header | Required | Description |
|--------|----------|-------------|
| `Content-Type` | Yes | `application/jose+json` for JWS requests |
| `Accept` | No | `application/json` |

### Response Headers

| Header | Description |
|--------|-------------|
| `Content-Type` | `application/json` or `application/pem-certificate-chain` |
| `Replay-Nonce` | Fresh nonce for subsequent requests |
| `Location` | URL of created resource |
| `Link` | Related resources (e.g., up, index) |
| `Retry-After` | Seconds to wait before retrying (polling) |

## JWS Request Format

All requests must be signed JWS with flattened serialization:

```json
{
  "protected": "<base64url-encoded protected header>",
  "payload": "<base64url-encoded payload>",
  "signature": "<base64url-encoded signature>"
}
```

### Protected Header Fields

| Field | Description | Required |
|-------|-------------|----------|
| `alg` | Signature algorithm (RS256, ES256, etc.) | Yes |
| `jwk` | JSON Web Key (for newAccount only) | Conditional |
| `kid` | Key ID (account URL) | Conditional |
| `nonce` | Anti-replay nonce | Yes |
| `url` | Request URL | Yes |

Either `jwk` or `kid` must be present, but not both.

## Error Responses

ACME errors follow RFC 8555 problem document format:

```json
{
  "type": "urn:ietf:params:acme:error:malformed",
  "detail": "Invalid JSON payload",
  "status": 400
}
```

### Error Types

| Type | Status | Description |
|------|--------|-------------|
| `accountDoesNotExist` | 400 | Account not found |
| `alreadyRevoked` | 400 | Certificate already revoked |
| `badCSR` | 400 | Invalid CSR |
| `badNonce` | 400 | Invalid or expired nonce |
| `badPublicKey` | 400 | Invalid public key |
| `badRevocationReason` | 400 | Invalid revocation reason |
| `badSignatureAlgorithm` | 400 | Unsupported signature algorithm |
| `caa` | 403 | CAA record forbids issuance |
| `compound` | 400 | Multiple errors |
| `connection` | 400 | Connection error during validation |
| `dns` | 400 | DNS resolution error |
| `externalAccountRequired` | 403 | EAB required but not provided |
| `incorrectResponse` | 403 | Challenge response incorrect |
| `invalidContact` | 400 | Invalid contact URL |
| `malformed` | 400 | Malformed request |
| `orderNotReady` | 403 | Order not ready for finalization |
| `rateLimited` | 429 | Rate limit exceeded |
| `rejectedIdentifier` | 400 | Server rejected identifier |
| `serverInternal` | 500 | Internal server error |
| `tls` | 400 | TLS error during validation |
| `unauthorized` | 403 | Unauthorized action |
| `unsupportedContact` | 400 | Unsupported contact scheme |
| `unsupportedIdentifier` | 400 | Unsupported identifier type |
| `userActionRequired` | 403 | User action required |

---

## Endpoints

### GET /acme/directory

Returns the ACME directory with available endpoints.

**RFC Reference:** Section 7.1.1

**Request:**

```http
GET /acme/directory HTTP/1.1
Host: acme.example.com
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "newNonce": "https://acme.example.com/acme/new-nonce",
  "newAccount": "https://acme.example.com/acme/new-account",
  "newOrder": "https://acme.example.com/acme/new-order",
  "revokeCert": "https://acme.example.com/acme/revoke-cert",
  "keyChange": "https://acme.example.com/acme/key-change",
  "meta": {
    "termsOfService": "https://example.com/terms",
    "website": "https://acme.example.com",
    "caaIdentities": ["acme.example.com"],
    "externalAccountRequired": false
  }
}
```

---

### HEAD/GET /acme/new-nonce

Obtains a fresh anti-replay nonce.

**RFC Reference:** Section 7.2

**Request:**

```http
HEAD /acme/new-nonce HTTP/1.1
Host: acme.example.com
```

**Response:**

```http
HTTP/1.1 200 OK
Replay-Nonce: oFvnlFP1wIhRlYS2jTaXbA
Cache-Control: no-store
```

---

### POST /acme/new-account

Creates a new ACME account or retrieves an existing one.

**RFC Reference:** Section 7.3

**Request (new account):**

```http
POST /acme/new-account HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({
    \"alg\": \"ES256\",
    \"jwk\": {\"kty\":\"EC\",\"crv\":\"P-256\",...},
    \"nonce\": \"oFvnlFP1wIhRlYS2jTaXbA\",
    \"url\": \"https://acme.example.com/acme/new-account\"
  })>",
  "payload": "<base64url({
    \"termsOfServiceAgreed\": true,
    \"contact\": [\"mailto:admin@example.com\"]
  })>",
  "signature": "<base64url(signature)>"
}
```

**Payload Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `contact` | []string | Contact URLs (mailto:) |
| `termsOfServiceAgreed` | bool | Accept terms of service |
| `onlyReturnExisting` | bool | Only return if account exists |
| `externalAccountBinding` | object | EAB JWS (if required) |

**Response (201 Created):**

```http
HTTP/1.1 201 Created
Location: https://acme.example.com/acme/account/12345
Replay-Nonce: IXVHDyxIRGcTE0VSblhPzw
Content-Type: application/json

{
  "status": "valid",
  "contact": ["mailto:admin@example.com"],
  "orders": "https://acme.example.com/acme/account/12345/orders"
}
```

**Response (200 OK - existing account with onlyReturnExisting):**

```http
HTTP/1.1 200 OK
Location: https://acme.example.com/acme/account/12345
...
```

### External Account Binding

When `externalAccountRequired` is true in the directory meta, include EAB:

```json
{
  "termsOfServiceAgreed": true,
  "contact": ["mailto:admin@example.com"],
  "externalAccountBinding": {
    "protected": "<base64url({
      \"alg\": \"HS256\",
      \"kid\": \"EAB-KEY-ID\",
      \"url\": \"https://acme.example.com/acme/new-account\"
    })>",
    "payload": "<base64url(account JWK)>",
    "signature": "<base64url(HMAC signature)>"
  }
}
```

---

### POST /acme/new-order

Creates a new certificate order.

**RFC Reference:** Section 7.4

**Request:**

```http
POST /acme/new-order HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({
    \"alg\": \"ES256\",
    \"kid\": \"https://acme.example.com/acme/account/12345\",
    \"nonce\": \"IXVHDyxIRGcTE0VSblhPzw\",
    \"url\": \"https://acme.example.com/acme/new-order\"
  })>",
  "payload": "<base64url({
    \"identifiers\": [
      {\"type\": \"dns\", \"value\": \"example.com\"},
      {\"type\": \"dns\", \"value\": \"www.example.com\"}
    ],
    \"notBefore\": \"2024-01-01T00:00:00Z\",
    \"notAfter\": \"2024-12-31T23:59:59Z\"
  })>",
  "signature": "<base64url(signature)>"
}
```

**Payload Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `identifiers` | []Identifier | Yes | Identifiers to include in certificate |
| `notBefore` | string | No | Requested validity start (RFC 3339) |
| `notAfter` | string | No | Requested validity end (RFC 3339) |

**Identifier Types:**

| Type | Description | Example |
|------|-------------|---------|
| `dns` | Domain name | `example.com`, `*.example.com` |
| `ip` | IP address | `192.168.1.1` |
| `permanent-identifier` | Device identifier | Base64-encoded public key |

**Response:**

```http
HTTP/1.1 201 Created
Location: https://acme.example.com/acme/order/67890
Replay-Nonce: Cf8dLfP1wIhRlYS2jTaXbA
Content-Type: application/json

{
  "status": "pending",
  "expires": "2024-01-08T12:00:00Z",
  "identifiers": [
    {"type": "dns", "value": "example.com"},
    {"type": "dns", "value": "www.example.com"}
  ],
  "authorizations": [
    "https://acme.example.com/acme/authz/11111",
    "https://acme.example.com/acme/authz/22222"
  ],
  "finalize": "https://acme.example.com/acme/order/67890/finalize"
}
```

---

### POST /acme/authz/{id}

Retrieves authorization details and available challenges.

**RFC Reference:** Section 7.5

**Request:**

```http
POST /acme/authz/11111 HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "",
  "signature": "<base64url(signature)>"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "pending",
  "expires": "2024-01-08T12:00:00Z",
  "identifier": {
    "type": "dns",
    "value": "example.com"
  },
  "challenges": [
    {
      "type": "http-01",
      "url": "https://acme.example.com/acme/challenge/111",
      "status": "pending",
      "token": "DGyRejmCefe7v4NfDGDKfA"
    },
    {
      "type": "dns-01",
      "url": "https://acme.example.com/acme/challenge/222",
      "status": "pending",
      "token": "DGyRejmCefe7v4NfDGDKfA"
    }
  ]
}
```

**Challenge Object Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `type` | string | Challenge type (http-01, dns-01, etc.) |
| `url` | string | Challenge URL |
| `status` | string | pending, processing, valid, invalid |
| `token` | string | Challenge token |
| `validated` | string | Validation timestamp (if valid) |
| `error` | object | Error details (if invalid) |

---

### POST /acme/challenge/{id}

Responds to a challenge to initiate validation.

**RFC Reference:** Section 7.5.1

**Request:**

```http
POST /acme/challenge/111 HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "<base64url({})>",
  "signature": "<base64url(signature)>"
}
```

The payload is an empty JSON object `{}` for standard challenges.

**Response (processing):**

```http
HTTP/1.1 200 OK
Link: <https://acme.example.com/acme/authz/11111>;rel="up"
Replay-Nonce: aXV4Y5Z6aa7b8c9d0e1f2g
Content-Type: application/json

{
  "type": "http-01",
  "url": "https://acme.example.com/acme/challenge/111",
  "status": "processing",
  "token": "DGyRejmCefe7v4NfDGDKfA"
}
```

**Response (valid):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "type": "http-01",
  "url": "https://acme.example.com/acme/challenge/111",
  "status": "valid",
  "token": "DGyRejmCefe7v4NfDGDKfA",
  "validated": "2024-01-01T12:05:00Z"
}
```

---

### POST /acme/order/{id}

Retrieves order status.

**RFC Reference:** Section 7.4

**Request:**

```http
POST /acme/order/67890 HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "",
  "signature": "<base64url(signature)>"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "ready",
  "expires": "2024-01-08T12:00:00Z",
  "identifiers": [
    {"type": "dns", "value": "example.com"}
  ],
  "authorizations": [
    "https://acme.example.com/acme/authz/11111"
  ],
  "finalize": "https://acme.example.com/acme/order/67890/finalize"
}
```

**Order Status Values:**

| Status | Description |
|--------|-------------|
| `pending` | Waiting for challenge completion |
| `ready` | All authorizations valid, ready to finalize |
| `processing` | Certificate being issued |
| `valid` | Certificate issued |
| `invalid` | Order failed |

---

### POST /acme/order/{id}/finalize

Finalizes the order with a CSR to obtain a certificate.

**RFC Reference:** Section 7.4

**Request:**

```http
POST /acme/order/67890/finalize HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "<base64url({
    \"csr\": \"MIIBkDCC...\"
  })>",
  "signature": "<base64url(signature)>"
}
```

**Payload Fields:**

| Field | Type | Description |
|-------|------|-------------|
| `csr` | string | Base64url-encoded DER CSR |

**CSR Requirements:**

- Must contain identifiers matching the order
- Subject CN should match one of the identifiers
- SANs should include all identifiers
- Key algorithm must be acceptable to CA

**Response (processing):**

```http
HTTP/1.1 200 OK
Location: https://acme.example.com/acme/order/67890
Retry-After: 5
Content-Type: application/json

{
  "status": "processing",
  "expires": "2024-01-08T12:00:00Z",
  "identifiers": [
    {"type": "dns", "value": "example.com"}
  ],
  "authorizations": [
    "https://acme.example.com/acme/authz/11111"
  ],
  "finalize": "https://acme.example.com/acme/order/67890/finalize"
}
```

**Response (valid):**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "valid",
  "expires": "2024-01-08T12:00:00Z",
  "identifiers": [
    {"type": "dns", "value": "example.com"}
  ],
  "authorizations": [
    "https://acme.example.com/acme/authz/11111"
  ],
  "finalize": "https://acme.example.com/acme/order/67890/finalize",
  "certificate": "https://acme.example.com/acme/cert/98765"
}
```

### TCG-CSR-IDevID (enroll-01)

For enroll-01 challenges, the CSR can be a packed TCG-CSR-IDevID:

```json
{
  "csr": "<base64url-encoded packed TCG-CSR-IDevID>"
}
```

The response includes both IAK and IDevID certificates concatenated in PEM format.

---

### POST /acme/cert/{id}

Downloads the issued certificate.

**RFC Reference:** Section 7.4.2

**Request:**

```http
POST /acme/cert/98765 HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json
Accept: application/pem-certificate-chain

{
  "protected": "<base64url({...})>",
  "payload": "",
  "signature": "<base64url(signature)>"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/pem-certificate-chain
Link: <https://acme.example.com/acme/cert/98765/1>;rel="alternate"

-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0GCSqGSIb3Qw0LKoZIhvcNAQEF
...
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDejCCAmKgAwIBAgICEAAwDQYJKoZIhvcNAQELBQAwRTELMAkGA1UEBhMC
...
-----END CERTIFICATE-----
```

The response contains the full certificate chain in PEM format:
1. End-entity certificate
2. Intermediate CA certificate(s)
3. Root CA certificate (optional)

---

### POST /acme/revoke-cert

Revokes a certificate.

**RFC Reference:** Section 7.6

**Request:**

```http
POST /acme/revoke-cert HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "<base64url({
    \"certificate\": \"MIIDXTCCAkWgAwIBAgIJAJC1HiIAZAiUMA0...\",
    \"reason\": 1
  })>",
  "signature": "<base64url(signature)>"
}
```

**Payload Fields:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `certificate` | string | Yes | Base64url-encoded DER certificate |
| `reason` | int | No | CRL reason code |

**Revocation Reason Codes:**

| Code | Reason |
|------|--------|
| 0 | Unspecified |
| 1 | Key compromise |
| 2 | CA compromise |
| 3 | Affiliation changed |
| 4 | Superseded |
| 5 | Cessation of operation |
| 6 | Certificate hold |
| 9 | Privilege withdrawn |
| 10 | AA compromise |

**Response:**

```http
HTTP/1.1 200 OK
```

---

### POST /acme/key-change

Rotates the account key.

**RFC Reference:** Section 7.3.5

**Request:**

```http
POST /acme/key-change HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({
    \"alg\": \"ES256\",
    \"kid\": \"https://acme.example.com/acme/account/12345\",
    \"nonce\": \"...\",
    \"url\": \"https://acme.example.com/acme/key-change\"
  })>",
  "payload": "<base64url(inner JWS)>",
  "signature": "<base64url(signature with OLD key)>"
}
```

**Inner JWS (signed with NEW key):**

```json
{
  "protected": "<base64url({
    \"alg\": \"ES256\",
    \"jwk\": {\"kty\":\"EC\",...new key...},
    \"url\": \"https://acme.example.com/acme/key-change\"
  })>",
  "payload": "<base64url({
    \"account\": \"https://acme.example.com/acme/account/12345\",
    \"oldKey\": {\"kty\":\"EC\",...old key...}
  })>",
  "signature": "<base64url(signature with NEW key)>"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json

{
  "status": "valid",
  "contact": ["mailto:admin@example.com"],
  "orders": "https://acme.example.com/acme/account/12345/orders"
}
```

---

### POST /acme/account/{id}/orders

Lists orders for an account.

**RFC Reference:** Section 7.1.2.1

**Request:**

```http
POST /acme/account/12345/orders HTTP/1.1
Host: acme.example.com
Content-Type: application/jose+json

{
  "protected": "<base64url({...})>",
  "payload": "",
  "signature": "<base64url(signature)>"
}
```

**Response:**

```http
HTTP/1.1 200 OK
Content-Type: application/json
Link: <https://acme.example.com/acme/account/12345/orders?cursor=abc>;rel="next"

{
  "orders": [
    "https://acme.example.com/acme/order/67890",
    "https://acme.example.com/acme/order/67891",
    "https://acme.example.com/acme/order/67892"
  ]
}
```

---

## Endorse-01 Specific Endpoints

### POST /acme/endorse-eab

Creates an External Account Binding credential for endorse-01 challenges.

**Request:**

```http
POST /acme/endorse-eab HTTP/1.1
Host: acme.example.com
Authorization: Bearer <admin-token>
Content-Type: application/json

{
  "externalAccountId": "device-001",
  "metadata": {
    "ek_pubkey_hash": "sha256:abc123...",
    "device_serial": "SN12345"
  },
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

**Response:**

```http
HTTP/1.1 201 Created
Content-Type: application/json

{
  "id": "eab-key-id-12345",
  "macKey": "base64url-encoded-hmac-key",
  "externalAccountId": "device-001",
  "expiresAt": "2024-12-31T23:59:59Z"
}
```

---

## Challenge-Specific Payloads

### http-01 Challenge Response

```json
{}
```

Empty payload. Client should have HTTP server ready at:
```
http://{domain}/.well-known/acme-challenge/{token}
```

### dns-01 Challenge Response

```json
{}
```

Empty payload. Client should have DNS TXT record at:
```
_acme-challenge.{domain}  TXT  {base64url(SHA256(keyAuth))}
```

### device-attest-01 Challenge Response

```json
{}
```

Empty payload. Client should have HTTP server ready with attestation object.

### enroll-01 Challenge Response

```json
{}
```

Empty payload. Client should have HTTP server ready with:
- GET `/.well-known/acme-challenge/{token}` - Returns TCG-CSR-IDevID
- POST `/.well-known/acme-activation/{token}` - Accepts credential activation

### endorse-01 Challenge Response

```json
{}
```

Empty payload. Challenge auto-validates (authorization via EAB).

---

## Rate Limits

| Endpoint | Limit |
|----------|-------|
| `/new-account` | 10/hour per IP |
| `/new-order` | 300/hour per account |
| `/finalize` | 300/hour per account |
| All endpoints | 20/second per account |

Rate limit exceeded response:

```http
HTTP/1.1 429 Too Many Requests
Retry-After: 3600
Content-Type: application/problem+json

{
  "type": "urn:ietf:params:acme:error:rateLimited",
  "detail": "Rate limit exceeded. Try again in 3600 seconds.",
  "status": 429
}
```

---

## Polling and Retry

For processing operations, use `Retry-After` header:

```http
HTTP/1.1 200 OK
Retry-After: 5
Content-Type: application/json

{
  "status": "processing"
}
```

Recommended polling strategy:
1. Initial delay: value from `Retry-After` header
2. Exponential backoff: double delay on each retry
3. Maximum delay: 60 seconds
4. Maximum retries: 30 attempts

---

## See Also

- [README](README.md) - Module overview
- [Architecture](architecture.md) - System architecture
- [Configuration](../acme-issuance/engineering.md) - Server configuration (`acme/configuration.md` was deleted by go-xkms#942)
- [Challenges](challenges.md) - Challenge type details
- [RFC 8555](https://tools.ietf.org/html/rfc8555) - ACME Protocol Specification
