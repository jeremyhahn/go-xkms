# Barrier API Reference

All barrier endpoints are under `/api/v1/barrier`. Shamir operations are only available via REST. gRPC, QUIC, and MCP protocols do not currently expose barrier/Shamir endpoints.

## Core Barrier Operations

### POST /api/v1/barrier/initialize

Initialize the barrier with a password-based credential. Generates a root key, seals it with the best available strategy, and transitions to unsealed.

**Request:**
```json
{ "secret": "my-secure-passphrase" }
```

**Response (200):**
```json
{ "success": true, "message": "barrier initialized" }
```

**Errors:** `ErrAlreadyInitialized` (409), `ErrNoAvailableStrategy` (500)

---

### POST /api/v1/barrier/unseal

Unseal the barrier with a password credential.

**Request:**
```json
{ "secret": "my-secure-passphrase" }
```

**Response (200):**
```json
{ "success": true, "message": "barrier unsealed" }
```

**Errors:** `ErrNotInitialized` (400), `ErrAlreadyUnsealed` (409), `ErrInvalidCredentials` (401)

---

### POST /api/v1/barrier/seal

Seal the barrier. Zeros the DEK. Idempotent.

**Request:** Empty body.

**Response (200):**
```json
{ "success": true, "message": "barrier sealed" }
```

---

### GET /api/v1/barrier/status

Returns the current barrier state.

**Response (200):**
```json
{ "sealed": true, "strategy": "software" }
```

## Shamir Initialization and Unsealing

### POST /api/v1/barrier/initialize-shamir

Initialize the barrier with Shamir secret sharing. In direct mode (`StrategyShamir` registered), no secret is needed. In credential mode, the secret is split into shares.

**Request:**
```json
{ "secret": "" }
```

The `secret` field is optional for direct mode and required for credential mode.

**Response (200):**
```json
{
  "shares": ["base64share1", "base64share2", "base64share3", "base64share4", "base64share5"],
  "threshold": 3,
  "total_shares": 5
}
```

Distribute the returned shares to key holders. The barrier transitions to unsealed.

**Errors:** `ErrShamirNotConfigured` (400), `ErrShamirThresholdInvalid` (400), `ErrAlreadyInitialized` (409)

---

### POST /api/v1/barrier/unseal-share

Submit a single Shamir share for stateful quorum-based unsealing. Shares accumulate in a server-side quorum with a 5-minute TTL. When the threshold is met, the barrier unseals automatically.

**Request:**
```json
{ "share": "base64sharevalue" }
```

**Response (200):**
```json
{
  "required": 3,
  "submitted": 2,
  "complete": false
}
```

When `complete` is `true`, the barrier has been unsealed.

**Errors:** `ErrShamirNotConfigured` (400), `ErrAlreadyUnsealed` (409), `ErrShamirDuplicateShare` (400), `ErrShamirQuorumExpired` (400), `ErrShamirCombineFailed` (400)

---

### POST /api/v1/barrier/unseal-shares

Stateless batch unsealing with all required shares in a single request.

**Request:**
```json
{
  "shares": ["share1", "share2", "share3"]
}
```

**Response (200):**
```json
{ "success": true, "message": "barrier unsealed with shares" }
```

**Errors:** `ErrShamirNotConfigured` (400), `ErrAlreadyUnsealed` (409), `ErrShamirQuorumIncomplete` (400), `ErrShamirCombineFailed` (400)

## Rekey

### POST /api/v1/barrier/rekey

Generate new Shamir shares for the existing root key. The root key does not change; only the shares are rotated. Requires `StrategyShamir` and the barrier must be unsealed.

**Request:**
```json
{
  "threshold": 4,
  "total": 7
}
```

**Response (200):**
```json
{
  "shares": ["newshare1", "newshare2", "newshare3", "newshare4", "newshare5", "newshare6", "newshare7"],
  "threshold": 4,
  "total_shares": 7
}
```

**Errors:** `ErrSealed` (400), `ErrShamirNotConfigured` (400), `ErrShamirThresholdInvalid` (400)

## Root Token

### POST /api/v1/barrier/root-token

Generate a one-time root token by proving knowledge of the master key through Shamir share reconstruction. Works whether the barrier is sealed or unsealed. Barrier state is unchanged after the call.

**Request:**
```json
{
  "shares": ["share1", "share2", "share3"]
}
```

**Response (200):**
```json
{
  "token": "a1b2c3d4e5f6...hex-encoded-hmac-sha256...",
  "created_at": "2025-01-15T10:30:00Z"
}
```

The token is `HMAC-SHA256(DEK, random_nonce || "go-xkms/root-token/v1")`.

**Errors:** `ErrShamirNotConfigured` (400), `ErrShamirQuorumIncomplete` (400), `ErrShamirCombineFailed` (400), `ErrRootTokenVerificationFailed` (401)

## Shamir Share Management

### GET /api/v1/barrier/shamir/shares

Returns the count and configuration of stored Shamir shares. Requires `StrategyShamir`.

**Response (200):**
```json
{
  "count": 5,
  "threshold": 3,
  "total": 5
}
```

**Errors:** `ErrShamirNotAvailable` (400)

---

### DELETE /api/v1/barrier/shamir/shares/{index}

Delete a single share by its 1-based index.

**Path parameters:** `index` (integer, >= 1)

**Response (200):**
```json
{ "success": true, "message": "share deleted" }
```

**Errors:** `ErrShamirNotAvailable` (400), `ErrInvalidShareIndex` (400), `ErrShamirShareNotFound` (404)

---

### DELETE /api/v1/barrier/shamir/shares

Delete all stored Shamir shares. Destructive and irreversible.

**Response (200):**
```json
{ "success": true, "message": "all shares deleted" }
```

**Errors:** `ErrShamirNotAvailable` (400)

---

### POST /api/v1/barrier/shamir/verify

Verify the integrity and consistency of all stored shares.

**Request:** Empty body.

**Response (200):**
```json
{ "success": true, "message": "shares verified" }
```

**Errors:** `ErrShamirNotAvailable` (400), `ErrShamirVerificationFailed` (400), `ErrShamirQuorumIncomplete` (400)

## Recovery Keys

### POST /api/v1/barrier/recovery-keys/generate

Generate an independent set of Shamir shares that can reconstruct the DEK. The barrier must be unsealed. Shares are returned for offline storage and are NOT persisted to the server.

**Request:**
```json
{
  "threshold": 3,
  "total": 5
}
```

**Response (200):**
```json
{
  "shares": ["recoveryshare1", "recoveryshare2", "recoveryshare3", "recoveryshare4", "recoveryshare5"],
  "threshold": 3,
  "total_shares": 5
}
```

**Errors:** `ErrSealed` (400), `ErrShamirThresholdInvalid` (400), `ErrShamirSplitFailed` (500)

---

### POST /api/v1/barrier/recovery-keys/recover

Reconstruct the DEK from recovery key shares and unseal the barrier. The barrier must be sealed.

**Request:**
```json
{
  "keys": ["recoveryshare1", "recoveryshare2", "recoveryshare3"]
}
```

**Response (200):**
```json
{ "success": true, "message": "barrier recovered with keys" }
```

**Errors:** `ErrAlreadyUnsealed` (409), `ErrRecoveryKeysNotFound` (404), `ErrShamirQuorumIncomplete` (400), `ErrShamirCombineFailed` (400)

---

### DELETE /api/v1/barrier/recovery-keys/

Remove recovery key metadata from storage. The barrier must be unsealed.

**Response (200):**
```json
{ "success": true, "message": "recovery keys deleted" }
```

**Errors:** `ErrSealed` (400)

## Common Error Responses

All error responses follow the format:

```json
{ "error": "error message text" }
```

| HTTP Status | Condition |
|-------------|-----------|
| 400 | Invalid request, bad parameters, or operation not applicable in current state |
| 401 | Authentication/credential failure |
| 404 | Resource not found (share, recovery keys) |
| 409 | Conflict (already initialized, already unsealed) |
| 500 | Internal server error |
| 503 | Barrier not configured on this server |
