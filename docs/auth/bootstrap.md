# Bootstrap Authentication

The `pkg/bootstrap` package manages first-time server initialization with a secure state machine, one-time setup tokens, and optional M-of-N threshold ceremony for multi-admin deployments.

## Server Startup Sequence

Bootstrap initializes as part of the server startup in `pkg/server/server.go`. The initialization order ensures all prerequisites are available before bootstrap runs:

```
 1. Backends         (software, PKCS#11, TPM2, cloud KMS, etc.)
 2. KeyStore         (per-backend key storage)
 3. UserStore        (prerequisite for bootstrap -- stores admin accounts)
 4. Authentication   (JWT, mTLS, adaptive auth)
 5. Authorization    (RBAC)
 6. AuditLogger      (structured audit trail)
 7. Barrier          (AES-256-GCM at-rest encryption)
 8. BarrierRegistry  (multi-tenant barrier isolation)
 9. Bootstrap        <-- HERE
10. PIN Manager      (SO PIN + User PIN)
11. PasswordStore    (static password storage)
12. PlatformStore    (sealed credential store)
13. PolicyManager    (PCR policy management)
14. Health           (health checks for all subsystems)
```

On startup, `NewService` checks `userStore.HasAnyUsers()`. If users already exist, the state is set to `complete` immediately -- the system has already been initialized.

## State Machine

```
                    GenerateSetupToken()
  UNINITIALIZED ----------------------> READY
                                          |
                          Initialize()    |
                     +--------------------+
                     |
            +--------v---------+
            |  single-admin?   |
            +--+----------+----+
               |          |
           yes |          | no (threshold mode)
               v          v
          COMPLETE    CEREMONY
                         |
                         | ConsumeInvitation() x N
                         v
                      COMPLETE
```

| State | Description |
|-------|-------------|
| `uninitialized` | No setup token generated |
| `ready` | Token generated, awaiting first admin |
| `ceremony` | Threshold mode: waiting for additional admins |
| `complete` | System fully initialized |

## Fresh Install Flow

### Single-Admin Mode

1. **Server starts** -- bootstrap service detects no users exist, enters `uninitialized` state
2. **Operator generates setup token** -- via CLI or internal API (server logs the token)
3. **Admin calls `POST /api/v1/init`** -- provides setup token, username, and FIDO2 attestation
4. **Bootstrap atomically creates admin** -- validates token, creates user with `RoleAdmin`, consumes token
5. **System enters `complete` state** -- all subsequent requests require authentication

### Multi-Admin Threshold Mode

1. **Server starts** with `threshold_mode: true`, `admin_threshold: M`, `admin_total: N`
2. **Operator generates setup token**
3. **First admin calls `POST /api/v1/init/threshold`** -- uses setup token, system enters `ceremony` state
4. **Operator generates N-1 invitations** -- distributes to remaining admins via secure channel
5. **Each subsequent admin calls `POST /api/v1/init/threshold`** -- uses their invitation token
6. **When N admins registered**, system auto-transitions to `complete`

## Setup Token

- 32 bytes from `crypto/rand`, base64url-encoded (43 characters)
- One-time use, TTL-limited (default: 1 hour)
- Validated with `crypto/subtle.ConstantTimeCompare` (timing-attack resistant)
- Can only be generated when state is `uninitialized`

## Atomic Initialization

`Initialize` is all-or-nothing:
1. Validate state is `ready`
2. Validate setup token (fail fast before side effects)
3. Create admin user in user store
4. If user creation fails, token is NOT consumed (retry safe)
5. On success: consume token, transition to `complete` (or `ceremony` for threshold)

## FIDO2 Integration

The `InitRequest.FIDO2Attestation` field carries a WebAuthn attestation response as base64 JSON. The flow:

1. Client performs FIDO2 registration (MakeCredential) locally against a hardware authenticator
2. Client sends the attestation response in the `POST /api/v1/init` request body
3. The REST handler passes the attestation to `webauthn.Service` for validation
4. Bootstrap validates the token and creates the admin user
5. The FIDO2 credential is associated with the user account

This binds the first admin account to a hardware security key, ensuring strong authentication from the very first operation.

## REST API

### GET /api/v1/bootstrap/status

Returns the current bootstrap state. No authentication required during bootstrap.

**Response:**
```json
{
  "state": "uninitialized",
  "message": "System requires initialization. Generate a setup token to begin."
}
```

State messages:

| State | Message |
|-------|---------|
| `uninitialized` | System requires initialization. Generate a setup token to begin. |
| `ready` | Setup token generated. System is ready for admin initialization. |
| `ceremony` | Threshold ceremony in progress. Waiting for additional admin registrations. |
| `complete` | System is initialized and ready. |

### POST /api/v1/init

Single-admin initialization. No authentication required.

**Request:**
```json
{
  "setup_token": "base64url-encoded-32-byte-token",
  "username": "admin",
  "display_name": "System Administrator",
  "fido2_attestation": "<base64-encoded WebAuthn attestation response>"
}
```

**Response (200 OK):**
```json
{
  "user_id": "base64url-encoded-user-id",
  "username": "admin",
  "jwt": "eyJhbGciOiJ...",
  "server_info": {
    "spki_pin": "sha256/...",
    "hostname": "xkms.example.com",
    "version": "1.0.0"
  }
}
```

### POST /api/v1/init/threshold

Threshold mode admin registration. No authentication required during bootstrap.

**First admin (uses setup token):**
```json
{
  "setup_token": "base64url-encoded-token",
  "username": "admin1",
  "display_name": "Admin One",
  "fido2_attestation": "<attestation>"
}
```

**Subsequent admins (use invitation token):**
```json
{
  "invitation": "base64url-encoded-invitation-token",
  "username": "admin2",
  "display_name": "Admin Two",
  "fido2_attestation": "<attestation>"
}
```

## Barrier Coordination

The barrier (at-rest encryption) initializes before bootstrap in the server startup sequence. This means:

- The barrier root key and encryption subsystem are available before any user data is created
- The first admin user's credentials are stored through the barrier's encrypted storage
- If the barrier is sealed on restart, bootstrap still reports `complete` (users exist), but key operations require unsealing

## Configuration

YAML (`xkmsd.yaml`):

```yaml
init_bootstrap:
  enabled: true
  token_ttl: 1h            # Setup token validity (default: 1 hour)
  threshold_mode: false     # Enable M-of-N admin ceremony
  admin_threshold: 0        # M: minimum admins (required if threshold_mode)
  admin_total: 0            # N: total admins to register (required if threshold_mode)
```

Go config struct:

```go
type InitBootstrapConfig struct {
    Enabled        bool          `yaml:"enabled"`
    TokenTTL       time.Duration `yaml:"token_ttl"`
    ThresholdMode  bool          `yaml:"threshold_mode"`
    AdminThreshold int           `yaml:"admin_threshold"`
    AdminTotal     int           `yaml:"admin_total"`
}
```

Validation: if `threshold_mode` is true, then `admin_threshold > 0` and `admin_threshold <= admin_total`.

## Service API

| Method | Description |
|--------|-------------|
| `NewService(config, userStore, logger)` | Creates bootstrap service |
| `State()` | Returns current state |
| `IsInitialized()` | Returns true if complete |
| `GenerateSetupToken()` | Generates one-time token (uninitialized state only) |
| `ValidateSetupToken(token)` | Checks validity without consuming |
| `ConsumeSetupToken(token)` | Atomically marks token as used |
| `Initialize(ctx, req)` | Atomic init: validate token, create admin, transition state |
| `GenerateInvitations(count)` | Creates invitation tokens (ceremony state only) |
| `ValidateInvitation(token)` | Checks invitation validity |
| `ConsumeInvitation(token)` | Consumes invitation, auto-completes ceremony when admin count reached |

## Concurrency

- **RWMutex**: write lock during state transitions (`Initialize`, `GenerateSetupToken`, `ConsumeInvitation`), read lock for status queries
- **Race-safe**: concurrent `Initialize` calls -- only the first succeeds, others get `ErrNotReady` after acquiring the lock
- **Atomic token consumption**: token marked as used only after successful user creation

## Error Reference

| Error | HTTP Status | Condition |
|-------|-------------|-----------|
| `ErrAlreadyInitialized` | 409 Conflict | System already initialized |
| `ErrNotReady` | 503 Service Unavailable | State is not `ready` |
| `ErrInvalidToken` | 401 Unauthorized | Token does not match (constant-time) |
| `ErrTokenExpired` | 410 Gone | Token TTL elapsed |
| `ErrTokenUsed` | 409 Conflict | Token already consumed |
| `ErrNoToken` | 503 Service Unavailable | No token generated yet |
| `ErrUsernameTaken` | 409 Conflict | Username already exists |
| `ErrEmptyUsername` | 400 Bad Request | Empty username in request |
| `ErrEmptyAttestation` | 400 Bad Request | Missing FIDO2 attestation |
| `ErrThresholdConfig` | -- | Invalid threshold/total values |
| `ErrCeremonyNotStarted` | 503 Service Unavailable | Threshold ceremony not active |
| `ErrCeremonyComplete` | 409 Conflict | Ceremony already finished |
| `ErrInvalidInvitation` | 401 Unauthorized | Invitation token invalid |
| `ErrInvitationExpired` | 410 Gone | Invitation TTL elapsed |
| `ErrInvitationUsed` | 409 Conflict | Invitation already consumed |

## Cross-References

- [Initialization Guide](../usage/initialization.md) -- step-by-step CLI initialization
- [Barrier Architecture](../seal/README.md) -- at-rest encryption design
- [MFA Policy Engine](mfa-policy.md) -- operation-level MFA requirements
- [Bootstrap CA Configuration](../configuration/bootstrap.md) -- CA bundle bootstrap (separate from init bootstrap)
