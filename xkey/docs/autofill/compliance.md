# Compliance Mapping

The xKey AutoFill system maps to controls in HIPAA, PCI DSS, and FedRAMP through the mechanisms below.

## Control Matrix

| Control | HIPAA | PCI DSS | FedRAMP | Implementation |
|---------|-------|---------|---------|----------------|
| Audit trail | 164.312(b) | 10.2 | AU-2, AU-3 | Every credential access logged to audit store with operation type, domain, credential ID, and timestamp |
| No credential caching | 164.312(a)(1) | 3.4 | SC-28 | Extension never persists credentials; fetched on-demand per fill via encrypted IPC |
| Session timeout | 164.312(a)(2)(iii) | 8.1.8 | AC-12 | Configurable inactivity timeout (default 300s, 0 = disabled); extension disconnects and clears session crypto |
| App lock gate | 164.312(a)(1) | 8.1 | AC-11 | IPC server refuses all autofill requests when the app is locked (`ErrAutoFillAppLocked`) |
| Policy engine | 164.312(a)(1) | 7.1 | AC-3 | Admin-configurable: fill mode, allowed/blocked domains, TOTP policy, rate limit |
| Transport security | 164.312(e)(1) | 4.1 | SC-8 | Unix socket (mode `0600`) + X25519 ECDH session encryption (AES-256-GCM) over native messaging pipe |
| Extension ID validation | -- | 6.5 | IA-3 | Native host manifest restricts connection to a specific browser extension ID |
| Rate limiting | -- | 6.5 | SC-5 | Sliding-window rate limiter (default 10 fills/minute) prevents credential exfiltration |
| PIN per fill | 164.312(d) | 8.3 | IA-11 | Optional `require_pin_per_fill` for PCI DSS high environments; PIN verified before each credential retrieval |
| Replay protection | -- | 4.1 | SC-8 | Monotonically increasing nonce counters on encrypted messages; out-of-order nonces rejected (`ErrReplayDetected`) |
| Master disable | 164.312(a)(1) | 7.1 | AC-3 | `BrowserExtensionEnabled` toggle; when disabled, all IPC autofill requests return `ErrAutoFillDisabled` |

## Audit Events

Three operation types are recorded when `audit_enabled` is `true`:

| Operation | Fields | Trigger |
|-----------|--------|---------|
| `autofill_search` | `domain`, `matches` (count) | Credential search by domain |
| `autofill_credential_access` | `credential_id` | Password retrieval for form fill |
| `autofill_totp_access` | `account_id` | TOTP code generation |

Audit events are written to the audit store via the `audit.Logger` interface. The audit store is barrier-encrypted at rest.

## Transport Security Detail

### Native Messaging Pipe (Extension <-> Host)

The stdin/stdout pipe between the browser and the native messaging host uses:

1. **X25519 ECDH** key exchange at connection time (ephemeral keys per session)
2. **HKDF-SHA256** to derive two directional 256-bit keys (`xkey-nativemsg-v1-send`, `xkey-nativemsg-v1-recv`)
3. **AES-256-GCM** authenticated encryption for every message after the handshake
4. **Counter-based nonces** starting at 1, with monotonic enforcement (replay rejection)

Key direction is determined by lexicographic comparison of the two X25519 public keys, ensuring both sides derive identical keying material with opposite send/recv roles.

### Unix Domain Socket (Host <-> IPC Server)

- Socket file created with mode `0600` (owner read/write only)
- Socket directory created with mode `0700`
- When running under `sudo`, ownership is transferred to the original user via `SUDO_UID`/`SUDO_GID`
- JSON messages are transmitted in cleartext over the local socket (same-host, same-user isolation)

## PCI DSS High-Security Mode

For environments requiring PCI DSS Level 1 compliance:

```json
{
  "autofill_policy": {
    "fill_mode": "click_to_fill",
    "totp_policy": "prompt",
    "session_timeout_sec": 120,
    "require_pin_per_fill": true,
    "max_fills_per_minute": 5,
    "audit_enabled": true
  }
}
```

This configuration:
- Requires explicit user click before any credential fill
- Prompts before TOTP code injection
- Enforces a 2-minute session timeout
- Requires PIN verification before every credential retrieval
- Limits to 5 fills per minute
- Ensures all access is audit-logged

## Separation of Concerns

| Layer | Trust Boundary | Data Exposure |
|-------|---------------|---------------|
| Browser extension | Untrusted (runs in browser sandbox) | Never sees plaintext credentials directly; passwords exist only in DOM briefly during fill |
| Native messaging host | Process boundary; encrypts/decrypts pipe traffic | Transient plaintext during IPC relay; no persistent storage |
| IPC server | Unix socket ACL (mode 0600) | Routes messages; no credential knowledge |
| AutoFillService | Application trust boundary | Accesses barrier-encrypted credential stores; enforces policy and audit |
| Barrier | Cryptographic boundary | AES-256-GCM encryption at rest for all sensitive data |
