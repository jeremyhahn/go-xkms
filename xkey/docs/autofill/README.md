# AutoFill Architecture

The xKey AutoFill system enables secure browser-based credential filling through a layered architecture that keeps sensitive data within the xKey desktop application. Credentials are never cached in the browser -- they are fetched on-demand per fill and transmitted over an encrypted channel.

## System Overview

```
Browser Extension
    |
    | stdin/stdout (length-prefixed JSON, X25519 ECDH + AES-256-GCM encrypted)
    v
Native Messaging Host (xkey extension host)
    |
    | Unix domain socket (JSON, mode 0600)
    v
xKey IPC Server
    |
    | in-process function calls
    v
AutoFillService --> PasswordManager (static passwords, barrier-encrypted)
               \--> OATH Service (TOTP generation)
               \--> AppLockService (gate on lock state)
               \--> PINService (optional per-fill verification)
               \--> AuditLogger (compliance trail)
```

WebAuthn/FIDO2 MFA is handled transparently by xKey's virtual FIDO2 authenticator. The browser extension does not participate in WebAuthn flows.

## Components

### Domain Matching Library

**Package:** `pkg/autofill/domain.go`

Provides URL normalization, hostname extraction, and secure domain matching.

- `ExtractDomain(rawURL)` -- extracts the registrable domain (e.g., `login.okta.com` -> `okta.com`)
- `ExtractHostname(rawURL)` -- extracts the lowercase hostname, stripping port/path/query/fragment
- `MatchesDomain(candidateURL, targetDomain)` -- dot-boundary subdomain matching
- `NormalizeURL(rawURL)` -- alias for `ExtractHostname` for semantic clarity

Dot-boundary security: `MatchesDomain` requires a `.` separator before the target domain. This prevents `evil-github.com` from matching `github.com`. Only exact matches (`github.com`) and proper subdomains (`login.github.com`) are accepted.

### Policy Engine

**Package:** `pkg/autofill/policy.go`

Configurable security policy governing autofill behavior.

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `fill_mode` | `FillMode` | `click_to_fill` | How credentials are injected |
| `totp_policy` | `TOTPPolicy` | `prompt` | How TOTP codes are handled |
| `session_timeout_sec` | `int` | `300` | Inactivity timeout (0 = disabled) |
| `require_pin_per_fill` | `bool` | `false` | Require PIN before each credential access |
| `allowed_domains` | `[]string` | `[]` | Domain allowlist (empty = all allowed) |
| `blocked_domains` | `[]string` | `[]` | Domain blocklist (takes precedence over allowed) |
| `max_fills_per_minute` | `int` | `10` | Sliding-window rate limit (0 = unlimited) |
| `audit_enabled` | `bool` | `true` | Log credential access events |

Includes a sliding-window `RateLimiter` using `sync/atomic` for the limit value and a mutex-protected timestamp slice.

See [Policy Configuration Reference](policy.md) for full details.

### AutoFill Service

**Package:** `xkey/pkg/gui/services/autofill_service.go`

Orchestrates credential lookup and TOTP generation. Implements the `ipc.AutofillHandler` interface for direct dispatch from the IPC server.

Responsibilities:
- Enforces preconditions (master toggle, app lock state)
- Applies domain policy via `autofill.IsDomainAllowed`
- Enforces rate limiting via `autofill.RateLimiter`
- Searches static passwords by domain match, cross-referencing OATH accounts for TOTP availability
- Generates TOTP codes via `OATHService`
- Optionally verifies PIN before credential access (`require_pin_per_fill`)
- Writes audit log entries for search, credential access, and TOTP access

The service uses `atomic.Pointer` for lock-free policy access and `atomic.Bool` for the master enable toggle.

### IPC Protocol

**Package:** `xkey/pkg/ipc/`

Unix domain socket server with JSON message framing. Socket created with mode `0600` in a directory with mode `0700`.

**Message types:** `touch`, `type_password`, `status`, `pkcs11`, `autofill`

**Autofill actions:** `search`, `get`, `totp`, `totp_by_id`, `status`, `policy`

All message types and autofill actions use map-based O(1) dispatch. The `AutofillHandler` interface defines six methods corresponding to the six autofill actions:

```go
type AutofillHandler interface {
    HandleAutofillSearch(domain string) (*AutofillResult, error)
    HandleAutofillGet(id, challenge string) (*AutofillResult, error)
    HandleAutofillTOTP(domain string) (*AutofillResult, error)
    HandleAutofillTOTPByID(id string) (*AutofillResult, error)
    HandleAutofillStatus() (*AutofillResult, error)
    HandleAutofillPolicy() (*AutofillResult, error)
}
```

**Example IPC request (search):**
```json
{
  "type": "autofill",
  "autofill": {
    "action": "search",
    "domain": "github.com"
  }
}
```

**Example IPC response:**
```json
{
  "status": "ok",
  "autofill": {
    "credentials": [
      {
        "id": "abc123",
        "title": "GitHub",
        "username": "user@example.com",
        "url": "https://github.com",
        "has_totp": true,
        "totp_id": "oath-456"
      }
    ]
  }
}
```

### Native Messaging Host

**Package:** `xkey/pkg/nativemsg/`

Bridges Chrome/Firefox native messaging to the IPC server. The browser launches the host process via the manifest; the host communicates with the browser over stdin/stdout using Chrome's length-prefixed JSON protocol (4-byte little-endian uint32 length header + JSON payload, max 1 MB).

**Session encryption protocol:**

1. Extension sends `{"type":"handshake","pubkey":"<base64 X25519 public key>"}`
2. Host generates ephemeral X25519 keypair, performs ECDH, derives directional keys via HKDF-SHA256
3. Host responds `{"type":"handshake_ok","pubkey":"<base64 X25519 public key>"}`
4. All subsequent messages are `{"type":"encrypted","nonce":<counter>,"ciphertext":"<base64 AES-256-GCM>"}`
5. Monotonically increasing nonce counters provide replay protection

Key direction is determined by lexicographic comparison of public keys using two HKDF info strings: `xkey-nativemsg-v1-send` and `xkey-nativemsg-v1-recv`.

The host name is `com.automatethethings.xkey`.

### Browser Extension

**Location:** `xkey/extension/`

Manifest V3 extension for Chrome and Firefox.

| Component | File | Role |
|-----------|------|------|
| Background service worker | `src/background.ts` | Native host connection, encryption, message dispatch |
| Content script | `src/content.ts` | Form detection, field icon injection, credential filling |
| Popup | `src/popup.ts` + `src/popup.html` | Manual credential search and fill |
| Types | `src/types.ts` | Shared TypeScript type definitions |

**Permissions:** `nativeMessaging`, `activeTab`, `tabs`

The content script:
- Detects visible password fields and associated username fields using selector-based heuristics
- Detects TOTP/MFA fields (`autocomplete="one-time-code"`, `name*="otp"`, etc.)
- Injects a key icon overlay on password fields (click-to-fill)
- Sets field values using the native `HTMLInputElement.prototype.value` setter to trigger React/Angular/Vue change detection
- Shows a credential chooser dropdown when multiple credentials match
- Monitors DOM mutations for SPA page transitions

### GUI Integration

The `AutoFillService` is wired as a Wails binding in `xkey/pkg/gui/app.go`, making its methods callable from the Svelte frontend. It is simultaneously registered as the `ipc.AutofillHandler` on the IPC server, so both the GUI and the browser extension share the same service instance.

The `BrowserExtensionEnabled` config toggle controls the master enable state via `AutoFillService.SetEnabled()`.

## Data Flow: Credential Fill

1. User clicks the xKey icon on a password field
2. Content script sends `{type:"search", domain:"github.com"}` to the background worker
3. Background worker connects to native host (if not already connected), performs ECDH handshake
4. Background worker encrypts the IPC message and sends it over the native messaging pipe
5. Native host decrypts, forwards to IPC server over Unix socket
6. IPC server dispatches to `AutoFillService.HandleAutofillSearch`
7. AutoFillService checks preconditions (enabled, unlocked, rate limit, domain policy)
8. AutoFillService searches passwords, cross-references OATH accounts, writes audit log
9. Response flows back: IPC -> native host (encrypted) -> background worker (decrypted) -> content script
10. Content script displays credential chooser (if multiple) or requests fill
11. Fill request retrieves the password (never cached), fills form fields
