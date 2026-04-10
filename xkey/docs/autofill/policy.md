# Policy Configuration Reference

The autofill policy is defined in `pkg/autofill/policy.go` as `AutoFillPolicy`. It governs all credential fill operations performed by the browser extension.

## Policy Fields

### `fill_mode`

**Type:** `FillMode` (string)
**Default:** `click_to_fill`
**JSON key:** `fill_mode`

Controls how credentials are injected into form fields.

| Value | Behavior |
|-------|----------|
| `click_to_fill` | User must click the xKey icon overlay on the password field to trigger a fill |
| `auto_fill` | Credentials are filled automatically on page load when a single match is found |
| `popup_only` | User must open the extension popup and manually select a credential |
| `disabled` | All autofill functionality is disabled |

### `totp_policy`

**Type:** `TOTPPolicy` (string)
**Default:** `prompt`
**JSON key:** `totp_policy`

Controls how TOTP codes are handled during autofill.

| Value | Behavior |
|-------|----------|
| `auto` | TOTP codes are filled automatically when a TOTP/MFA field is detected |
| `prompt` | User is prompted before filling TOTP codes |
| `disabled` | TOTP codes are never auto-filled |

### `session_timeout_sec`

**Type:** `int`
**Default:** `300` (5 minutes)
**JSON key:** `session_timeout_sec`

Inactivity timeout in seconds for the native messaging session. After this period without activity, the extension disconnects from the native host and clears its session encryption state. The user must re-establish the connection on the next fill request.

Set to `0` to disable the session timeout.

### `require_pin_per_fill`

**Type:** `bool`
**Default:** `false`
**JSON key:** `require_pin_per_fill`

When `true`, the user must provide their PIN before each credential retrieval (`get` action). The PIN is verified against the `PINService` in the AutoFillService. This is intended for high-security environments (PCI DSS Level 1).

The PIN is transmitted within the encrypted IPC message and is never stored by the extension.

### `allowed_domains`

**Type:** `[]string`
**Default:** `[]` (empty -- all non-blocked domains permitted)
**JSON key:** `allowed_domains`

When non-empty, only domains matching an entry in this list are permitted for autofill operations. Domain matching uses the same dot-boundary rules as `blocked_domains`.

An empty list means all domains are allowed (subject to `blocked_domains`).

### `blocked_domains`

**Type:** `[]string`
**Default:** `[]` (empty -- no domains blocked)
**JSON key:** `blocked_domains`

Domains that are always denied for autofill, regardless of the `allowed_domains` list. Blocked domains take precedence over allowed domains.

### `max_fills_per_minute`

**Type:** `int`
**Default:** `10`
**JSON key:** `max_fills_per_minute`

Maximum number of credential fill operations allowed within a 60-second sliding window. When the limit is exceeded, subsequent fill requests return `ErrAutoFillRateLimit` until the window advances.

Set to `0` to disable rate limiting.

### `audit_enabled`

**Type:** `bool`
**Default:** `true`
**JSON key:** `audit_enabled`

When `true`, the AutoFillService writes audit log entries for credential search, credential access, and TOTP access events. See [Compliance Mapping](compliance.md) for audit event details.

## Domain Matching Rules

Domain matching is implemented in `pkg/autofill/domain.go` and applies to both `allowed_domains` and `blocked_domains`.

**Precedence:** Blocked domains are always checked first and take precedence over allowed domains.

**Dot-boundary matching:** A candidate hostname matches a target domain if:
1. It equals the target domain exactly (case-insensitive, `www.` stripped), OR
2. It ends with `.` + target domain (proper subdomain)

This prevents suffix-collision attacks:

| Candidate | Target | Match? | Reason |
|-----------|--------|--------|--------|
| `github.com` | `github.com` | Yes | Exact match |
| `www.github.com` | `github.com` | Yes | `www.` stripped, exact match |
| `login.github.com` | `github.com` | Yes | Proper subdomain (`.github.com`) |
| `evil-github.com` | `github.com` | No | No dot boundary; `-github.com` is not `.github.com` |
| `192.168.1.1` | `192.168.1.1` | Yes | IP address exact match |

**URL normalization:** URLs are normalized by stripping the scheme, port, path, query, and fragment before matching. If no scheme is present, `https://` is assumed for parsing purposes.

## Example Configuration

```json
{
  "browser_extension_enabled": true,
  "autofill_policy": {
    "fill_mode": "click_to_fill",
    "totp_policy": "auto",
    "session_timeout_sec": 300,
    "require_pin_per_fill": false,
    "allowed_domains": [],
    "blocked_domains": ["example-blocked.com"],
    "max_fills_per_minute": 10,
    "audit_enabled": true
  }
}
```

This configuration:
- Enables the browser extension master toggle
- Requires the user to click the icon before filling (`click_to_fill`)
- Automatically fills TOTP codes when detected (`auto`)
- Disconnects after 5 minutes of inactivity
- Does not require PIN per fill
- Allows all domains except `example-blocked.com` and its subdomains
- Limits to 10 fills per minute
- Logs all credential access to the audit store

## Validation

`AutoFillPolicy.Validate()` checks:
- `fill_mode` must be one of: `click_to_fill`, `auto_fill`, `popup_only`, `disabled`
- `totp_policy` must be one of: `auto`, `prompt`, `disabled`
- `session_timeout_sec` must be >= 0
- `max_fills_per_minute` must be >= 0

Invalid policies are rejected with typed errors: `ErrInvalidFillMode`, `ErrInvalidTOTPPolicy`, `ErrInvalidSessionTimeout`, `ErrInvalidMaxFills`.

## Runtime Policy Updates

The policy can be updated at runtime via `AutoFillService.SetPolicy()`. This validates the new policy, stores it atomically (using `atomic.Pointer`), and updates the rate limiter limit to match. No restart is required.
