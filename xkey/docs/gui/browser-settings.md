# Browser Settings

> **Status: REFERENCE** · Last verified: 2026-10-13
> Superseded background: the GUI feature folder, starting with [architecture.md](architecture.md), is normative.

Platform-aware browser launcher for xkey. Used by OIDC login flows and any feature that needs to open a URL in the user's browser.

**Package:** `xkey/pkg/gui/services/browser_service.go`

## Overview

The browser service detects available browsers, persists user preferences, and opens URLs using the configured browser. Configuration is stored as plain JSON (not barrier-encrypted) since it contains no secrets.

## API

### Types

| Type | Description |
|------|-------------|
| `BrowserConfig` | Settings: DefaultBrowser, CustomCommand, IncludeTrustBundle, ChromeProfileMode, FirefoxProfileMode, IncludeExtensions |
| `BrowserInfo` | Detected browser: Name, Path |
| `BrowserService` | Service managing browser launching |

### BrowserService Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `OpenURL` | `OpenURL(url) error` | Launch URL in configured browser |
| `GetConfig` | `GetConfig() BrowserConfig` | Return current configuration |
| `SetConfig` | `SetConfig(config) error` | Update and persist configuration |
| `DetectBrowsers` | `DetectBrowsers() []BrowserInfo` | List available browsers on the system |

`OpenURL` (`browser_service.go:189`) accepts only `http` and `https` URLs
(`urlsafety.ValidateLaunchURL`); any other scheme returns
`ErrBrowserInvalidURL` before a launcher runs.

### Browser Resolution Order

1. **Custom command** - If `CustomCommand` is set, use it with `{url}` placeholder replacement (the URL is appended when there is no placeholder)
2. **System default** - If `DefaultBrowser` is `"system"`, delegate to platform handler
3. **Specific binary** - Use `DefaultBrowser` as the browser executable path

### Platform Handlers

| Platform | System Handler |
|----------|---------------|
| Linux | `xdg-open {url}` |
| macOS | `open {url}` |
| Windows | `rundll32 url.dll,FileProtocolHandler {url}` |

### Custom Command

The `{url}` placeholder is replaced with the target URL before execution:

```json
{
  "default_browser": "system",
  "custom_command": "/usr/bin/chromium --new-window {url}"
}
```

### Trust bundle

When `include_trust_bundle` is set, `OpenURL` first asks the wired
`TrustSyncer` to write the platform CAs into the browsers' certificate
databases, and sets `SSL_CERT_FILE` on the child process for OpenSSL-based
consumers (`syncBrowserTrust` and `applyTrustBundle`, `browser_service.go:367`
and `:386`).

## Configuration

Config file: `~/.xkey/config/browser.json` when no path is passed to
`NewBrowserService` (`browser_service.go:132`).

This file is **not** barrier-encrypted because it contains no sensitive data. It is written atomically with `0600` permissions inside a `0700` directory (`saveConfig`, `:432`).

Default configuration when no file exists: `default_browser` is `system`, and
both profile modes are `isolated` (`NewBrowserService`, `:122`).

### Detected Browsers (Linux)

`DetectBrowsers` always lists **System Default**, then each of these paths
that exists (`knownBrowsersForGOOS`, `browser_service.go:467`; macOS has its
own list):

| Name | Path |
|------|------|
| Firefox | `/usr/bin/firefox` |
| Chromium | `/usr/bin/chromium` |
| Chromium | `/usr/bin/chromium-browser` |
| Google Chrome | `/usr/bin/google-chrome` |
| Brave | `/usr/bin/brave-browser` |

## Errors

Declared in `xkey/pkg/gui/services/browser_errors.go`:

| Error | Description |
|-------|-------------|
| `ErrBrowserEmptyURL` | Empty URL provided |
| `ErrBrowserInvalidURL` | URL is not `http` or `https` |
| `ErrBrowserLaunchFailed` | Browser process failed to start |
| `ErrBrowserInvalidConfig` | Invalid configuration (both fields empty) |
| `ErrBrowserConfigSave` | Failed to persist configuration |
| `ErrBrowserConfigLoad` | Failed to load configuration |
| `ErrBrowserTrustBundleExport` | Exporting the trust bundle failed |
| `ErrBrowserTrustBundleManifestWrite` | Writing the trust bundle manifest failed |
