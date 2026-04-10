# Browser Settings

Platform-aware browser launcher for xkey. Used by OIDC login flows and any feature that needs to open a URL in the user's browser.

**Package:** `xkey/pkg/gui/services/browser_service.go`

## Overview

The browser service detects available browsers, persists user preferences, and opens URLs using the configured browser. Configuration is stored as plain JSON (not barrier-encrypted) since it contains no secrets.

## API

### Types

| Type | Description |
|------|-------------|
| `BrowserConfig` | Settings: DefaultBrowser, CustomCommand |
| `BrowserInfo` | Detected browser: Name, Path |
| `BrowserService` | Service managing browser launching |

### BrowserService Methods

| Method | Signature | Description |
|--------|-----------|-------------|
| `OpenURL` | `OpenURL(ctx, url) error` | Launch URL in configured browser |
| `GetConfig` | `GetConfig() BrowserConfig` | Return current configuration |
| `SetConfig` | `SetConfig(config) error` | Update and persist configuration |
| `DetectBrowsers` | `DetectBrowsers() []BrowserInfo` | List available browsers on the system |

### Browser Resolution Order

1. **Custom command** - If `CustomCommand` is set, use it with `{url}` placeholder replacement
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

## Configuration

Config file: `~/.xkey/config/browser.json`

This file is **not** barrier-encrypted because it contains no sensitive data. It is created with `0600` permissions inside a `0700` directory.

Default configuration when no file exists:

```json
{
  "default_browser": "system"
}
```

### Detected Browsers (Linux)

| Name | Path |
|------|------|
| System Default | (platform handler) |
| Firefox | `/usr/bin/firefox` |
| Chromium | `/usr/bin/chromium` |
| Google Chrome | `/usr/bin/google-chrome` |
| Brave | `/usr/bin/brave-browser` |

## Errors

| Error | Description |
|-------|-------------|
| `ErrBrowserEmptyURL` | Empty URL provided |
| `ErrBrowserLaunchFailed` | Browser process failed to start |
| `ErrBrowserInvalidConfig` | Invalid configuration (both fields empty) |
| `ErrBrowserConfigSave` | Failed to persist configuration |
| `ErrBrowserConfigLoad` | Failed to load configuration |
