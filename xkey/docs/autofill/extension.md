# Extension Installation & Configuration

## CLI Commands

### `xkey extension install`

Install native messaging host manifests so the browser can launch the xKey host process.

```bash
# Install for all supported browsers
xkey extension install

# Install for Chrome only
xkey extension install chrome

# Install for Firefox only
xkey extension install firefox
```

The command auto-detects the xkey binary path and writes the manifest to the platform-appropriate location.

### `xkey extension uninstall`

Remove native messaging manifests. Missing manifests are reported but do not cause errors.

```bash
# Uninstall for all browsers
xkey extension uninstall

# Uninstall for Chrome only
xkey extension uninstall chrome
```

### `xkey extension status`

Display the installation status of native messaging manifests for all supported browsers.

```bash
$ xkey extension status
BROWSER    INSTALLED  PATH
chrome     yes        /home/user/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json
firefox    no         /home/user/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json
```

### `xkey extension host`

Run the native messaging host process. This is invoked by the browser, not by the user. It is a hidden command.

```bash
# Typically invoked by the browser via the manifest, not manually:
xkey extension host --socket /run/user/1000/xkey/xkey.sock
```

- Stdout is the native messaging pipe; all logging goes to stderr (JSON format).
- Connects to the IPC server via the Unix socket.
- Performs X25519 ECDH handshake with the extension, then enters the encrypted message relay loop.
- Exits cleanly on SIGINT, SIGTERM, or stdin EOF (browser closes extension).

## Native Messaging Host Manifest

The manifest name is `com.automatethethings.xkey`. The manifest tells the browser:
- The path to the xkey binary
- The communication type (`stdio`)
- Which extension IDs are allowed to connect

### Chrome Manifest

```json
{
  "name": "com.automatethethings.xkey",
  "description": "xkey native messaging host for browser extension integration",
  "path": "/usr/local/bin/xkey",
  "type": "stdio",
  "allowed_origins": [
    "chrome-extension://placeholder_extension_id/"
  ]
}
```

### Firefox Manifest

```json
{
  "name": "com.automatethethings.xkey",
  "description": "xkey native messaging host for browser extension integration",
  "path": "/usr/local/bin/xkey",
  "type": "stdio",
  "allowed_extensions": [
    "xkey@automatethethings.com"
  ]
}
```

## Manifest Locations

### Linux

| Browser | Path |
|---------|------|
| Chrome | `~/.config/google-chrome/NativeMessagingHosts/com.automatethethings.xkey.json` |
| Firefox | `~/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json` |

### macOS

| Browser | Path |
|---------|------|
| Chrome | `~/Library/Application Support/Google/Chrome/NativeMessagingHosts/com.automatethethings.xkey.json` |
| Firefox | `~/Library/Application Support/Mozilla/NativeMessagingHosts/com.automatethethings.xkey.json` |

Manifest directories are created with mode `0755`. Manifest files are written with mode `0644`.

## Browser Extension Loading (Development)

### Build

```bash
cd xkey/extension
npm install
npm run build
```

This compiles TypeScript sources from `src/` into `dist/` and copies `manifest.json`, `popup.html`, and icons.

### Load Unpacked (Chrome)

1. Navigate to `chrome://extensions/`
2. Enable "Developer mode" (toggle in top-right)
3. Click "Load unpacked"
4. Select the `xkey/extension/dist/` directory
5. Note the generated Extension ID -- update `ChromeExtensionID` in `nativemsg/manifest.go` and reinstall the manifest

### Load Temporarily (Firefox)

1. Navigate to `about:debugging#/runtime/this-firefox`
2. Click "Load Temporary Add-on..."
3. Select `xkey/extension/dist/manifest.json`
4. The extension ID (`xkey@automatethethings.com`) is set in the manifest's `browser_specific_settings.gecko.id`

## Extension Manifest V3

**File:** `xkey/extension/manifest.json`

```json
{
  "manifest_version": 3,
  "name": "xKey AutoFill",
  "version": "1.0.0",
  "permissions": ["nativeMessaging", "activeTab", "tabs"],
  "background": {
    "service_worker": "background.js",
    "type": "module"
  },
  "content_scripts": [
    {
      "matches": ["<all_urls>"],
      "js": ["content.js"],
      "run_at": "document_idle"
    }
  ],
  "action": {
    "default_popup": "popup.html"
  },
  "browser_specific_settings": {
    "gecko": {
      "id": "xkey@automatethethings.com"
    }
  }
}
```

**Permissions explained:**

| Permission | Purpose |
|------------|---------|
| `nativeMessaging` | Connect to the native messaging host (`com.automatethethings.xkey`) |
| `activeTab` | Access the current tab's URL for domain matching |
| `tabs` | Query tab URLs for the popup credential search |

## Extension ID Validation

The native messaging manifest restricts which extension IDs can connect to the host:

- **Chrome:** `allowed_origins` in the manifest must contain the extension's `chrome-extension://` origin
- **Firefox:** `allowed_extensions` must contain the extension's addon ID (`xkey@automatethethings.com`)

If an extension with a different ID attempts to connect, the browser rejects the connection before the host process is launched.
