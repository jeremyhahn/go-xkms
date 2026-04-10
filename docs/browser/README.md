# Secure Browser Launch

The secure browser launch feature starts a web browser pre-configured to trust certificates from the xkey trust store. This eliminates the need to manually import CA certificates into each browser, ensuring that all xkey-issued TLS certificates are trusted automatically.

## Overview

When xkey operates as a CA or manages an internal PKI, browsers need to trust the CA certificates to establish TLS connections without warnings. The secure browser launch feature solves this by creating browser profiles with the trust store certificates injected at launch time. Certificates are kept in sync: any mutation to the trust store triggers an automatic rebuild of the browser trust configuration.

## How It Works

Each browser family uses a different mechanism for certificate trust:

**Firefox family** -- Firefox reads enterprise policies from a `policies.json` file pointed to by the `MOZ_POLICIES_FILE` environment variable. The launcher exports each CA certificate as an individual PEM file and references them in the policies file under `Certificates.Install`. No manual cert import dialogs are needed.

**Chrome family** -- Chromium-based browsers use NSS `cert9.db` databases for certificate trust. The launcher populates the NSS database using a pure Go implementation, removing any dependency on the `certutil` command-line tool. Certificates are inserted with the `CT,C,C` trust flags (trusted for TLS, email, and object signing).

**Change detection** -- The launcher computes a SHA-256 hash over the sorted certificate fingerprints from the trust store. Browser trust configuration is rebuilt only when this hash changes, avoiding unnecessary work on repeated launches. Trust store mutations (add, remove, update) trigger an automatic rebuild on the next launch.

## Profile Modes

Each browser family supports two profile modes, configurable independently:

- **Isolated** (default) -- A dedicated profile directory is created under `~/.xkey/browsers/`. Browser state (bookmarks, history, extensions) is fully separated from the user's normal browser profile. This is the recommended mode for security-sensitive workflows.
- **Shared** -- The browser launches using the user's existing default profile. Trust store certificates are injected into the default profile's certificate database. Use this mode when you want xkey CA trust alongside your normal browsing environment.

Profile mode is configured per browser family in the xkey configuration or via the GUI.

## CLI Usage

```
xkey browser launch [url] [flags]
```

**Flags:**

| Flag | Description |
|------|-------------|
| `--browser` | Browser to launch: `chrome`, `chromium`, `brave`, `edge`, `opera`, `vivaldi`, `firefox`, `librewolf`, `waterfox` |

**Examples:**

```bash
# Launch default browser with xkey trust store
xkey browser launch

# Open a specific URL in Firefox
xkey browser launch https://internal.example.com --browser firefox

# Launch Brave with xkey CA certificates
xkey browser launch --browser brave
```

The launcher auto-detects installed browsers if `--browser` is not specified.

## GUI Usage

Navigate to **Settings > Browser**. The browser section displays detected browsers and their profile mode (isolated or shared). Click the launch button next to any browser to open it with the xkey trust store certificates injected.

## Data Layout

```
~/.xkey/browsers/
    trust-hash                     # SHA-256 hash of current trust store state
    certs/                         # Exported PEM files (one per CA certificate)
        ca-<fingerprint>.pem
    firefox/
        profile/                   # Isolated Firefox profile directory
        policies.json              # Enterprise policy file referencing certs/
    chrome/
        profile/                   # Isolated Chrome profile directory
        nssdb/
            cert9.db               # NSS certificate database
            key4.db                # NSS key database
            pkcs11.txt             # NSS module configuration
```

Chrome family browsers share the `chrome/nssdb/` database. Firefox family browsers share the `firefox/` profile and policy configuration.

## Supported Browsers

**Chrome family** (NSS cert9.db):

| Browser | Binary |
|---------|--------|
| Chrome | `google-chrome`, `google-chrome-stable` |
| Chromium | `chromium`, `chromium-browser` |
| Brave | `brave-browser`, `brave` |
| Edge | `microsoft-edge`, `microsoft-edge-stable` |
| Opera | `opera` |
| Vivaldi | `vivaldi`, `vivaldi-stable` |

**Firefox family** (MOZ_POLICIES_FILE):

| Browser | Binary |
|---------|--------|
| Firefox | `firefox` |
| LibreWolf | `librewolf` |
| Waterfox | `waterfox` |

## Requirements

- Go 1.21+
- Linux (browser detection uses standard binary paths)
- At least one supported browser installed

## License

This module is part of go-xkms and is dual-licensed under AGPL-3.0 and Commercial licenses.
