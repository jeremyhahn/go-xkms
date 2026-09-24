# Browser Trust Injection — CLI

> **Status: NORMATIVE** · Feature: `browser-trust-injection` · Repo: `go-xkms` (`xkey/`) · Last verified: 2026-09-24

Binary: `xkey`. Group: `browser`. Source: `xkey/cmd/xkey/cmd/browser.go`.

## `xkey browser launch`

```
xkey browser launch [url] [flags]
```

Detects or resolves the target browser, synchronizes CA certificates from the
xkey trust store into that browser's certificate store, and launches it.
Defaults `url` to `about:blank` when omitted (`browser.go:93-97`).

| Flag | Type | Default | Notes |
|---|---|---|---|
| `--browser` | string | `""` | absolute path to a browser binary; empty auto-detects the first available Chrome- or Firefox-family browser |
| `--include-extensions` | bool | `false` | import user-installed extensions from the system default Chrome profile; Chrome + isolated mode only |
| `--extension` | string (repeatable) | none | restrict `--include-extensions` to specific extension IDs; default is all |
| `--source-profile` | string | `""` | source Chrome profile directory to import extensions from; default `~/.config/google-chrome/Default` |

(`browser.go:79-88`.)

```bash
# Auto-detect and launch with trust store certificates injected
xkey browser launch https://example.com

# A specific browser binary
xkey browser launch --browser /usr/bin/firefox https://internal.corp.local
xkey browser launch --browser /usr/bin/brave-browser https://myapp.local

# Import browser-automation extensions into the isolated Chrome profile
xkey browser launch --include-extensions https://app.local
xkey browser launch --include-extensions --extension <extension-id> https://app.local
```

Output reports the resolved family, profile mode, and certificate/extension
counts, e.g. `Launched chrome (isolated mode, 4 certificates)` or, when
extensions were imported, `Launched chrome (isolated mode, 4 certificates, 2
extensions)` (`browser.go:159-169`).

## What this command does not expose

There is no `--mode` flag to force isolated vs. shared profile mode from the
CLI — that is configured through `BrowserConfig.ChromeProfileMode` /
`FirefoxProfileMode`, persisted at `<xkey-home>/config/browser.json`, which
this command group has no verb to edit directly (the GUI's Browser panel,
`xkey/frontend/src/views/Browser.svelte`, does; see [`user.md`](user.md)).
There is also no `xkey browser rebuild`
verb — a forced resync happens automatically on trust-store mutation inside
the GUI process (`SetOnMutate`), or implicitly on the next `launch` whose
trust hash has changed; a CLI-only workflow that mutates the trust store
without ever launching a browser through this command will not proactively
resync a browser's certificate store until the next `launch`.
