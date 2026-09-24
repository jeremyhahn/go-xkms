# Browser Trust Injection — User Guide

> **Status: NORMATIVE** · Feature: `browser-trust-injection` · Repo: `go-xkms` (`xkey/`) · Last verified: 2026-09-24

## Launch a browser that trusts your xkey CA

```
xkey browser launch https://internal.example.com
```

`xkey` auto-detects the first available Chrome- or Firefox-family browser,
syncs every certificate currently in your xkey trust store into that
browser's certificate database, and opens the URL. Supported Chrome-family
binaries: Chrome, Chromium, Brave, Edge, Opera, Vivaldi. Supported
Firefox-family binaries: Firefox, LibreWolf, Waterfox.

```
xkey browser launch --browser /usr/bin/firefox https://internal.example.com
```

## Isolated vs. shared profiles

By default, `xkey browser launch` opens the browser with a dedicated,
isolated profile under `~/.xkey/browsers/<family>/profile/` — separate
bookmarks, history, and extensions from your normal browsing. This is the
recommended mode for anything security-sensitive.

Switch a family to **shared mode** (your existing default browser profile,
with xkey's CA certificates injected into it) from the GUI's Browser panel,
per-family. There is no CLI flag for this — see [`cli.md`](cli.md).

Shared-mode Chrome injects certificates into your real
`~/.pki/nssdb`. **Shared-mode Firefox does not inject anything** — xkey will
not modify your real Firefox profile's certificate database, by design.

## Bring browser-automation extensions into the isolated profile

If your isolated Chrome profile needs an extension you already have
installed in your normal Chrome profile (a browser-automation extension is
the motivating example):

```
xkey browser launch --include-extensions https://app.local
```

Restrict to specific extensions:

```
xkey browser launch --include-extensions --extension <extension-id> https://app.local
```

Only the extension's own files and its `chrome.storage.local`/IndexedDB
state are copied — cookies, history, and everything else from your source
profile stay there. This only works for Chrome-family browsers in isolated
mode.

## Certificates go stale — when do they resync?

If you're using the desktop GUI, adding, removing, or updating a certificate
in the trust store automatically resyncs every managed browser's certificate
store, with no extra step. If you're driving everything from the CLI, a
resync happens automatically the next time you run `xkey browser launch`
against a family whose stored certificates have changed — there is no
separate "resync now" verb.

## Troubleshooting

- **A launched "trusted" browser still shows a certificate warning.** Confirm
  you launched it through `xkey browser launch` (or the GUI's launch button)
  rather than the browser's normal shortcut — untouched browser launches get
  no certificate injection at all. If you recently flipped a family between
  isolated and shared mode, launch once more: the store for the newly
  selected mode may not have been synced yet.
- **Firefox specifically.** If you were relying on the legacy
  `~/.xkey/browsers/firefox/policies.json` file being read by a system-wide
  Firefox policy deployment, note that the *launched* isolated-profile
  Firefox does not depend on that file at all — it reads its own profile's
  certificate database directly. The `policies.json` file is written for
  operators who want to deploy the trust bundle through Firefox's supported
  system-wide policy mechanism separately; it is not what makes
  `xkey browser launch --browser firefox` work.
