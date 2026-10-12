# Browser Trust Injection — Architecture

> **Status: NORMATIVE** · Feature: `browser-trust-injection` · Repo: `go-xkms` (`xkey/`) · Last verified: 2026-10-12

## The problem

When xkey operates as (or trusts) a CA, browsers need to trust that CA's
certificates to open TLS connections without warnings. `SSL_CERT_FILE` does
not solve this: it reaches OpenSSL-based child processes, but Chrome reads
its trust roots from an NSS `cert9.db`/`key4.db` pair and Firefox reads its
own profile's `cert9.db` — neither consults the OpenSSL environment at all
(`xkey/pkg/gui/services/browser_service.go:33-40`). Setting the variable and
calling the problem solved produced exactly the failure it was meant to
prevent: a TLS interstitial in a browser the user had just been told to
trust.

## Where this lives

The whole feature is xkey-side, under `xkey/pkg/gui/services/` and
`xkey/pkg/nssdb/`, with a CLI entry point at `xkey/cmd/xkey/cmd/browser.go`.
Nothing in go-xkms's root module (`pkg/*`) is involved — this is a xkey
product surface over the go-xkms trust store, not shared library code, so it
belongs under `xkey/docs/` per that tree's own convention
(`xkey/docs/README.md` §"Feature documentation"). It absorbed the root
module's legacy `docs/browser/README.md`, which was stale on a load-bearing
point (below) and has been deleted (go-xkms#1433).

## Shape chosen: a pure-Go NSS writer plus a Firefox-policy exporter, both driven by one trust-hash gate

Two independent browser families, two independent mechanisms, one shared
gate:

- **Chrome family** (Chrome, Chromium, Brave, Edge, Opera, Vivaldi — matched
  by binary-name substring in `classifyBrowser`,
  `secure_browser_service.go:811-831`) reads NSS `cert9.db`/`key4.db`.
  `xkey/pkg/nssdb.Writer` (`nssdb.go:151-421`) is a from-scratch, pure-Go
  writer for that format — no `certutil` dependency — built directly on
  `database/sql` against `modernc.org/sqlite` (a pure-Go SQLite driver), with
  hand-rolled PKCS#11-attribute-shaped rows, PBES2/PBMAC1 ASN.1 structures
  for the password/signature metadata, and NSS's own
  `sftkdb_HMACSDB`-compatible HMAC construction for trust-object signatures
  (`nssdb.go:611-705`, citing `lib/softoken/sftkdb.c` by name).
- **Firefox family** (Firefox, LibreWolf, Waterfox) is documented in the
  deleted legacy README as reading a `policies.json` file via `MOZ_POLICIES_FILE`.
  **That mechanism does not work and the code no longer relies on it**: "Firefox
  enterprise policies (policies.json) are NOT used because Mozilla only loads
  policies.json from system-protected paths (`/etc/firefox/policies/`,
  `<install>/distribution/`) — there is no env var or per-user override that
  Firefox honors" (`secure_browser_service.go:408-420`). Firefox trust is
  established the same way Chrome's is: `xkey/pkg/nssdb.Writer` populates the
  isolated Firefox profile's own `cert9.db` directly
  (`injectFirefoxNSSDB`, `secure_browser_service.go:469-503`). `policies.json`
  and per-certificate PEM exports are still written alongside it, but only as
  an operator-inspection aid and a manual fallback for a system administrator
  who wants to deploy the supported system-wide policies path — not as the
  mechanism the launched browser itself reads.
- **Change detection**: `computeTrustHash` (`secure_browser_service.go:844-852`)
  is a SHA-256 over an implementation-version tag and the sorted SHA-256
  fingerprints of every trust-store certificate. It is tracked **per
  resolved target store** — keyed by browser family *and* the currently
  configured profile mode — not globally, because the on-disk store a sync
  writes to depends on both (`secure_browser_service.go:36-49`,
  `:744-755`). A single global hash was tried first and caused a launch in
  one profile mode to mark a *different* mode's store falsely up to date,
  leaving that store with stale CAs. `browserStorePresent`
  (`secure_browser_service.go:733-742`) additionally probes for the
  resolved store's `cert9.db` on disk, so a store wiped externally after its
  hash was recorded still gets resynced rather than silently skipped.
- **Automatic rebuild on trust-store mutation**: the GUI wires
  `trustSvc.SetOnMutate(func() { secureBrowserSvc.Rebuild() })`
  (`xkey/pkg/gui/app.go:1831-1835`), so adding, removing, or updating a CA
  certificate in the xkey trust store triggers `Rebuild()`
  (`secure_browser_service.go:289-317`), which resyncs both families
  unconditionally rather than waiting for the hash check on next launch.

## Profile modes

Each family independently supports **isolated** (default — a dedicated
profile under `~/.xkey/browsers/<family>/profile/`, fully separated from the
user's normal browser state) and **shared** (the browser's own default
profile; for shared-mode Chrome this targets the user's real
`~/.pki/nssdb`, and for shared-mode Firefox no NSS injection happens at all
— "the user's own profile must not be mutated by us",
`secure_browser_service.go:461-465`). `targetNSSDBDir`
(`secure_browser_service.go:753-772`) is the single function resolving which
of the four (family × mode) combinations a sync writes to.

## Chrome extension import (isolated mode only)

A separate, optional capability layered on top of the same isolated Chrome
profile: `LaunchBrowserWithOptions` can copy user-installed extensions (the
documented motivating case is a browser-automation extension) from the
system default Chrome profile into the isolated one, so automation that
depends on an extension being present still works inside the sandboxed
profile (`secure_browser_extensions.go:25-53`). It materializes the
extension's unpacked version directory and its `extensions.settings.<id>`
registration entry the way Chrome's own installer would — `--load-extension`
is ignored by branded Chrome 137+, so this is the only mechanism that still
works — and separately regenerates native-messaging-host manifests with a
HOME-restoring wrapper script, because the isolated launch redirects `HOME`
to the profile directory for NSS purposes and that redirection would
otherwise break any native-messaging host that resolves its own state under
the real `$HOME` (`secure_browser_extensions.go:286-333`). Only the
extension's unpacked files, its registration entry, and its two state
directories (`Local Extension Settings`, `IndexedDB`) are copied — cookies,
history, login data, and every other profile artifact stay in the source
profile.

## Why HOME redirection, not `--user-data-dir` alone, for Chrome

`--user-data-dir` controls where Chrome stores its profile, but Chrome on
Linux reads its NSS trust database from `$HOME/.pki/nssdb` **regardless** of
`--user-data-dir`. Isolated-mode Chrome launches with `HOME` set to the
profile directory so that `$HOME/.pki/nssdb` resolves to a directory inside
the managed profile rather than the user's real home
(`secure_browser_service.go:546-553`).

## Rejected alternatives

- **`SSL_CERT_FILE` / a system trust-bundle file.** Rejected: neither Chrome
  nor Firefox reads it; both use NSS. `BrowserService.applyTrustBundle`
  still sets `SSL_CERT_FILE` for whatever *non-browser* child processes it
  launches (OpenSSL/curl/native-messaging helpers), but its own doc comment
  says explicitly that browser trust comes from `syncBrowserTrust`, not this
  (`browser_service.go:368-395`).
- **Shelling out to `certutil`.** Rejected in favor of the pure-Go
  `nssdb.Writer`, removing a runtime dependency on the NSS command-line
  tools being installed.
- **Firefox `policies.json` via `MOZ_POLICIES_FILE`.** Tried, then
  abandoned once found non-functional for a per-user, per-profile launcher —
  see above.
- **A single global trust-hash.** Tried, then replaced by the
  per-resolved-target-store keying described above once it was shown to
  desync a mode-switched store.
