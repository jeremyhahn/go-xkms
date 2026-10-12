# Browser Trust Injection — Engineering Contract

> **Status: NORMATIVE** · Feature: `browser-trust-injection` · Repo: `go-xkms` (`xkey/`) · Last verified: 2026-10-12

## Exported surface — `xkey/pkg/gui/services`

- `NewBrowserService(configPath string, logger *slog.Logger) (*BrowserService,
  error)` (`browser_service.go:119-153`). Empty `configPath` defaults to
  `~/.xkey/config/browser.json`. `BrowserConfig` fields:
  `DefaultBrowser string` (default `BrowserSystem = "system"`),
  `CustomCommand string`, `IncludeTrustBundle bool`,
  `ChromeProfileMode`/`FirefoxProfileMode string` (`ProfileModeIsolated =
  "isolated"` default, or `ProfileModeShared = "shared"`),
  `IncludeExtensions bool` (`browser_service.go:56-86`).
- `BrowserService.OpenURL(url string) error`, `GetConfig()`/`SetConfig()`,
  `DetectBrowsers() []BrowserInfo`, `SetTrustSyncer(TrustSyncer)`,
  `SetTrustBundlePath(path string)`/`GetTrustBundlePath()`.
- `TrustSyncer` interface: `Rebuild() error` — `*SecureBrowserService`
  satisfies it (`browser_service.go:41-45`).
- `NewSecureBrowserService(baseDir string, browserSvc *BrowserService,
  trustSvc *TrustService, logger *slog.Logger) *SecureBrowserService`
  (`secure_browser_service.go:128-146`).
- `SecureBrowserService.LaunchBrowser(browserPath, url string)
  (*LaunchResult, error)` and `LaunchBrowserWithOptions(browserPath, url
  string, opts LaunchOptions) (*LaunchResult, error)`
  (`secure_browser_service.go:160-269`). `LaunchOptions{IncludeExtensions
  bool, ExtensionIDs []string, SourceProfile string}`
  (`secure_browser_service.go:75-93`). `LaunchResult{Browser, Family, Mode
  string, CertCount, ExtensionsImported int, PID int}`
  (`secure_browser_service.go:58-70`).
- `SecureBrowserService.DetectBrowsers() []BrowserInfo` — like
  `BrowserService.DetectBrowsers` but filtered to browsers `classifyBrowser`
  can place in the Chrome or Firefox family (`secure_browser_service.go:274-287`).
- `SecureBrowserService.Rebuild() error` — force-resyncs both families
  regardless of the trust hash (`secure_browser_service.go:292-317`).

## Exported surface — `xkey/pkg/nssdb`

- `InitDir(nssdbDir string) error` — creates the directory, writes
  `pkcs11.txt`, and opens/closes a `Writer` once to create schema and the
  password entry (`nssdb.go:404-421`).
- `NewWriter(nssdbDir string) (*Writer, error)` — directory must already
  exist. `Writer.AddTrustedCA(cert *x509.Certificate, label string) error`,
  `Writer.RemoveByPrefix(prefix string) error`, `Writer.Close() error`
  (`nssdb.go:160-399`).

`AddTrustedCA` writes a certificate object and a matching trust object into
`cert9.db` (`CKA_CLASS` = `CKO_CERTIFICATE` / the NSS trust-object class
`0xCE534353`), then writes PBMAC1 HMAC signatures for the trust attributes
into `key4.db`'s `metaData` table (`nssdb.go:223-266`). `RemoveByPrefix`
matches on the certificate label column (`a3`), then separately locates and
removes every trust object sharing that certificate's issuer+serial pair —
plural, because a certificate re-synced multiple times without this could
accumulate stale trust objects, one of which NSS might pick instead of the
fresh one, silently producing `",,"` (untrusted) trust flags for a
certificate whose current trust object is valid (`nssdb.go:268-379`).

## Invariants

- **Labels are prefixed `"xkey-"` for every certificate this package
  writes** (`nssdbCertLabelPrefix`, `secure_browser_service.go:52-53`), so
  `RemoveByPrefix("xkey-")` can remove exactly the xkey-managed set on
  resync without touching any certificate a user or another tool added to
  the same NSS database.
- **Trust-object signatures cover only the attributes NSS itself verifies**
  — `CKA_TRUST_SERVER_AUTH`/`CLIENT_AUTH`/`CODE_SIGNING`/
  `EMAIL_PROTECTION`/`STEP_UP_APPROVED` and the SHA-1/MD5 cert-hash
  attributes (`nssSignsAttribute`, `nssdb.go:648-663`); structural
  attributes (class/token/private/label/issuer/serial/override) are
  deliberately left unsigned to match what `certutil` itself writes.
- **The HMAC input has no length prefixes** — `objectID (uint32 BE) ||
  attrType (uint32 BE) || attrValue`, matching NSS's `sftkdb_HMACSDB`
  exactly (`encodeSignatureData`, `nssdb.go:684-705`); an earlier version
  that substituted `0` for `objectID` and length-prefixed each value
  produced signatures NSS silently rejected as untrusted.
- **Shared-mode Chrome's `~/.pki/nssdb` is only ever probed for existence,
  never written to as xkey bookkeeping** (`browserStorePresent`,
  `secure_browser_service.go:733-742`) — the trust-hash file itself always
  lives under xkey's own `baseDir`, never inside the user's real NSS
  directory.
- **`Clean`/`Close`-style teardown is idempotent everywhere in this feature**:
  `Writer.Close()` is safe to call once and sets `closed`; every subsequent
  `Writer` method checks it and returns `ErrWriterClosed`.
- **Extension import only fires for Chrome in isolated mode.** Any other
  combination (Firefox, or Chrome in shared mode) returns
  `ErrSecureBrowserExtImportUnsupported` before any file is touched
  (`secure_browser_service.go:220-224`).

## Errors

`xkey/pkg/gui/services/browser_errors.go`: `ErrBrowserEmptyURL`,
`ErrBrowserLaunchFailed`, `ErrBrowserInvalidConfig`, `ErrBrowserConfigSave`,
`ErrBrowserConfigLoad`, `ErrBrowserTrustBundleExport`,
`ErrBrowserTrustBundleManifestWrite`.

`xkey/pkg/gui/services/secure_browser_errors.go`: `ErrSecureBrowserEmptyURL`,
`ErrSecureBrowserEmptyPath`, `ErrSecureBrowserUnknownFamily`,
`ErrSecureBrowserLaunchFailed`, `ErrSecureBrowserCertSync`,
`ErrSecureBrowserNoCerts`, `ErrSecureBrowserPolicyWrite`,
`ErrSecureBrowserNSSDB`, `ErrSecureBrowserHashRead`,
`ErrSecureBrowserHashWrite`, `ErrSecureBrowserCertExport`,
`ErrSecureBrowserInvalidMode`, `ErrSecureBrowserHomeDir`,
`ErrSecureBrowserExtImportUnsupported`, `ErrSecureBrowserSourceProfile`,
`ErrSecureBrowserExtImport`.

`xkey/pkg/nssdb/errors.go`: `ErrDirNotExist`, `ErrOpenDatabase`,
`ErrCloseDatabase`, `ErrCreateSchema`, `ErrWriterClosed`,
`ErrNilCertificate`, `ErrEmptyLabel`, `ErrInsertCertificate`,
`ErrInsertTrust`, `ErrRemoveCertificate`, `ErrRemoveTrust`,
`ErrEmptyPrefix`, `ErrBeginTx`, `ErrCommitTx`, `ErrSerialEncode`,
`ErrPasswordInit`, `ErrSignatureInsert`, `ErrASN1Marshal`, `ErrEncrypt`,
`ErrInitDir`, `ErrWritePKCS11Txt`. All typed sentinels; `DetailError`,
`MessageError`, `WrappedError` in the same file provide `Unwrap()`-preserving
wrapping without inline `fmt.Errorf`.

## Configuration

`BrowserConfig` is JSON-persisted at `~/.xkey/config/browser.json` (GUI) or
`<xkey-home>/config/browser.json` (CLI, resolved via `xhome.Resolve()`).
There is no separate on-disk configuration file for
`SecureBrowserService`; its only configuration input is `baseDir` (GUI:
`~/.xkey/browsers`; CLI: `<xkey-home>/browsers`), and it reads the profile
mode fields (`ChromeProfileMode`, `FirefoxProfileMode`) live off the
`BrowserService` it was constructed with.

### On-disk layout under `baseDir`

| Path | Written by | Source |
|---|---|---|
| `trust_hash.<family>.<mode>` | last-synced trust hash, one per resolved target store, mode `0600` | `trustHashPath`, `writeTrustHash` (`secure_browser_service.go:781`, `:799`) |
| `chrome/profile/` | isolated Chrome profile; HOME is redirected here | `secure_browser_service.go:236` |
| `chrome/profile/.pki/nssdb/` | isolated Chrome NSS database | `chromeNSSDBDir` (`:698`) |
| `firefox/profile/` | isolated Firefox profile; its `cert9.db` sits directly in it | `firefoxNSSDBDir` (`:715`) |
| `firefox/certs/<sha256-fingerprint>.pem` | one PEM per CA, operator aid only | `firefoxCertsDir` (`:703`), `:462` |
| `firefox/policies.json` | operator aid only, not read by the launched browser | `firefoxPoliciesPath` (`:708`) |

Shared-mode Chrome writes the user's `~/.pki/nssdb` instead; no bookkeeping
file is ever written there (`targetNSSDBDir`, `:753`).

### Auto-detection candidates

`DetectBrowsers` walks a fixed per-OS list (`knownBrowsersForGOOS`,
`browser_service.go:467`): on Linux `/usr/bin/firefox`, `/usr/bin/chromium`,
`/usr/bin/chromium-browser`, `/usr/bin/google-chrome` and
`/usr/bin/brave-browser`; on macOS the Safari, Firefox, Google Chrome and
Brave app bundles; no other OS. Any other binary is reachable by passing its
path with `--browser`. Its family is then the first keyword its base name
contains (`classifyBrowser`, `secure_browser_service.go:811`): `chrome`,
`chromium`, `brave`, `edge`, `opera`, `vivaldi` for Chrome; `firefox`,
`librewolf`, `waterfox` for Firefox.

## What is absent, half-built, or misdescribed

- **Firefox trust is not established via `policies.json`/`MOZ_POLICIES_FILE`**
  (the claim of the legacy `docs/browser/README.md`, absorbed and deleted,
  go-xkms#1433); the actual mechanism is direct NSS `cert9.db` injection
  into the isolated profile — see [`architecture.md`](architecture.md).
  `policies.json` is still written, but only as an operator-facing artifact.
- **No REST/gRPC/network transport surface** — this feature is reachable
  only through the xkey CLI and the Wails-bound GUI service methods. See
  [`api.md`](api.md).
- **Shared-mode Firefox gets no CA injection at all** — by design
  (`secure_browser_service.go:461-465`), not a gap, but worth stating
  plainly: choosing shared mode for Firefox means the launched browser does
  not trust the xkey CA any differently than it would unlaunched.
- **GUI and CLI resolve `baseDir` through two different paths** — the GUI
  hardcodes `filepath.Join(home, ".xkey", "browsers")`
  (`xkey/pkg/gui/app.go:1823-1826`) while the CLI resolves it through
  `xhome.Resolve()` (`xkey/cmd/xkey/cmd/browser.go:101-133`). In the common
  case these resolve to the same directory, but a deployment with a
  non-default `xhome` root would see the CLI and GUI manage separate browser
  profile trees.

## Tests

`xkey/pkg/gui/services/browser_service_test.go`,
`secure_browser_service_test.go`, `secure_browser_extensions_test.go`;
`xkey/pkg/nssdb/nssdb_test.go` and `nssdb_failure_test.go` (error-injection
coverage for the writer); `xkey/cmd/xkey/cmd/browser_test.go` for the CLI
verb. Frontend end-to-end coverage:
`xkey/frontend/tests/e2e/browser-settings.spec.ts`,
`secure-browser.spec.ts`, `truststrap-to-browser.spec.ts`.
