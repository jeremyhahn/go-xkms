# Browser Extension AutoFill — Engineering

> **Status: NORMATIVE** · Feature: `autofill` · Module: `go-xkms/xkey` · Last verified: 2026-09-28

See [architecture.md](architecture.md) for the component map and data flow
before reading this document.

## Exported surface: `go-xkms/pkg/autofill` (root module, via `sdk/go/autofill.go`)

```go
// domain.go
func ExtractDomain(rawURL string) string
func ExtractHostname(rawURL string) string
func MatchesDomain(candidateURL, targetDomain string) bool
func MatchesBaseDomain(candidateURL, storedURL string) bool
func MatchesPattern(hostname, pattern string) bool
func MatchesEntry(pageDomain, entryURL string, matchPatterns []string) bool
func NormalizeURL(rawURL string) string

// policy.go
type FillMode string   // "click_to_fill" | "auto_fill" | "popup_only" | "disabled"
type TOTPPolicy string  // "auto" | "prompt" | "disabled"
type AutoFillPolicy struct {
	FillMode              FillMode
	TOTPPolicy            TOTPPolicy
	SessionTimeoutSec     int
	RequireAuthentication bool
	AllowedDomains        []string
	BlockedDomains        []string
	MaxFillsPerMinute     int
	AuditEnabled          bool
}
func DefaultPolicy() *AutoFillPolicy
func (p *AutoFillPolicy) Validate() error
func (p *AutoFillPolicy) IsDomainAllowed(domain string) bool
type RateLimiter struct{ /* sliding 60s window */ }
func NewRateLimiter(maxPerMinute int) *RateLimiter
func (r *RateLimiter) Allow() bool
func (r *RateLimiter) Reset()
func (r *RateLimiter) SetLimit(maxPerMinute int)

// verifier.go
type VerifierOptions struct{ AllowMissingUV bool } // zero value is strict; see architecture.md
type AssertionVerifier struct{ /* ... */ }
func NewAssertionVerifier(rpID string, publicKeyCOSE []byte) (*AssertionVerifier, error)
func NewAssertionVerifierWithOptions(rpID string, publicKeyCOSE []byte, opts VerifierOptions) (*AssertionVerifier, error)
func (v *AssertionVerifier) Verify(authData, signature, clientDataHash []byte) error
```

Re-exported in `sdk/go/autofill.go` as `xkms.AutoFillPolicy`,
`xkms.AssertionVerifier`, `xkms.AutoFillVerifierOptions`,
`xkms.AutoFillRateLimiter`, `xkms.DefaultAutoFillPolicy`,
`xkms.AutoFillMatchesEntry`, `xkms.NewAssertionVerifier`,
`xkms.NewAssertionVerifierWithOptions`, `xkms.NewAutoFillRateLimiter`, plus
`xkms.FillModeAutoFill`/`FillModeClickToFill`/`TOTPPolicyPrompt` constants —
xkey imports only this SDK surface, never `pkg/autofill` directly.

## Exported surface: `AutoFillService` (`pkg/gui/services/autofill_service.go`)

```go
func NewAutoFillService(passwordSvc *StaticPasswordService, oathSvc *OATHService,
	appLockSvc *AppLockService, auditStore audit.Logger, logger *slog.Logger) *AutoFillService
func (s *AutoFillService) SetContext(ctx context.Context)
func (s *AutoFillService) SetPolicyPersistFunc(fn PolicyPersistFunc)
func (s *AutoFillService) SetEnabled(enabled bool) error
func (s *AutoFillService) IsEnabled() bool
func (s *AutoFillService) SetAuthenticator(auth *authenticator.Authenticator)
func (s *AutoFillService) SetRegistrationDir(dir string)
func (s *AutoFillService) SetEnterprisePolicy(p *EnterpriseExtensionPolicy)
func (s *AutoFillService) GetEnterprisePolicy() *EnterpriseExtensionPolicy
func (s *AutoFillService) SetPolicy(policy *xkms.AutoFillPolicy) error
func (s *AutoFillService) GetPolicy() *xkms.AutoFillPolicy
func (s *AutoFillService) GetRequireAuthentication() bool
func (s *AutoFillService) SetRequireAuthentication(required bool) error
func (s *AutoFillService) SearchCredentials(domain string) ([]ipc.AutofillCredential, error)
func (s *AutoFillService) GetCredential(id, challenge string) (*ipc.AutofillFillResult, error)
func (s *AutoFillService) SaveCredential(domain, username, password, title string) (*ipc.AutofillResult, error)
func (s *AutoFillService) IgnoreDomain(domain string) (*ipc.AutofillResult, error)
func (s *AutoFillService) IsIgnoredDomain(domain string) bool
func (s *AutoFillService) GetTOTPForDomain(domain string) (*ipc.AutofillTOTP, error)
func (s *AutoFillService) GetTOTPByID(id string) (*ipc.AutofillTOTP, error)
func (s *AutoFillService) GetStatus() *ipc.AutofillStatus
func (s *AutoFillService) GetAutoFillPolicy() *ipc.AutofillPolicyResult
```

`EnterpriseExtensionPolicy{Enabled, RequireAuthentication, ForceAudit,
AllowedDomains, BlockedDomains, MaxFillsPerMinute, UserCanConfigure}` — SO
overrides that always win over the user's own policy.
`PolicyPersistFunc func(*xkms.AutoFillPolicy) error` writes a changed policy
back to config.

`AutoFillService` also implements `ipc.AutofillHandler` (nine
`Handle*` methods, one per `ipc.Action*` constant — see below) for direct
IPC dispatch.

## Exported surface: `pkg/nativemsg`

```go
// crypto.go
func NewSessionCrypto() (*SessionCrypto, []byte, error)
func (sc *SessionCrypto) CompleteHandshake(peerPubKey []byte) error
func (sc *SessionCrypto) Encrypt(plaintext []byte) (nonce uint64, ciphertext []byte, err error)
func (sc *SessionCrypto) Decrypt(nonce uint64, ciphertext []byte) ([]byte, error)
func (sc *SessionCrypto) Ready() bool

// pairing.go
type PairingState struct{ IdentityKey []byte; PairedAt time.Time }
func NewPairingVerifier(statePath string) (*PairingVerifier, error)
func (v *PairingVerifier) IsPaired() bool
func (v *PairingVerifier) IsPairedForOrigin(origin string) bool
func (v *PairingVerifier) GetStates() map[string]*PairingState
func (v *PairingVerifier) VerifyIdentity(identityKey, signature, ephemeralPubKey []byte, origin string) error
func (v *PairingVerifier) StartPairing(identityKey []byte, origin string) (string, error)
func (v *PairingVerifier) CompletePairing(identityKey []byte, origin, code string) error
func (v *PairingVerifier) UnpairOrigin(origin string) error
func (v *PairingVerifier) UnpairAll() error
func (v *PairingVerifier) Reload() error
func (v *PairingVerifier) VerifyParentProcess() error
func (v *PairingVerifier) SetAuditLogger(l audit.Logger)

// host.go
func NewHost(ipcSocketPath string, logger *slog.Logger, pairing *PairingVerifier) *Host
func (h *Host) Run(ctx context.Context) error

// manifest.go
func InstallManifest(browser Browser, xkeyBinaryPath string) error
func UninstallManifest(browser Browser) error
func GetManifestStatus() []ManifestStatusInfo
const ChromeExtensionID = "chrome-extension://ogbhdplieldlomhnokdapcopejmkelkl/"
const FirefoxExtensionID = "xkey@automatethethings.com"
var ChromeAllowedOriginOverride string // set by `xkey extension install --allowed-origin`
```

## Exported surface: `pkg/ipc` (autofill/pairing payloads)

```go
// autofill_types.go
const ActionAutofillSearch, ActionAutofillGet, ActionAutofillTOTP, ActionAutofillTOTPByID,
	ActionAutofillStatus, ActionAutofillPolicy, ActionAutofillSave, ActionAutofillIgnoreDomain,
	ActionAutofillFocus = "search", "get", "totp", "totp_by_id", "status", "policy", "save", "ignore_domain", "focus"
type AutofillPayload struct{ Action, Domain, ID, Challenge, Username, Password, Title string }
type AutofillCredential struct{ ID, Title, Username, URL string; HasTOTP bool; TOTPID string }
type AutofillAssertion struct{ AuthData, Signature, CredentialID, PublicKey string } // base64
type AutofillFillResult struct{ Username, Password string; Assertion *AutofillAssertion }
type AutofillTOTP struct{ Code string; TimeLeft, Period int; AccountID, Issuer string }
type AutofillStatus struct{ Available, AppLocked bool; FillMode string; ExtensionEnabled bool }
type AutofillPolicyResult struct{ /* mirrors xkms.AutoFillPolicy, JSON-tagged */ }
func (p *AutofillPayload) Validate() error

// server.go
type AutofillHandler interface {
	HandleAutofillSearch(domain string) (*AutofillResult, error)
	HandleAutofillGet(id, challenge string) (*AutofillResult, error)
	HandleAutofillTOTP(domain string) (*AutofillResult, error)
	HandleAutofillTOTPByID(id string) (*AutofillResult, error)
	HandleAutofillStatus() (*AutofillResult, error)
	HandleAutofillPolicy() (*AutofillResult, error)
	HandleAutofillSave(domain, username, password, title string) (*AutofillResult, error)
	HandleAutofillIgnoreDomain(domain string) (*AutofillResult, error)
	HandleAutofillFocus() (*AutofillResult, error)
}
type PairingHandler interface {
	HandlePairingNotifyCode(code, identityKey, origin string) error
	HandlePairingCompleted(origin string) error
}

// pairing_types.go
const ActionPairingNotifyCode, ActionPairingCompleted = "notify_code", "completed"
type PairingPayload struct{ Action, Code, IdentityKey, Origin string }
```

## Exported surface: GUI `PairingService` (`pkg/gui/services/pairing_service.go`)

```go
func NewPairingService(log *slog.Logger) *PairingService
func (s *PairingService) SetVerifier(v *nativemsg.PairingVerifier)
func (s *PairingService) SetIPCProvider(p IPCStatusProvider)
func (s *PairingService) SetEventEmitter(fn func(events.Event))
func (s *PairingService) IsPaired() bool
func (s *PairingService) GetPairedExtensions() []*PairingStatus
func (s *PairingService) RequestPairing(identityKeyBase64, origin string) (string, error)
func (s *PairingService) VerifyPairingCode(identityKeyBase64, origin, code string) error
func (s *PairingService) Unpair(origin string) error
func (s *PairingService) GetExtensionFullStatus() *ExtensionFullStatus
func (s *PairingService) InstallManifest(browser string) error
func (s *PairingService) UninstallManifest(browser string) error
```

Emits Wails events `extension:pairing_request` and `extension:paired`/
`extension:unpaired` (`pkg/gui/events`) so the Svelte frontend reacts live.

## Invariants

- **`VerifierOptions.AllowMissingUV` is set in exactly one constructor call**
  in this codebase — `newAutofillVerifier` (`autofill_service.go`) — and the
  doc comment on both the option and the constructor explain why nowhere
  else should set it. See architecture.md.
- **A denied autofill precondition is always audited**, and a failed audit
  write fails the request rather than letting it proceed unaudited:
  `auditPreconditionFailure` logs `audit.OpAutofillDenied`
  (`SeveritySecurity`) and every caller propagates a non-nil error from it.
- **Enterprise policy always wins over user policy**, never the reverse:
  `checkPreconditions`, `isEnterpriseDomainAllowed`, and the `RequireAuthentication`/
  audit checks in `GetCredential`/`SearchCredentials` all check the
  enterprise override after the user's own and let it force a stricter
  outcome, never a looser one.
- **Pairing and identity-verification failures are durable.** Every
  failure is persisted before the refusal is returned
  (`recordLimitFailure`, `pairing_limits.go:88`); a failure that cannot be
  persisted is returned as an error rather than as `ErrPairingInvalidCode`,
  so a flaky store never grants a free guess. A new `PairingVerifier` over
  the same state directory inherits the count and any lockout
  (`lockedOut`, `pairing_limits.go:68`).
- **A pairing-revoked extension is disconnected on its next message, not
  polled for.** `Host.relayLoop` reloads pairing state and checks
  `IsPairedForOrigin` before processing every incoming message.
- **Password values are never included in an `AutofillResult` except inside
  `AutofillFillResult` at fill time**, and only after any required CTAP2
  authentication succeeds.

## Errors

`go-xkms/pkg/autofill` (`errors.go`, `verifier.go`):
`ErrInvalidFillMode`, `ErrInvalidTOTPPolicy`, `ErrInvalidSessionTimeout`,
`ErrInvalidMaxFills`, `ErrRateLimitExceeded`, `ErrAuthenticationFailed`;
`ErrVerifierInvalidAuthData`, `ErrVerifierRPIDMismatch`,
`ErrVerifierMissingUP`, `ErrVerifierMissingUV`,
`ErrVerifierSignCountRegress`, `ErrVerifierInvalidSignature`,
`ErrVerifierInvalidPublicKey`, `ErrVerifierNilAuthData`,
`ErrVerifierNilSignature`, `ErrVerifierNilClientDataHash`,
`ErrVerifierEmptyRPID`, `ErrVerifierNilCOSEKey`.

`pkg/gui/services/autofill_service.go`: `ErrAutoFillNotConfigured`,
`ErrAutoFillAppLocked`, `ErrAutoFillDisabled`, `ErrAutoFillRateLimit`,
`ErrAutoFillDomainBlocked`, `ErrAutoFillInvalidID`, `ErrAutoFillNotFound`,
`ErrAutoFillAuthFailed`, `ErrAutoFillChallengeRequired`,
`ErrAutoFillVerificationFailed`, `ErrAutoFillPolicyEnforced`,
`ErrAutoFillSaveInvalidInput`, `ErrAutoFillCredentialExists`,
`ErrAutoFillDomainIgnored`, `ErrAutoFillStoreNotConfigured`.

`pkg/nativemsg/errors.go`: `ErrHandshakeRequired`, `ErrHandshakeFailed`,
`ErrInvalidPublicKey`, `ErrEncryptionFailed`, `ErrDecryptionFailed`,
`ErrReplayDetected`, `ErrMessageTooLarge`, `ErrReadFailed`, `ErrWriteFailed`,
`ErrInvalidManifest`, `ErrManifestInstall`, `ErrManifestNotFound`,
`ErrIPCConnection`, `ErrPairingRequired`, `ErrPairingRejected`,
`ErrPairingInvalidCode`, `ErrPairingLocked`, `ErrPairingExpired`,
`ErrIdentityMismatch`, `ErrIdentitySignature`, `ErrIdentityOriginMismatch`,
`ErrIdentityLocked`, `ErrParentProcessInvalid`, `ErrPairingRevoked`.

`cmd/xkey/cmd/extension.go`: `ErrExtensionInstallFailed`,
`ErrExtensionUninstallFailed`, `ErrExtensionInvalidBrowser`,
`ErrExtensionHostFailed`, `ErrExtensionUnpairFailed`,
`ErrExtensionPairStatusFailed`. `cmd/xkey/cmd/extension_serve.go` adds a
long list of headless-startup-specific errors (barrier strategy refusals
for `pkcs11`/`shamir`/cloud-KMS strategies a headless process cannot drive
interactively — see the doc comments at each sentinel in that file).

## Configuration

| Setting | Resolution | Notes |
|---|---|---|
| IPC socket | `--socket` (GUI: fixed path; headless: flag) → `ipc.DefaultSocketPath()` | Shared by the GUI and `xkey extension serve` |
| Native messaging manifest | Installed by `xkey extension install`; browser launches the host via `os.Executable()`'s resolved path | See [cli.md](cli.md) |
| Pairing state | `<data dir>/extension/pairing.json`, created only by `extension host`/`extension serve` (never by a read-only command) | `--no-pairing` skips identity verification (development only) |
| Pairing rate limits | `<data dir>/extension/pairing-limits.json` (0600), derived from the pairing state path (`limitsPathFor`, `pairing_limits.go:62`); shared by the GUI and every native host instance | Deleting it by hand clears a lockout; a corrupt file refuses pairing until removed |
| Autofill policy | In-memory (`atomic.Pointer`), persisted via `PolicyPersistFunc` to config; `EnterpriseExtensionPolicy` layered on top | See architecture.md |

## Tests

| File | Tags | Covers |
|---|---|---|
| `go-xkms/pkg/autofill/domain_test.go`, `policy_test.go`, `verifier_test.go` (root module) | (none) | Domain matching edge cases, policy validation, CTAP2 assertion verification (including replay/UV/signature failure) |
| `xkey/pkg/gui/services/autofill_service_test.go` | (none) | Search/get/save/ignore flows, enterprise policy overrides, CTAP2 registration/auth, audit-on-deny |
| `xkey/pkg/nativemsg/crypto_test.go`, `pairing_test.go`, `host_test.go`, `protocol_test.go`, `manifest_test.go` | (none) | ECDH handshake, pairing ceremony + lockouts + migration, host relay loop, wire framing, manifest install/status |
| `xkey/pkg/nativemsg/pairing_limits_test.go` | (none) | Pairing/verify failures and lockouts survive a new host instance over the same state dir, 0600 mode, unpair does not clear a lockout, corrupt/unwritable limits fail closed |
| `xkey/pkg/ipc/server_autofill_test.go`, `autofill_types_test.go` | (none) | IPC dispatch, payload validation |
| `xkey/pkg/gui/services/pairing_service_test.go` | (none) | GUI pairing service, event emission |
| `xkey/cmd/xkey/cmd/extension_test.go`, `extension_serve_test.go`, `extension_serve_policy_test.go`, `extension_agent_piv_test.go` | `ble codec_json` | CLI verbs, headless barrier-strategy handling, enterprise policy wiring |
| `xkey/test/integration/extension/tests/autofill.spec.ts`, `ipc-autofill.spec.ts` | (Playwright, `make integration-test`) | Extension-side end-to-end fill flow |

Run the root-module package tests:

```
GOWORK=off go test ./pkg/autofill/...
```

Run the xkey-side unit tests:

```
cd xkey && GOWORK=off go test ./pkg/nativemsg/... ./pkg/ipc/... ./pkg/gui/services/... -run Autofill
cd xkey && GOWORK=off go test -tags 'ble codec_json' -run TestExtension ./cmd/xkey/cmd/...
```
