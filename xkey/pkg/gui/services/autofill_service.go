// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
)

// AutoFillService errors.
var (
	ErrAutoFillNotConfigured      = errors.New("autofill_service: not configured")
	ErrAutoFillAppLocked          = errors.New("autofill_service: app is locked")
	ErrAutoFillDisabled           = errors.New("autofill_service: browser extension disabled")
	ErrAutoFillRateLimit          = errors.New("autofill_service: rate limit exceeded")
	ErrAutoFillDomainBlocked      = errors.New("autofill_service: domain blocked by policy")
	ErrAutoFillInvalidID          = errors.New("autofill_service: invalid credential ID")
	ErrAutoFillNotFound           = errors.New("autofill_service: credential not found")
	ErrAutoFillAuthFailed         = errors.New("autofill_service: CTAP2 authentication failed")
	ErrAutoFillChallengeRequired  = errors.New("autofill_service: challenge required for authentication")
	ErrAutoFillVerificationFailed = errors.New("autofill_service: assertion verification failed")
	ErrAutoFillPolicyEnforced     = errors.New("autofill_service: setting locked by enterprise policy")
	ErrAutoFillSaveInvalidInput   = errors.New("autofill_service: domain, username, and password are required")
	ErrAutoFillCredentialExists   = errors.New("autofill_service: credential already exists for this domain and username")
	ErrAutoFillDomainIgnored      = errors.New("autofill_service: domain is on the ignored list")
	ErrAutoFillStoreNotConfigured = errors.New("autofill_service: password store not configured")
)

// autofillRPID is the WebAuthn Relying Party ID for autofill credentials.
// This credential appears in the FIDO2 credential management UI as
// "xKey Extension" (ID: "xkey-autofill").
const autofillRPID = "xkey-autofill"

// registrationFile is the filename for persisted autofill credential registration.
const registrationFile = "registration.json"

// Audit operation types for autofill events.
const (
	opAutoFillSearch           audit.OperationType = "autofill_search"
	opAutoFillCredentialAccess audit.OperationType = "autofill_credential_access"
	opAutoFillTOTPAccess       audit.OperationType = "autofill_totp_access"
	opAutoFillAuthentication   audit.OperationType = "autofill_authentication"
	opAutoFillSave             audit.OperationType = "autofill_save"
	opAutoFillIgnoreDomain     audit.OperationType = "autofill_ignore_domain"
)

// autofillRegistration persists the CTAP2 credential registration for
// autofill operations. Stored in ~/.xkey/data/extension/autofill/.
type autofillRegistration struct {
	CredentialID  []byte    `json:"credential_id"`
	PublicKeyCOSE []byte    `json:"public_key_cose"`
	RegisteredAt  time.Time `json:"registered_at"`
}

// EnterpriseExtensionPolicy holds SO-enforced enterprise policy overrides
// for the browser extension. When set, these fields override user-level
// settings and cannot be changed by the user.
type EnterpriseExtensionPolicy struct {
	Enabled               bool
	RequireAuthentication bool
	ForceAudit            bool
	AllowedDomains        []string
	BlockedDomains        []string
	MaxFillsPerMinute     int
}

// AutoFillService mediates credential lookups and TOTP generation for the
// browser extension autofill pipeline. It coordinates between the static
// password store, the OATH store, the app lock, CTAP2 authentication,
// and server-side assertion verification, enforcing domain-based policy,
// rate limiting, and audit logging.
// PolicyPersistFunc is called after policy changes to persist the updated
// policy to the config file. It receives the full current policy.
type PolicyPersistFunc func(policy *autofill.AutoFillPolicy) error

// AutoFillService struct fields.
type AutoFillService struct {
	ctx              context.Context
	log              *slog.Logger
	policy           atomic.Pointer[autofill.AutoFillPolicy]
	passwordSvc      *StaticPasswordService
	oathSvc          *OATHService
	appLockSvc       *AppLockService
	auditStore       audit.Logger
	rateLimiter      *autofill.RateLimiter
	enabled          atomic.Bool // master toggle: browser extension enabled
	auth             *authenticator.Authenticator
	verifier         *autofill.AssertionVerifier
	credID           []byte
	registrationDir  string
	registrationMu   sync.Mutex
	persistPolicy    PolicyPersistFunc
	enterprisePolicy atomic.Pointer[EnterpriseExtensionPolicy]
	ignoredDomains   sync.Map // map[string]bool -- domains the user chose to never save
}

// NewAutoFillService creates a new AutoFillService with secure defaults.
// The master toggle starts disabled; call SetEnabled(true) to activate.
func NewAutoFillService(
	passwordSvc *StaticPasswordService,
	oathSvc *OATHService,
	appLockSvc *AppLockService,
	auditStore audit.Logger,
	logger *slog.Logger,
) *AutoFillService {
	if logger == nil {
		logger = slog.Default()
	}
	defaultPolicy := autofill.DefaultPolicy()
	svc := &AutoFillService{
		log:         logger.With("component", "autofill_service"),
		passwordSvc: passwordSvc,
		oathSvc:     oathSvc,
		appLockSvc:  appLockSvc,
		auditStore:  auditStore,
		rateLimiter: autofill.NewRateLimiter(defaultPolicy.MaxFillsPerMinute),
	}
	svc.policy.Store(defaultPolicy)
	svc.enabled.Store(false)
	return svc
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *AutoFillService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetPolicyPersistFunc sets the callback used to persist policy changes
// to the config file when the user toggles settings in the GUI.
func (s *AutoFillService) SetPolicyPersistFunc(fn PolicyPersistFunc) {
	s.persistPolicy = fn
}

// SetEnabled sets the master toggle. When disabled, all operations return
// ErrAutoFillDisabled. Returns ErrAutoFillPolicyEnforced if enterprise
// policy forbids enabling the extension.
func (s *AutoFillService) SetEnabled(enabled bool) error {
	if enabled {
		if ep := s.enterprisePolicy.Load(); ep != nil && !ep.Enabled {
			return ErrAutoFillPolicyEnforced
		}
	}
	s.enabled.Store(enabled)
	return nil
}

// IsEnabled reports whether the autofill extension is enabled.
func (s *AutoFillService) IsEnabled() bool {
	return s.enabled.Load()
}

// SetAuthenticator sets the shared FIDO2 authenticator used for CTAP2
// challenge-response authentication. This is the same authenticator
// that powers the USB virtual device and WebAuthn operations.
func (s *AutoFillService) SetAuthenticator(auth *authenticator.Authenticator) {
	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()
	s.auth = auth
	// Reset registration state so it reloads with the new authenticator.
	s.verifier = nil
	s.credID = nil
}

// SetRegistrationDir sets the directory where autofill credential
// registration state is persisted (e.g., ~/.xkey/data/extension/autofill/).
func (s *AutoFillService) SetRegistrationDir(dir string) {
	s.registrationDir = dir
}

// SetEnterprisePolicy sets the SO enterprise policy overrides. When set,
// these override user-level settings and cannot be changed by the user.
// Enterprise domain block lists are always enforced on top of user lists.
func (s *AutoFillService) SetEnterprisePolicy(p *EnterpriseExtensionPolicy) {
	s.enterprisePolicy.Store(p)
	if p != nil {
		s.log.Info("enterprise extension policy applied",
			"enabled", p.Enabled,
			"require_auth", p.RequireAuthentication,
			"force_audit", p.ForceAudit,
			"max_fills_per_minute", p.MaxFillsPerMinute,
		)
		if p.MaxFillsPerMinute > 0 {
			s.rateLimiter.SetLimit(p.MaxFillsPerMinute)
		}
	}
}

// GetEnterprisePolicy returns the current enterprise policy, or nil if none.
func (s *AutoFillService) GetEnterprisePolicy() *EnterpriseExtensionPolicy {
	return s.enterprisePolicy.Load()
}

// SetPolicy validates and stores a new autofill policy, updating the rate
// limiter limit to match.
func (s *AutoFillService) SetPolicy(policy *autofill.AutoFillPolicy) error {
	if policy == nil {
		return ErrAutoFillNotConfigured
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	s.policy.Store(policy)
	s.rateLimiter.SetLimit(policy.MaxFillsPerMinute)
	return nil
}

// GetPolicy returns the current autofill policy.
func (s *AutoFillService) GetPolicy() *autofill.AutoFillPolicy {
	return s.policy.Load()
}

// GetRequireAuthentication returns whether CTAP2 authentication is required
// for autofill operations. This is the value behind the GUI toggle.
func (s *AutoFillService) GetRequireAuthentication() bool {
	return s.policy.Load().RequireAuthentication
}

// SetRequireAuthentication updates the RequireAuthentication flag on the
// current policy and persists it to the config file if a persist callback
// is registered. Returns ErrAutoFillPolicyEnforced if enterprise policy
// requires authentication and the caller attempts to disable it.
func (s *AutoFillService) SetRequireAuthentication(required bool) error {
	if !required {
		if ep := s.enterprisePolicy.Load(); ep != nil && ep.RequireAuthentication {
			return ErrAutoFillPolicyEnforced
		}
	}
	p := s.policy.Load()
	updated := *p
	updated.RequireAuthentication = required
	s.policy.Store(&updated)
	s.log.Info("autofill authentication requirement changed", "require_authentication", required)
	if s.persistPolicy != nil {
		return s.persistPolicy(&updated)
	}
	return nil
}

// SearchCredentials searches all stored passwords for entries whose URL
// matches the given domain, and cross-references OATH accounts to indicate
// TOTP availability on each result.
func (s *AutoFillService) SearchCredentials(domain string) ([]ipc.AutofillCredential, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillSearch, domain, err)
		return nil, err
	}

	if !s.rateLimiter.Allow() {
		return nil, ErrAutoFillRateLimit
	}

	policy := s.policy.Load()
	if !policy.IsDomainAllowed(domain) {
		return nil, ErrAutoFillDomainBlocked
	}

	// Enterprise domain restrictions override user policy.
	if ep := s.enterprisePolicy.Load(); ep != nil {
		if !s.isEnterpriseDomainAllowed(ep, domain) {
			return nil, ErrAutoFillDomainBlocked
		}
	}

	entries, err := s.passwordSvc.ListPasswords()
	if err != nil {
		return nil, err
	}

	// Prefetch OATH accounts once for cross-referencing.
	var oathAccounts []OATHAccount
	if s.oathSvc != nil {
		oathAccounts, _ = s.oathSvc.ListAccounts()
	}

	results := make([]ipc.AutofillCredential, 0)
	for _, entry := range entries {
		if entry.URL == "" {
			continue
		}
		if !autofill.MatchesEntry(domain, entry.URL, entry.MatchPatterns) {
			continue
		}
		hasTotp, totpID := s.matchOATHAccount(domain, oathAccounts)
		results = append(results, ipc.AutofillCredential{
			ID:       entry.ID,
			Title:    entry.Title,
			Username: entry.Username,
			URL:      entry.URL,
			HasTOTP:  hasTotp,
			TOTPID:   totpID,
		})
	}

	auditEnabled := policy.AuditEnabled
	if ep := s.enterprisePolicy.Load(); ep != nil && ep.ForceAudit {
		auditEnabled = true
	}
	if s.auditStore != nil && auditEnabled {
		s.auditStore.LogServiceEvent(opAutoFillSearch, map[string]any{
			"domain":  domain,
			"matches": len(results),
		})
	}

	return results, nil
}

// GetCredential retrieves a credential's username and password for form
// filling. When the policy requires authentication, a CTAP2 challenge-response
// flow is performed: the authenticator prompts for PIN and touch in the
// desktop app (or via phone biometrics), signs the challenge, and the
// assertion is verified server-side before credentials are released.
func (s *AutoFillService) GetCredential(id, challenge string) (*ipc.AutofillFillResult, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillCredentialAccess, id, err)
		return nil, err
	}
	if id == "" {
		return nil, ErrAutoFillInvalidID
	}
	if !s.rateLimiter.Allow() {
		return nil, ErrAutoFillRateLimit
	}

	policy := s.policy.Load()
	var assertion *ipc.AutofillAssertion

	// Enterprise policy can force authentication even if user disabled it.
	requireAuth := policy.RequireAuthentication
	if ep := s.enterprisePolicy.Load(); ep != nil && ep.RequireAuthentication {
		requireAuth = true
	}

	if requireAuth {
		if challenge == "" {
			return nil, ErrAutoFillChallengeRequired
		}
		if s.auth == nil {
			return nil, ErrAutoFillNotConfigured
		}

		var err error
		assertion, err = s.authenticateWithCTAP2(challenge)
		if err != nil {
			return nil, err
		}
	}

	entry, err := s.passwordSvc.GetPassword(id)
	if err != nil {
		return nil, ErrAutoFillNotFound
	}

	auditEnabled := policy.AuditEnabled
	if ep := s.enterprisePolicy.Load(); ep != nil && ep.ForceAudit {
		auditEnabled = true
	}
	if s.auditStore != nil && auditEnabled {
		s.auditStore.LogServiceEvent(opAutoFillCredentialAccess, map[string]any{
			"credential_id":      id,
			"assertion_verified": assertion != nil,
		})
	}

	return &ipc.AutofillFillResult{
		Username:  entry.Username,
		Password:  entry.Password,
		Assertion: assertion,
	}, nil
}

// SaveCredential saves a new credential from a browser form submission.
// It checks preconditions, validates inputs, deduplicates against existing
// entries by domain + username, and creates the entry via the password store.
func (s *AutoFillService) SaveCredential(domain, username, password, title string) (*ipc.AutofillResult, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillSave, domain, err)
		return nil, err
	}

	if domain == "" || username == "" || password == "" {
		return nil, ErrAutoFillSaveInvalidInput
	}

	if s.passwordSvc == nil {
		return nil, ErrAutoFillStoreNotConfigured
	}

	// Check if the domain is on the ignored list.
	if s.IsIgnoredDomain(domain) {
		return nil, ErrAutoFillDomainIgnored
	}

	// Check for existing credential with same domain + username.
	entries, err := s.passwordSvc.ListPasswords()
	if err != nil {
		return nil, err
	}

	url := "https://" + domain
	for _, entry := range entries {
		if entry.URL == "" {
			continue
		}
		if autofill.MatchesEntry(domain, entry.URL, entry.MatchPatterns) &&
			strings.EqualFold(entry.Username, username) {
			return &ipc.AutofillResult{Exists: true}, nil
		}
	}

	// Determine the title: use provided title, fall back to domain.
	entryTitle := title
	if entryTitle == "" {
		entryTitle = domain
	}

	// Create the credential via the password service.
	pw := &staticpw.StaticPassword{
		Name:     entryTitle,
		Title:    entryTitle,
		Username: username,
		Password: password,
		URL:      url,
	}
	if addErr := s.passwordSvc.store.Add(pw); addErr != nil {
		return nil, addErr
	}

	// Audit log the save operation.
	policy := s.policy.Load()
	auditEnabled := policy.AuditEnabled
	if ep := s.enterprisePolicy.Load(); ep != nil && ep.ForceAudit {
		auditEnabled = true
	}
	if s.auditStore != nil && auditEnabled {
		s.auditStore.LogServiceEvent(opAutoFillSave, map[string]any{
			"domain":   domain,
			"username": username,
		})
	}

	s.log.Info("credential saved from browser extension",
		"domain", domain,
		"username", username)

	return &ipc.AutofillResult{Saved: true}, nil
}

// IgnoreDomain adds a domain to the ignored list so the extension will not
// prompt to save credentials for it. The list is stored in-memory.
func (s *AutoFillService) IgnoreDomain(domain string) (*ipc.AutofillResult, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillIgnoreDomain, domain, err)
		return nil, err
	}

	if domain == "" {
		return nil, fmt.Errorf("%w: domain is required", ErrAutoFillSaveInvalidInput)
	}

	s.ignoredDomains.Store(strings.ToLower(domain), true)

	// Audit log the ignore operation.
	policy := s.policy.Load()
	auditEnabled := policy.AuditEnabled
	if ep := s.enterprisePolicy.Load(); ep != nil && ep.ForceAudit {
		auditEnabled = true
	}
	if s.auditStore != nil && auditEnabled {
		s.auditStore.LogServiceEvent(opAutoFillIgnoreDomain, map[string]any{
			"domain": domain,
		})
	}

	s.log.Info("domain added to ignore list", "domain", domain)

	return &ipc.AutofillResult{Saved: true}, nil
}

// IsIgnoredDomain reports whether the given domain is on the ignored list.
func (s *AutoFillService) IsIgnoredDomain(domain string) bool {
	_, ok := s.ignoredDomains.Load(strings.ToLower(domain))
	return ok
}

// GetTOTPForDomain finds an OATH account whose issuer or account name matches
// the given domain, generates a TOTP code, and returns it.
func (s *AutoFillService) GetTOTPForDomain(domain string) (*ipc.AutofillTOTP, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillTOTPAccess, domain, err)
		return nil, err
	}
	if s.oathSvc == nil {
		return nil, ErrAutoFillNotConfigured
	}

	accounts, err := s.oathSvc.ListAccounts()
	if err != nil {
		return nil, err
	}

	hasMatch, totpID := s.matchOATHAccount(domain, accounts)
	if !hasMatch {
		return nil, ErrAutoFillNotFound
	}

	return s.generateAndAuditTOTP(totpID)
}

// GetTOTPByID generates a TOTP code for the given OATH account ID.
func (s *AutoFillService) GetTOTPByID(id string) (*ipc.AutofillTOTP, error) {
	if err := s.checkPreconditions(); err != nil {
		s.auditPreconditionFailure(opAutoFillTOTPAccess, id, err)
		return nil, err
	}
	if s.oathSvc == nil {
		return nil, ErrAutoFillNotConfigured
	}
	if id == "" {
		return nil, ErrAutoFillInvalidID
	}

	return s.generateAndAuditTOTP(id)
}

// GetStatus returns the current autofill system state.
func (s *AutoFillService) GetStatus() *ipc.AutofillStatus {
	policy := s.policy.Load()
	appLocked := false
	if s.appLockSvc != nil {
		appLocked = s.appLockSvc.IsLocked()
	}
	return &ipc.AutofillStatus{
		Available:        s.passwordSvc != nil,
		AppLocked:        appLocked,
		FillMode:         string(policy.FillMode),
		ExtensionEnabled: s.enabled.Load(),
	}
}

// GetAutoFillPolicy converts the internal policy to the IPC result type.
func (s *AutoFillService) GetAutoFillPolicy() *ipc.AutofillPolicyResult {
	policy := s.policy.Load()
	return &ipc.AutofillPolicyResult{
		FillMode:              string(policy.FillMode),
		TOTPPolicy:            string(policy.TOTPPolicy),
		SessionTimeoutSec:     policy.SessionTimeoutSec,
		RequireAuthentication: policy.RequireAuthentication,
		AllowedDomains:        policy.AllowedDomains,
		BlockedDomains:        policy.BlockedDomains,
		MaxFillsPerMinute:     policy.MaxFillsPerMinute,
		AuditEnabled:          policy.AuditEnabled,
	}
}

// ---------------------------------------------------------------------------
// IPC AutofillHandler interface implementation
// ---------------------------------------------------------------------------

// HandleAutofillSearch implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillSearch(domain string) (*ipc.AutofillResult, error) {
	creds, err := s.SearchCredentials(domain)
	if err != nil {
		return nil, err
	}
	return &ipc.AutofillResult{Credentials: creds}, nil
}

// HandleAutofillGet implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillGet(id, challenge string) (*ipc.AutofillResult, error) {
	fill, err := s.GetCredential(id, challenge)
	if err != nil {
		return nil, err
	}
	return &ipc.AutofillResult{Fill: fill}, nil
}

// HandleAutofillTOTP implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillTOTP(domain string) (*ipc.AutofillResult, error) {
	totp, err := s.GetTOTPForDomain(domain)
	if err != nil {
		return nil, err
	}
	return &ipc.AutofillResult{TOTP: totp}, nil
}

// HandleAutofillTOTPByID implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillTOTPByID(id string) (*ipc.AutofillResult, error) {
	totp, err := s.GetTOTPByID(id)
	if err != nil {
		return nil, err
	}
	return &ipc.AutofillResult{TOTP: totp}, nil
}

// HandleAutofillStatus implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillStatus() (*ipc.AutofillResult, error) {
	status := s.GetStatus()
	return &ipc.AutofillResult{Status: status}, nil
}

// HandleAutofillPolicy implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillPolicy() (*ipc.AutofillResult, error) {
	policy := s.GetAutoFillPolicy()
	return &ipc.AutofillResult{Policy: policy}, nil
}

// HandleAutofillSave implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillSave(domain, username, password, title string) (*ipc.AutofillResult, error) {
	return s.SaveCredential(domain, username, password, title)
}

// HandleAutofillIgnoreDomain implements ipc.AutofillHandler.
func (s *AutoFillService) HandleAutofillIgnoreDomain(domain string) (*ipc.AutofillResult, error) {
	return s.IgnoreDomain(domain)
}

// HandleAutofillFocus implements ipc.AutofillHandler. The service layer has no
// knowledge of the GUI window; the caller (guiIPCHandler) is responsible for
// raising the window. This method exists solely to satisfy the interface.
func (s *AutoFillService) HandleAutofillFocus() (*ipc.AutofillResult, error) {
	return &ipc.AutofillResult{}, nil
}

// ---------------------------------------------------------------------------
// CTAP2 authentication
// ---------------------------------------------------------------------------

// authenticateWithCTAP2 performs CTAP2 challenge-response authentication.
// It ensures a credential is registered, calls GetAssertion on the shared
// authenticator (which triggers PIN + touch in the GUI), and verifies the
// assertion server-side.
func (s *AutoFillService) authenticateWithCTAP2(challenge string) (*ipc.AutofillAssertion, error) {
	if err := s.ensureRegistered(); err != nil {
		return nil, err
	}

	challengeBytes, err := base64.StdEncoding.DecodeString(challenge)
	if err != nil {
		return nil, fmt.Errorf("%w: invalid challenge encoding", ErrAutoFillAuthFailed)
	}

	clientDataHash := sha256.Sum256(challengeBytes)

	allowList := []authenticator.CredentialDescriptor{
		{Type: "public-key", ID: s.credID},
	}

	// Use the authenticator's internal PIN hash to bypass the CTAP2 clientPin
	// ECDH ceremony. This is safe because the autofill service is a trusted
	// in-process caller — the PIN hash is never exposed over IPC or USB.
	pinHash := s.auth.GetState().PINHash

	resp, err := s.auth.GetAssertion(
		clientDataHash[:],
		autofillRPID,
		allowList,
		&authenticator.GetAssertionOptions{
			Options:         map[string]bool{"up": true, "uv": true},
			InternalPINHash: pinHash,
		},
	)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrAutoFillAuthFailed, err)
	}

	if err := s.verifier.Verify(resp.AuthData, resp.Signature, clientDataHash[:]); err != nil {
		s.log.Warn("CTAP2 assertion verification failed",
			"error", err)
		return nil, fmt.Errorf("%w: %v", ErrAutoFillVerificationFailed, err)
	}

	if s.auditStore != nil {
		s.auditStore.LogServiceEvent(opAutoFillAuthentication, map[string]any{
			"assertion_verified": true,
		})
	}

	return &ipc.AutofillAssertion{
		AuthData:     base64.StdEncoding.EncodeToString(resp.AuthData),
		Signature:    base64.StdEncoding.EncodeToString(resp.Signature),
		CredentialID: base64.StdEncoding.EncodeToString(s.credID),
	}, nil
}

// ensureRegistered ensures a CTAP2 credential is registered for autofill.
// On first call, it either loads the registration from disk or creates a
// new credential via MakeCredential. Subsequent calls are a fast no-op.
func (s *AutoFillService) ensureRegistered() error {
	// Fast path: already initialized.
	if s.verifier != nil && s.credID != nil {
		return nil
	}

	s.registrationMu.Lock()
	defer s.registrationMu.Unlock()

	// Double-check after acquiring lock.
	if s.verifier != nil && s.credID != nil {
		return nil
	}

	// Try loading from persisted state.
	if s.loadRegistration() {
		return nil
	}

	// Register a new credential.
	return s.registerCredential()
}

// registerCredential creates a new discoverable CTAP2 credential for the
// autofill RP, extracts the credential ID and COSE public key from the
// attested auth data, creates a verifier, and persists the registration.
func (s *AutoFillService) registerCredential() error {
	if s.auth == nil {
		return ErrAutoFillNotConfigured
	}

	clientDataHash := sha256.Sum256([]byte("xkey-autofill-registration"))

	// Use the authenticator's internal PIN hash to bypass the CTAP2 clientPin
	// ECDH ceremony. This is safe because the autofill service is a trusted
	// in-process caller — the PIN hash is never exposed over IPC or USB.
	regPINHash := s.auth.GetState().PINHash

	resp, err := s.auth.MakeCredential(
		clientDataHash[:],
		authenticator.RelyingParty{
			ID:   autofillRPID,
			Name: "xKey Extension",
		},
		authenticator.User{
			ID:          []byte("xkey-autofill-user"),
			Name:        "xKey AutoFill",
			DisplayName: "xKey AutoFill",
		},
		[]authenticator.PublicKeyCredentialParam{
			{Type: "public-key", Alg: authenticator.COSEAlgES256},
		},
		&authenticator.MakeCredentialOptions{
			Options:         map[string]bool{"rk": true, "uv": true},
			InternalPINHash: regPINHash,
		},
	)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAutoFillAuthFailed, err)
	}

	authData, err := authenticator.ParseAuthData(resp.AuthData)
	if err != nil {
		return fmt.Errorf("%w: failed to parse auth data: %v", ErrAutoFillAuthFailed, err)
	}

	if !authData.HasAttestedCredentialData() {
		return fmt.Errorf("%w: no attested credential data in response", ErrAutoFillAuthFailed)
	}

	s.credID = authData.CredentialID
	pubKeyCOSE := authData.PublicKey

	verifier, err := autofill.NewAssertionVerifier(autofillRPID, pubKeyCOSE)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrAutoFillAuthFailed, err)
	}
	s.verifier = verifier

	s.saveRegistration(pubKeyCOSE)

	s.log.Info("autofill CTAP2 credential registered",
		"rp_id", autofillRPID,
		"cred_id_len", len(s.credID))

	return nil
}

// loadRegistration attempts to load the autofill credential registration
// from the persisted JSON file. Returns true if successfully loaded.
func (s *AutoFillService) loadRegistration() bool {
	if s.registrationDir == "" {
		return false
	}

	data, err := os.ReadFile(filepath.Join(s.registrationDir, registrationFile))
	if err != nil {
		return false
	}

	var reg autofillRegistration
	if err := json.Unmarshal(data, &reg); err != nil {
		s.log.Warn("failed to parse autofill registration file", "error", err)
		return false
	}

	if len(reg.CredentialID) == 0 || len(reg.PublicKeyCOSE) == 0 {
		return false
	}

	verifier, err := autofill.NewAssertionVerifier(autofillRPID, reg.PublicKeyCOSE)
	if err != nil {
		s.log.Warn("failed to create verifier from stored registration", "error", err)
		return false
	}

	s.credID = reg.CredentialID
	s.verifier = verifier

	s.log.Info("loaded autofill CTAP2 registration from disk",
		"registered_at", reg.RegisteredAt)

	return true
}

// saveRegistration persists the autofill credential registration to disk.
// Errors are logged but do not prevent the service from operating (the
// credential will be re-registered on next restart).
func (s *AutoFillService) saveRegistration(pubKeyCOSE []byte) {
	if s.registrationDir == "" {
		return
	}

	reg := autofillRegistration{
		CredentialID:  s.credID,
		PublicKeyCOSE: pubKeyCOSE,
		RegisteredAt:  time.Now(),
	}

	data, err := json.Marshal(reg)
	if err != nil {
		s.log.Error("failed to marshal autofill registration", "error", err)
		return
	}

	if err := os.MkdirAll(s.registrationDir, 0700); err != nil {
		s.log.Error("failed to create autofill registration dir", "error", err)
		return
	}

	if err := os.WriteFile(filepath.Join(s.registrationDir, registrationFile), data, 0600); err != nil {
		s.log.Error("failed to write autofill registration", "error", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// checkPreconditions verifies the master toggle, enterprise policy, and
// app lock state.
func (s *AutoFillService) checkPreconditions() error {
	// Enterprise policy can disable the extension entirely.
	if ep := s.enterprisePolicy.Load(); ep != nil && !ep.Enabled {
		return ErrAutoFillDisabled
	}
	if !s.enabled.Load() {
		return ErrAutoFillDisabled
	}
	if s.appLockSvc != nil && s.appLockSvc.IsLocked() {
		return ErrAutoFillAppLocked
	}
	return nil
}

// auditPreconditionFailure logs a security-relevant audit entry when an
// autofill operation is denied due to the extension being disabled, the
// app being locked, or a policy enforcement. These events are always
// logged regardless of the user's audit-enabled setting.
func (s *AutoFillService) auditPreconditionFailure(op audit.OperationType, detail string, err error) {
	if s.auditStore == nil {
		return
	}
	s.auditStore.LogServiceEvent(op, map[string]any{
		"denied": true,
		"reason": err.Error(),
		"detail": detail,
	})
}

// isEnterpriseDomainAllowed checks the enterprise domain allow/block lists.
// Enterprise blocked domains always block. If enterprise allowed domains are
// specified, they restrict the universe (domain must be in the allow list).
func (s *AutoFillService) isEnterpriseDomainAllowed(ep *EnterpriseExtensionPolicy, domain string) bool {
	domainLower := strings.ToLower(domain)
	for _, blocked := range ep.BlockedDomains {
		if strings.ToLower(blocked) == domainLower {
			return false
		}
	}
	if len(ep.AllowedDomains) > 0 {
		for _, allowed := range ep.AllowedDomains {
			if strings.ToLower(allowed) == domainLower {
				return true
			}
		}
		return false
	}
	return true
}

// matchOATHAccount checks whether any OATH account matches the given domain
// by comparing the lowercase issuer against the domain base (domain without
// the TLD). Returns whether a match was found and the matching account's ID.
func (s *AutoFillService) matchOATHAccount(domain string, accounts []OATHAccount) (bool, string) {
	domainBase := extractDomainBase(domain)
	if domainBase == "" {
		return false, ""
	}
	for _, acct := range accounts {
		if acct.Type != "totp" {
			continue
		}
		issuerLower := strings.ToLower(acct.Issuer)
		accountLower := strings.ToLower(acct.AccountName)
		if strings.Contains(issuerLower, domainBase) || strings.Contains(domainBase, issuerLower) {
			return true, acct.ID
		}
		if strings.Contains(accountLower, domainBase) {
			return true, acct.ID
		}
	}
	return false, ""
}

// extractDomainBase strips the TLD (last dot-segment) from a domain,
// returning the base for fuzzy matching. For example, "github.com" becomes
// "github". Returns the input unchanged if no dot is present.
func extractDomainBase(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return ""
	}
	idx := strings.LastIndex(domain, ".")
	if idx <= 0 {
		return domain
	}
	return domain[:idx]
}

// generateAndAuditTOTP generates a TOTP code for the given account ID,
// converts it to the IPC type, and writes an audit log entry.
func (s *AutoFillService) generateAndAuditTOTP(id string) (*ipc.AutofillTOTP, error) {
	code, err := s.oathSvc.GenerateTOTP(id)
	if err != nil {
		return nil, err
	}

	policy := s.policy.Load()
	if s.auditStore != nil && policy.AuditEnabled {
		s.auditStore.LogServiceEvent(opAutoFillTOTPAccess, map[string]any{
			"account_id": id,
		})
	}

	// Resolve the issuer for the response.
	issuer := ""
	if accounts, listErr := s.oathSvc.ListAccounts(); listErr == nil {
		for _, acct := range accounts {
			if acct.ID == id {
				issuer = acct.Issuer
				break
			}
		}
	}

	return &ipc.AutofillTOTP{
		Code:      code.Code,
		TimeLeft:  code.TimeLeft,
		Period:    code.Period,
		AccountID: code.AccountID,
		Issuer:    issuer,
	}, nil
}

// Compile-time interface satisfaction check.
var _ ipc.AutofillHandler = (*AutoFillService)(nil)
