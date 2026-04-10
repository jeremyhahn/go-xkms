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
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// autofillMockPINBackend is a minimal PINBackend for autofill tests that verifies
// against a single valid PIN. Used by AppLockService, not by AutoFillService.
type autofillMockPINBackend struct {
	validPIN string
}

func (m *autofillMockPINBackend) SOPINSet() bool                       { return true }
func (m *autofillMockPINBackend) UserPINSet() bool                     { return true }
func (m *autofillMockPINBackend) IsInitialized() bool                  { return true }
func (m *autofillMockPINBackend) Strategy() pin.StrategyID             { return pin.StrategySoftware }
func (m *autofillMockPINBackend) SetSOPIN(_, _ string) error           { return nil }
func (m *autofillMockPINBackend) SetUserPIN(_, _ string) error         { return nil }
func (m *autofillMockPINBackend) ChangeSOPIN(_, _ string) error        { return nil }
func (m *autofillMockPINBackend) ChangeUserPIN(_, _ string) error      { return nil }
func (m *autofillMockPINBackend) VerifySOPIN(_ string) error           { return nil }
func (m *autofillMockPINBackend) ResetLockout(_ string) error          { return nil }
func (m *autofillMockPINBackend) SetMaxAttempts(_ int)                 {}
func (m *autofillMockPINBackend) GetLockoutStatus() *pin.LockoutStatus { return &pin.LockoutStatus{} }

func (m *autofillMockPINBackend) VerifyUserPIN(userPIN string) error {
	if userPIN == m.validPIN {
		return nil
	}
	return errors.New("pin: invalid user PIN")
}

// autofillMockBarrier is a minimal barrier implementation for autofill tests.
type autofillMockBarrier struct {
	unsealed bool
}

func (m *autofillMockBarrier) IsInitialized() bool          { return true }
func (m *autofillMockBarrier) IsUnsealed() bool             { return m.unsealed }
func (m *autofillMockBarrier) Unseal(_, _ string) error     { return nil }
func (m *autofillMockBarrier) Initialize(_, _ string) error { return nil }

// newTestAutoFillService creates a fully wired AutoFillService for testing.
// It populates the static password store with test entries and the OATH
// store with a test TOTP credential.
func newTestAutoFillService(t *testing.T) (*AutoFillService, *audit.BackendStore) {
	t.Helper()

	// Static password store backed by in-memory storage.
	memBackend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	pwStore := staticpw.NewStore(memBackend)

	// Add test passwords.
	require.NoError(t, pwStore.Add(&staticpw.StaticPassword{
		Name:     "GitHub",
		Password: "gh-secret-123",
		Username: "octocat",
		URL:      "https://github.com",
	}))
	require.NoError(t, pwStore.Add(&staticpw.StaticPassword{
		Name:     "GitLab",
		Password: "gl-secret-456",
		Username: "gluser",
		URL:      "https://gitlab.com",
	}))
	require.NoError(t, pwStore.Add(&staticpw.StaticPassword{
		Name:     "No URL Entry",
		Password: "nope",
		Username: "nourl",
	}))

	passwordSvc := NewStaticPasswordService(pwStore)

	// OATH store with a matching GitHub TOTP credential.
	oathStore := oath.NewMemoryStore()
	require.NoError(t, oathStore.Add(&oath.Credential{
		ID:          "github:octocat",
		Name:        "GitHub (octocat)",
		Issuer:      "GitHub",
		AccountName: "octocat",
		Secret:      "JBSWY3DPEHPK3PXP",
		Type:        oath.TypeTOTP,
		Algorithm:   oath.AlgorithmSHA1,
		Digits:      6,
		Period:      30,
	}))
	oathSvc := NewOATHService(oathStore)

	// PIN service with a mock backend (for AppLockService).
	pinSvc := NewPINService()
	backend := &autofillMockPINBackend{validPIN: "123456"}
	pSvc := pin.NewService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	// App lock service starts unlocked.
	appLockSvc := NewAppLockService(pinSvc, &autofillMockBarrier{unsealed: true})

	// Audit store.
	auditStore, auditErr := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, auditErr)

	svc := NewAutoFillService(passwordSvc, oathSvc, appLockSvc, auditStore, slog.Default())
	svc.SetContext(context.Background())
	require.NoError(t, svc.SetEnabled(true))

	// Disable authentication by default for unit tests that don't
	// need the full CTAP2 flow.
	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = false
	require.NoError(t, svc.SetPolicy(policy))

	return svc, auditStore
}

// ---------------------------------------------------------------------------
// Constructor and lifecycle tests
// ---------------------------------------------------------------------------

func TestAutoFillService_New(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	assert.NotNil(t, svc)
	assert.False(t, svc.IsEnabled(), "must start disabled")
}

func TestAutoFillService_SetContext(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	svc.SetContext(context.Background())
	assert.NotNil(t, svc.ctx)
}

func TestAutoFillService_EnableDisable(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	require.NoError(t, svc.SetEnabled(true))
	assert.True(t, svc.IsEnabled())

	require.NoError(t, svc.SetEnabled(false))
	assert.False(t, svc.IsEnabled())
}

// ---------------------------------------------------------------------------
// Policy tests
// ---------------------------------------------------------------------------

func TestAutoFillService_SetPolicy(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	policy := autofill.DefaultPolicy()
	policy.FillMode = autofill.FillModeAutoFill
	policy.MaxFillsPerMinute = 20

	err := svc.SetPolicy(policy)
	require.NoError(t, err)

	got := svc.GetPolicy()
	assert.Equal(t, autofill.FillModeAutoFill, got.FillMode)
	assert.Equal(t, 20, got.MaxFillsPerMinute)
}

func TestAutoFillService_SetPolicy_Nil(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	err := svc.SetPolicy(nil)
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestAutoFillService_SetPolicy_Invalid(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	policy := &autofill.AutoFillPolicy{
		FillMode: "bogus",
	}
	err := svc.SetPolicy(policy)
	assert.Error(t, err)
}

func TestAutoFillService_GetAutoFillPolicy(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	result := svc.GetAutoFillPolicy()
	assert.NotNil(t, result)
	assert.Equal(t, string(autofill.FillModeClickToFill), result.FillMode)
	assert.Equal(t, string(autofill.TOTPPolicyPrompt), result.TOTPPolicy)
	assert.True(t, result.RequireAuthentication)
}

// ---------------------------------------------------------------------------
// SearchCredentials tests
// ---------------------------------------------------------------------------

func TestAutoFillService_SearchCredentials_MatchingDomain(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	results, err := svc.SearchCredentials("github.com")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "octocat", results[0].Username)
	assert.True(t, results[0].HasTOTP, "should detect matching OATH TOTP")
	assert.Equal(t, "github:octocat", results[0].TOTPID)

	// Verify audit log was written.
	assert.Greater(t, auditStore.Count(), 0)
}

func TestAutoFillService_SearchCredentials_NoMatch(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	results, err := svc.SearchCredentials("example.org")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestAutoFillService_SearchCredentials_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.SearchCredentials("github.com")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_SearchCredentials_AppLocked(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	svc.appLockSvc.LockForStartup()

	_, err := svc.SearchCredentials("github.com")
	assert.ErrorIs(t, err, ErrAutoFillAppLocked)
}

func TestAutoFillService_SearchCredentials_BlockedDomain(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = false
	policy.BlockedDomains = []string{"github.com"}
	require.NoError(t, svc.SetPolicy(policy))

	_, err := svc.SearchCredentials("github.com")
	assert.ErrorIs(t, err, ErrAutoFillDomainBlocked)
}

func TestAutoFillService_SearchCredentials_RateLimit(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Set a very restrictive rate limit.
	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = false
	policy.MaxFillsPerMinute = 1
	require.NoError(t, svc.SetPolicy(policy))

	// First call should succeed.
	_, err := svc.SearchCredentials("github.com")
	require.NoError(t, err)

	// Second call should be rate limited.
	_, err = svc.SearchCredentials("github.com")
	assert.ErrorIs(t, err, ErrAutoFillRateLimit)
}

// ---------------------------------------------------------------------------
// GetCredential tests (no CTAP2 auth)
// ---------------------------------------------------------------------------

func TestAutoFillService_GetCredential(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	// Look up the GitHub entry by listing first to get the generated ID.
	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	result, err := svc.GetCredential(githubID, "")
	require.NoError(t, err)
	assert.Equal(t, "octocat", result.Username)
	assert.Equal(t, "gh-secret-123", result.Password)
	assert.Nil(t, result.Assertion, "no assertion when auth disabled")
	assert.Greater(t, auditStore.Count(), 0)
}

func TestAutoFillService_GetCredential_EmptyID(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	_, err := svc.GetCredential("", "")
	assert.ErrorIs(t, err, ErrAutoFillInvalidID)
}

func TestAutoFillService_GetCredential_NotFound(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	_, err := svc.GetCredential("nonexistent-id", "")
	assert.ErrorIs(t, err, ErrAutoFillNotFound)
}

func TestAutoFillService_GetCredential_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.GetCredential("any-id", "")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

// ---------------------------------------------------------------------------
// GetCredential tests (CTAP2 auth required)
// ---------------------------------------------------------------------------

func TestAutoFillService_GetCredential_AuthRequired_NoChallengeReturnsError(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = true
	require.NoError(t, svc.SetPolicy(policy))

	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	// No challenge provided when auth is required.
	_, err = svc.GetCredential(githubID, "")
	assert.ErrorIs(t, err, ErrAutoFillChallengeRequired)
}

func TestAutoFillService_GetCredential_AuthRequired_NoAuthenticatorReturnsError(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = true
	require.NoError(t, svc.SetPolicy(policy))

	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	// Challenge provided but no authenticator set.
	_, err = svc.GetCredential(githubID, "dGVzdC1jaGFsbGVuZ2U=")
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestAutoFillService_GetCredential_AuthRequired_InvalidChallengeEncoding(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = true
	require.NoError(t, svc.SetPolicy(policy))

	// Set a non-nil authenticator to get past the nil check.
	// The challenge decoding error should occur before GetAssertion is called.
	// We need a real authenticator to test this path, but since we just need
	// to get past ensureRegistered, let's use a real one with auto-approve.
	auth := createTestAuthenticatorForAutofill(t)
	svc.SetAuthenticator(auth)

	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	// Invalid base64 challenge.
	_, err = svc.GetCredential(githubID, "!!!invalid-base64!!!")
	assert.ErrorIs(t, err, ErrAutoFillAuthFailed)
}

// ---------------------------------------------------------------------------
// SetAuthenticator tests
// ---------------------------------------------------------------------------

func TestAutoFillService_SetAuthenticator(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	assert.Nil(t, svc.auth)

	auth := createTestAuthenticatorForAutofill(t)
	svc.SetAuthenticator(auth)
	assert.NotNil(t, svc.auth)
	assert.Equal(t, auth, svc.auth)
}

func TestAutoFillService_SetAuthenticator_ResetsRegistration(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	// Simulate existing registration state.
	svc.credID = []byte("old-cred")
	svc.verifier = &autofill.AssertionVerifier{}

	auth := createTestAuthenticatorForAutofill(t)
	svc.SetAuthenticator(auth)

	// Registration state should be cleared.
	assert.Nil(t, svc.verifier)
	assert.Nil(t, svc.credID)
}

// ---------------------------------------------------------------------------
// GetTOTPForDomain tests
// ---------------------------------------------------------------------------

func TestAutoFillService_GetTOTPForDomain(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	totp, err := svc.GetTOTPForDomain("github.com")
	require.NoError(t, err)
	assert.NotEmpty(t, totp.Code)
	assert.Equal(t, 30, totp.Period)
	assert.Equal(t, "github:octocat", totp.AccountID)
	assert.Equal(t, "GitHub", totp.Issuer)
	assert.Greater(t, auditStore.Count(), 0)
}

func TestAutoFillService_GetTOTPForDomain_NoMatch(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.GetTOTPForDomain("unknown-domain.org")
	assert.ErrorIs(t, err, ErrAutoFillNotFound)
}

func TestAutoFillService_GetTOTPForDomain_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.GetTOTPForDomain("github.com")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_GetTOTPForDomain_NilOATHService(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	svc.oathSvc = nil

	_, err := svc.GetTOTPForDomain("github.com")
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

// ---------------------------------------------------------------------------
// GetTOTPByID tests
// ---------------------------------------------------------------------------

func TestAutoFillService_GetTOTPByID(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	totp, err := svc.GetTOTPByID("github:octocat")
	require.NoError(t, err)
	assert.NotEmpty(t, totp.Code)
	assert.Equal(t, "github:octocat", totp.AccountID)
	assert.Greater(t, auditStore.Count(), 0)
}

func TestAutoFillService_GetTOTPByID_EmptyID(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.GetTOTPByID("")
	assert.ErrorIs(t, err, ErrAutoFillInvalidID)
}

func TestAutoFillService_GetTOTPByID_NotFound(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.GetTOTPByID("nonexistent")
	assert.Error(t, err)
}

func TestAutoFillService_GetTOTPByID_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.GetTOTPByID("github:octocat")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_GetTOTPByID_NilOATHService(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	svc.oathSvc = nil

	_, err := svc.GetTOTPByID("github:octocat")
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

// ---------------------------------------------------------------------------
// GetStatus tests
// ---------------------------------------------------------------------------

func TestAutoFillService_GetStatus(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	status := svc.GetStatus()
	assert.True(t, status.Available)
	assert.False(t, status.AppLocked)
	assert.True(t, status.ExtensionEnabled)
	assert.Equal(t, string(autofill.FillModeClickToFill), status.FillMode)
}

func TestAutoFillService_GetStatus_Locked(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	svc.appLockSvc.LockForStartup()

	status := svc.GetStatus()
	assert.True(t, status.AppLocked)
}

func TestAutoFillService_GetStatus_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	status := svc.GetStatus()
	assert.False(t, status.ExtensionEnabled)
}

// ---------------------------------------------------------------------------
// IPC Handler tests
// ---------------------------------------------------------------------------

func TestAutoFillService_HandleAutofillSearch(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillSearch("github.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Len(t, result.Credentials, 1)
}

func TestAutoFillService_HandleAutofillGet(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	result, err := svc.HandleAutofillGet(githubID, "")
	require.NoError(t, err)
	require.NotNil(t, result.Fill)
	assert.Equal(t, "octocat", result.Fill.Username)
}

func TestAutoFillService_HandleAutofillTOTP(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillTOTP("github.com")
	require.NoError(t, err)
	require.NotNil(t, result.TOTP)
	assert.NotEmpty(t, result.TOTP.Code)
}

func TestAutoFillService_HandleAutofillTOTPByID(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillTOTPByID("github:octocat")
	require.NoError(t, err)
	require.NotNil(t, result.TOTP)
	assert.NotEmpty(t, result.TOTP.Code)
}

func TestAutoFillService_HandleAutofillStatus(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillStatus()
	require.NoError(t, err)
	require.NotNil(t, result.Status)
	assert.True(t, result.Status.ExtensionEnabled)
}

func TestAutoFillService_HandleAutofillPolicy(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillPolicy()
	require.NoError(t, err)
	require.NotNil(t, result.Policy)
	assert.Equal(t, string(autofill.FillModeClickToFill), result.Policy.FillMode)
}

// ---------------------------------------------------------------------------
// Helper function tests
// ---------------------------------------------------------------------------

func TestExtractDomainBase(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"simple domain", "github.com", "github"},
		{"subdomain", "login.github.com", "login.github"},
		{"no TLD", "localhost", "localhost"},
		{"empty", "", ""},
		{"spaces", "  github.com  ", "github"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expect, extractDomainBase(tt.input))
		})
	}
}

// ---------------------------------------------------------------------------
// Interface satisfaction
// ---------------------------------------------------------------------------

func TestAutoFillService_ImplementsAutofillHandler(t *testing.T) {
	var _ ipc.AutofillHandler = (*AutoFillService)(nil)
}

// ---------------------------------------------------------------------------
// Test authenticator helper
// ---------------------------------------------------------------------------

// createTestAuthenticatorForAutofill creates a minimal in-memory authenticator
// with auto-approve user presence for testing the autofill CTAP2 flow.
func createTestAuthenticatorForAutofill(t *testing.T) *authenticator.Authenticator {
	t.Helper()

	store := authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:             store,
		AAGUID:              [16]byte{0x01, 0x02, 0x03, 0x04},
		EnableResidentKey:   true,
		EnablePIN:           false,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	require.NoError(t, err)

	return auth
}

// ---------------------------------------------------------------------------
// GetRequireAuthentication / SetRequireAuthentication
// ---------------------------------------------------------------------------

func TestAutoFillService_GetRequireAuthentication_Default(t *testing.T) {
	// newTestAutoFillService sets RequireAuthentication=false for unit test isolation.
	svc, _ := newTestAutoFillService(t)
	assert.False(t, svc.GetRequireAuthentication())
}

func TestAutoFillService_GetRequireAuthentication_TrueDefault(t *testing.T) {
	// Verify that a fresh service with DefaultPolicy has RequireAuthentication=true.
	svc := NewAutoFillService(nil, nil, nil, nil, nil)
	assert.True(t, svc.GetRequireAuthentication())
}

func TestAutoFillService_SetRequireAuthentication_Enable(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	assert.False(t, svc.GetRequireAuthentication())

	err := svc.SetRequireAuthentication(true)
	require.NoError(t, err)
	assert.True(t, svc.GetRequireAuthentication())

	// Verify the policy object was updated, not replaced entirely.
	p := svc.GetPolicy()
	assert.True(t, p.RequireAuthentication)
	assert.Equal(t, autofill.FillModeClickToFill, p.FillMode, "other fields preserved")
}

func TestAutoFillService_SetRequireAuthentication_Toggle(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	// Starts disabled in test helper.
	assert.False(t, svc.GetRequireAuthentication())

	err := svc.SetRequireAuthentication(true)
	require.NoError(t, err)
	assert.True(t, svc.GetRequireAuthentication())

	err = svc.SetRequireAuthentication(false)
	require.NoError(t, err)
	assert.False(t, svc.GetRequireAuthentication())
}

func TestAutoFillService_SetRequireAuthentication_PersistCallback(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	var persisted *autofill.AutoFillPolicy
	svc.SetPolicyPersistFunc(func(policy *autofill.AutoFillPolicy) error {
		persisted = policy
		return nil
	})

	err := svc.SetRequireAuthentication(false)
	require.NoError(t, err)
	require.NotNil(t, persisted, "persist callback should have been called")
	assert.False(t, persisted.RequireAuthentication)
}

func TestAutoFillService_SetRequireAuthentication_PersistError(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	persistErr := errors.New("disk full")
	svc.SetPolicyPersistFunc(func(policy *autofill.AutoFillPolicy) error {
		return persistErr
	})

	err := svc.SetRequireAuthentication(false)
	assert.ErrorIs(t, err, persistErr)
	// Runtime value should still be updated even if persist fails --
	// the caller (frontend) handles the error and reverts the toggle.
	assert.False(t, svc.GetRequireAuthentication())
}

// ---------------------------------------------------------------------------
// Enterprise policy tests
// ---------------------------------------------------------------------------

func TestAutoFillService_EnterpriseDisableExtension(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Enterprise policy disables the extension entirely.
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled: false,
	})

	// User-level enabled=true was set by newTestAutoFillService, but
	// enterprise policy should override: checkPreconditions returns
	// ErrAutoFillDisabled when enterprise Enabled=false.
	_, err := svc.SearchCredentials("github.com")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)

	_, err = svc.GetCredential("any-id", "")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_EnterpriseForceAuth(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// User policy has RequireAuthentication=false (set by newTestAutoFillService).
	assert.False(t, svc.GetRequireAuthentication())

	// Enterprise forces authentication.
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:               true,
		RequireAuthentication: true,
	})

	// Look up a valid credential ID.
	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	var githubID string
	for _, e := range entries {
		if e.Name == "GitHub" {
			githubID = e.ID
			break
		}
	}
	require.NotEmpty(t, githubID)

	// GetCredential without a challenge should fail because enterprise
	// forces authentication even though the user policy has it disabled.
	_, err = svc.GetCredential(githubID, "")
	assert.ErrorIs(t, err, ErrAutoFillChallengeRequired)
}

func TestAutoFillService_EnterpriseDomainBlock(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Enterprise blocks "evil.com".
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:        true,
		BlockedDomains: []string{"evil.com"},
	})

	// Searching for a blocked domain returns ErrAutoFillDomainBlocked.
	_, err := svc.SearchCredentials("evil.com")
	assert.ErrorIs(t, err, ErrAutoFillDomainBlocked)

	// Searching for a non-blocked domain still works (no match, but no error).
	results, err := svc.SearchCredentials("github.com")
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

func TestAutoFillService_EnterpriseDomainAllow(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Enterprise allows only "corp.com".
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:        true,
		AllowedDomains: []string{"corp.com"},
	})

	// Searching for a domain not in the allow list returns ErrAutoFillDomainBlocked.
	_, err := svc.SearchCredentials("other.com")
	assert.ErrorIs(t, err, ErrAutoFillDomainBlocked)

	// Searching for the allowed domain succeeds (no match but no policy error).
	results, err := svc.SearchCredentials("corp.com")
	require.NoError(t, err)
	assert.Empty(t, results, "no passwords match corp.com but no policy error")
}

func TestAutoFillService_EnterpriseForceAudit(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	// Disable audit in user policy.
	policy := autofill.DefaultPolicy()
	policy.RequireAuthentication = false
	policy.AuditEnabled = false
	require.NoError(t, svc.SetPolicy(policy))

	// Enterprise forces audit.
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:    true,
		ForceAudit: true,
	})

	// Perform a search. Even with user audit disabled, enterprise ForceAudit
	// should cause an audit entry to be written.
	countBefore := auditStore.Count()
	_, err := svc.SearchCredentials("github.com")
	require.NoError(t, err)

	assert.Greater(t, auditStore.Count(), countBefore,
		"audit store should have new entries from enterprise ForceAudit")
}

func TestAutoFillService_SetEnabledBlockedByEnterprise(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, nil)

	// Enterprise disables the extension.
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled: false,
	})

	// Attempting to enable the extension should return ErrAutoFillPolicyEnforced.
	err := svc.SetEnabled(true)
	assert.ErrorIs(t, err, ErrAutoFillPolicyEnforced)
	assert.False(t, svc.IsEnabled(), "extension must remain disabled")

	// Disabling should still succeed (no policy conflict).
	err = svc.SetEnabled(false)
	require.NoError(t, err)
}

func TestAutoFillService_SetRequireAuthBlockedByEnterprise(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Enterprise requires authentication.
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:               true,
		RequireAuthentication: true,
	})

	// Attempting to disable authentication should return ErrAutoFillPolicyEnforced.
	err := svc.SetRequireAuthentication(false)
	assert.ErrorIs(t, err, ErrAutoFillPolicyEnforced)

	// Enabling authentication should succeed (matches enterprise requirement).
	err = svc.SetRequireAuthentication(true)
	require.NoError(t, err)
	assert.True(t, svc.GetRequireAuthentication())
}

// ---------------------------------------------------------------------------
// SaveCredential tests
// ---------------------------------------------------------------------------

func TestAutoFillService_SaveCredential_Success(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	countBefore := auditStore.Count()
	result, err := svc.SaveCredential("newsite.com", "newuser", "newpass", "New Site")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Saved)
	assert.False(t, result.Exists)

	// Verify the credential was actually stored.
	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	found := false
	for _, e := range entries {
		if e.Username == "newuser" && e.URL == "https://newsite.com" {
			found = true
			assert.Equal(t, "New Site", e.Title)
			break
		}
	}
	assert.True(t, found, "saved credential should appear in password list")

	// Verify audit entry was written.
	assert.Greater(t, auditStore.Count(), countBefore)
}

func TestAutoFillService_SaveCredential_DefaultTitle(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Empty title should fall back to domain.
	result, err := svc.SaveCredential("example.org", "user1", "pass1", "")
	require.NoError(t, err)
	assert.True(t, result.Saved)

	entries, err := svc.passwordSvc.ListPasswords()
	require.NoError(t, err)

	for _, e := range entries {
		if e.Username == "user1" && e.URL == "https://example.org" {
			assert.Equal(t, "example.org", e.Title)
			return
		}
	}
	t.Fatal("saved credential not found")
}

func TestAutoFillService_SaveCredential_DuplicateReturnsExists(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// The test helper already has github.com / octocat.
	result, err := svc.SaveCredential("github.com", "octocat", "newpass", "GitHub Again")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Exists, "should detect existing credential")
	assert.False(t, result.Saved)
}

func TestAutoFillService_SaveCredential_MissingDomain(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.SaveCredential("", "user", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillSaveInvalidInput)
}

func TestAutoFillService_SaveCredential_MissingUsername(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.SaveCredential("example.com", "", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillSaveInvalidInput)
}

func TestAutoFillService_SaveCredential_MissingPassword(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.SaveCredential("example.com", "user", "", "title")
	assert.ErrorIs(t, err, ErrAutoFillSaveInvalidInput)
}

func TestAutoFillService_SaveCredential_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.SaveCredential("example.com", "user", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_SaveCredential_IgnoredDomain(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	// Ignore the domain first.
	_, err := svc.IgnoreDomain("blocked.com")
	require.NoError(t, err)

	// Attempting to save should fail with domain ignored error.
	_, err = svc.SaveCredential("blocked.com", "user", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillDomainIgnored)
}

func TestAutoFillService_SaveCredential_NilPasswordService(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	svc.passwordSvc = nil

	_, err := svc.SaveCredential("example.com", "user", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillStoreNotConfigured)
}

// ---------------------------------------------------------------------------
// IgnoreDomain tests
// ---------------------------------------------------------------------------

func TestAutoFillService_IgnoreDomain_Success(t *testing.T) {
	svc, auditStore := newTestAutoFillService(t)

	countBefore := auditStore.Count()
	result, err := svc.IgnoreDomain("ignore-me.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Saved)

	// Verify the domain is now ignored.
	assert.True(t, svc.IsIgnoredDomain("ignore-me.com"))
	assert.Greater(t, auditStore.Count(), countBefore)
}

func TestAutoFillService_IgnoreDomain_CaseInsensitive(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.IgnoreDomain("Example.COM")
	require.NoError(t, err)

	// Should match regardless of case.
	assert.True(t, svc.IsIgnoredDomain("example.com"))
	assert.True(t, svc.IsIgnoredDomain("EXAMPLE.COM"))
}

func TestAutoFillService_IgnoreDomain_EmptyDomain(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.IgnoreDomain("")
	assert.Error(t, err)
}

func TestAutoFillService_IgnoreDomain_Disabled(t *testing.T) {
	svc, _ := newTestAutoFillService(t)
	require.NoError(t, svc.SetEnabled(false))

	_, err := svc.IgnoreDomain("example.com")
	assert.ErrorIs(t, err, ErrAutoFillDisabled)
}

func TestAutoFillService_IsIgnoredDomain_NotIgnored(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	assert.False(t, svc.IsIgnoredDomain("not-ignored.com"))
}

// ---------------------------------------------------------------------------
// IPC Handler delegation tests for save/ignore
// ---------------------------------------------------------------------------

func TestAutoFillService_HandleAutofillSave(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillSave("newdomain.com", "testuser", "testpass", "Test")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Saved)
}

func TestAutoFillService_HandleAutofillSave_InvalidInput(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.HandleAutofillSave("", "user", "pass", "title")
	assert.ErrorIs(t, err, ErrAutoFillSaveInvalidInput)
}

func TestAutoFillService_HandleAutofillIgnoreDomain(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	result, err := svc.HandleAutofillIgnoreDomain("skip.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Saved)
	assert.True(t, svc.IsIgnoredDomain("skip.com"))
}

func TestAutoFillService_HandleAutofillIgnoreDomain_Empty(t *testing.T) {
	svc, _ := newTestAutoFillService(t)

	_, err := svc.HandleAutofillIgnoreDomain("")
	assert.Error(t, err)
}
