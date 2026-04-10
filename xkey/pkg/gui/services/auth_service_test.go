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
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// authMockPINBackend extends mockPINBackend with SO PIN verification support.
type authMockPINBackend struct {
	strategy    pin.StrategyID
	soPINSet    bool
	userPINSet  bool
	initialized bool

	verifyUserErr error
	verifySOErr   error

	lockoutStatus *pin.LockoutStatus
}

func (m *authMockPINBackend) Strategy() pin.StrategyID             { return m.strategy }
func (m *authMockPINBackend) SOPINSet() bool                       { return m.soPINSet }
func (m *authMockPINBackend) UserPINSet() bool                     { return m.userPINSet }
func (m *authMockPINBackend) IsInitialized() bool                  { return m.initialized }
func (m *authMockPINBackend) GetLockoutStatus() *pin.LockoutStatus { return m.lockoutStatus }
func (m *authMockPINBackend) SetSOPIN(_, _ string) error           { return nil }
func (m *authMockPINBackend) SetUserPIN(_, _ string) error         { return nil }
func (m *authMockPINBackend) ChangeSOPIN(_, _ string) error        { return nil }
func (m *authMockPINBackend) ChangeUserPIN(_, _ string) error      { return nil }
func (m *authMockPINBackend) VerifySOPIN(_ string) error           { return m.verifySOErr }
func (m *authMockPINBackend) VerifyUserPIN(_ string) error         { return m.verifyUserErr }
func (m *authMockPINBackend) ResetLockout(_ string) error          { return nil }
func (m *authMockPINBackend) SetMaxAttempts(_ int)                 {}

// newTestAuthService creates an AuthService backed by a PINService with
// the given mock PINBackend and a temporary config directory.
func newTestAuthService(backend pin.PINBackend, configDir string) *AuthService {
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	if backend != nil {
		pSvc := pin.NewService(backend, slog.Default())
		pinSvc.SetPINService(pSvc)
	}
	svc := NewAuthService(pinSvc, configDir)
	svc.SetContext(context.Background())
	return svc
}

// loadedPolicy loads the policy from config.Load() which is the same path
// that LoginSO() uses to obtain the policy for HMAC verification. This
// ensures tests write the HMAC against the actual policy the service will
// verify, regardless of whether a config file exists at the XDG path.
func loadedPolicy(t *testing.T) *config.PolicySection {
	t.Helper()
	cfg, err := config.Load()
	require.NoError(t, err)
	return &cfg.Policy
}

func TestNewAuthService(t *testing.T) {
	pinSvc := NewPINService()
	svc := NewAuthService(pinSvc, t.TempDir())

	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.NotNil(t, svc.pinSvc)
	assert.Equal(t, string(AuthModeLocked), svc.GetMode())
}

func TestGetMode_DefaultLocked(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())

	mode := svc.GetMode()
	assert.Equal(t, "locked", mode)
}

func TestIsEnterpriseMode_WithoutHMACFile(t *testing.T) {
	tmpDir := t.TempDir()
	svc := newTestAuthService(nil, tmpDir)

	assert.False(t, svc.IsEnterpriseMode())
}

func TestIsEnterpriseMode_WithHMACFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the HMAC sentinel file that signals enterprise mode.
	hmacPath := filepath.Join(tmpDir, "xkey_policy.hmac")
	err := os.WriteFile(hmacPath, []byte(`{"version":1}`), 0600)
	require.NoError(t, err)

	svc := newTestAuthService(nil, tmpDir)

	assert.True(t, svc.IsEnterpriseMode())
}

func TestLoginUser_NotConfigured(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())

	result := svc.LoginUser("user-pin-123456")

	assert.False(t, result.Success)
	assert.Equal(t, "locked", result.Mode)
	assert.NotEmpty(t, result.Error)
}

func TestLoginSO_NotConfigured(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())

	result := svc.LoginSO("so-pin-123456")

	assert.False(t, result.Success)
	assert.NotEmpty(t, result.Error)
	assert.Equal(t, "locked", result.Mode)
}

func TestLogout(t *testing.T) {
	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, t.TempDir())

	// First login the user.
	result := svc.LoginUser("user-pin-123456")
	require.True(t, result.Success)
	assert.Equal(t, "user", svc.GetMode())

	// Logout should return to locked.
	svc.Logout()
	assert.Equal(t, "locked", svc.GetMode())
}

func TestSetModeUser(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())
	assert.Equal(t, "locked", svc.GetMode())

	svc.SetModeUser()
	assert.Equal(t, "user", svc.GetMode())
}

func TestLoginUser_AlreadyLoggedIn(t *testing.T) {
	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, t.TempDir())

	// First login.
	result := svc.LoginUser("user-pin-123456")
	require.True(t, result.Success)
	assert.Equal(t, "user", result.Mode)

	// Second login should return success without re-verifying PIN.
	result2 := svc.LoginUser("wrong-pin-should-not-matter")
	assert.True(t, result2.Success)
	assert.Equal(t, "user", result2.Mode)
}

func TestLoginUser_Success(t *testing.T) {
	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, t.TempDir())

	result := svc.LoginUser("user-pin-123456")

	assert.True(t, result.Success)
	assert.Equal(t, "user", result.Mode)
	assert.Empty(t, result.Error)
	assert.Equal(t, "user", svc.GetMode())
}

func TestLoginUser_InvalidPIN(t *testing.T) {
	backend := &authMockPINBackend{
		strategy:      pin.StrategySoftware,
		verifyUserErr: pin.ErrPINInvalid,
	}
	svc := newTestAuthService(backend, t.TempDir())

	result := svc.LoginUser("wrong-pin")

	assert.False(t, result.Success)
	assert.Equal(t, "locked", result.Mode)
	assert.NotEmpty(t, result.Error)
	assert.Equal(t, "locked", svc.GetMode())
}

func TestLoginSO_Success_NonEnterprise(t *testing.T) {
	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, t.TempDir())

	result := svc.LoginSO("so-pin-123456")

	assert.True(t, result.Success)
	assert.Equal(t, "so_admin", result.Mode)
	assert.Empty(t, result.Error)
	assert.Equal(t, "so_admin", svc.GetMode())
}

func TestLoginSO_InvalidPIN(t *testing.T) {
	backend := &authMockPINBackend{
		strategy:    pin.StrategySoftware,
		verifySOErr: pin.ErrPINInvalid,
	}
	svc := newTestAuthService(backend, t.TempDir())

	result := svc.LoginSO("wrong-so-pin")

	assert.False(t, result.Success)
	assert.Equal(t, "locked", result.Mode)
	assert.NotEmpty(t, result.Error)
}

func TestIsPolicyVerified_Default(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())
	assert.False(t, svc.IsPolicyVerified())
}

func TestIsTamperDetected_Default(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())
	assert.False(t, svc.IsTamperDetected())
}

func TestAuthService_SetContext(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestLogout_FromSOAdmin(t *testing.T) {
	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, t.TempDir())

	// Login as SO.
	result := svc.LoginSO("so-pin-123456")
	require.True(t, result.Success)
	assert.Equal(t, "so_admin", svc.GetMode())

	// Logout should return to locked.
	svc.Logout()
	assert.Equal(t, "locked", svc.GetMode())
}

func TestSetModeUser_ThenLogout(t *testing.T) {
	svc := newTestAuthService(nil, t.TempDir())

	svc.SetModeUser()
	assert.Equal(t, "user", svc.GetMode())

	svc.Logout()
	assert.Equal(t, "locked", svc.GetMode())
}

// ---------------------------------------------------------------------------
// LoginSO - Enterprise mode tests (Phase 2)
// ---------------------------------------------------------------------------

func TestLoginSO_Enterprise_ValidHMAC(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"

	// Use the same policy that LoginSO() will load via config.Load().
	// This ensures the HMAC matches regardless of whether a config file
	// exists at the XDG path on the host machine.
	policy := loadedPolicy(t)
	hmacPath := config.PolicyHMACPath(tmpDir)
	err := config.WritePolicyHMAC(policy, soPIN, hmacPath)
	require.NoError(t, err)

	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, tmpDir)

	result := svc.LoginSO(soPIN)

	assert.True(t, result.Success)
	assert.Equal(t, "so_admin", result.Mode)
	assert.True(t, result.PolicyVerified, "policy should be verified when HMAC matches")
	assert.False(t, result.TamperDetected, "no tampering should be detected with valid HMAC")

	// Session-level cache should be set.
	assert.True(t, svc.IsPolicyVerified())
	assert.False(t, svc.IsTamperDetected())
}

func TestLoginSO_Enterprise_TamperedHMAC(t *testing.T) {
	tmpDir := t.TempDir()
	soPIN := "enterprise-so-pin-12345"

	// Write a valid HMAC but with a different policy than what config.Load() returns.
	// This simulates policy tampering: the HMAC was computed for a different policy.
	tamperedPolicy := loadedPolicy(t)
	tamperedPolicy.MinPINLength = 99 // Differ from whatever the loaded config has.
	hmacPath := config.PolicyHMACPath(tmpDir)
	err := config.WritePolicyHMAC(tamperedPolicy, soPIN, hmacPath)
	require.NoError(t, err)

	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, tmpDir)

	result := svc.LoginSO(soPIN)

	// Login succeeds (SO PIN was verified) but policy is flagged as tampered.
	assert.True(t, result.Success)
	assert.Equal(t, "so_admin", result.Mode)
	assert.False(t, result.PolicyVerified, "policy should NOT be verified when HMAC does not match loaded config")
	assert.True(t, result.TamperDetected, "tamper should be detected when policy differs from HMAC")

	// Session-level cache reflects tamper detection.
	assert.False(t, svc.IsPolicyVerified())
	assert.True(t, svc.IsTamperDetected())
}

func TestLoginSO_Enterprise_CorruptedHMACFile(t *testing.T) {
	tmpDir := t.TempDir()

	// Write a corrupted HMAC file (invalid JSON, missing required fields).
	hmacPath := config.PolicyHMACPath(tmpDir)
	err := os.WriteFile(hmacPath, []byte(`{"version":0}`), 0600)
	require.NoError(t, err)

	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, tmpDir)

	result := svc.LoginSO("so-pin-123456")

	// Login succeeds (SO PIN was verified) but policy verification has an error.
	assert.True(t, result.Success)
	assert.Equal(t, "so_admin", result.Mode)
	assert.False(t, result.PolicyVerified)
	assert.True(t, result.TamperDetected, "tamper should be detected when HMAC file is corrupted")
	assert.NotEmpty(t, result.Error, "error message should describe the verification failure")

	// Session cache should reflect tamper detection.
	assert.True(t, svc.IsTamperDetected())
}

func TestLoginSO_Enterprise_WrongSOPIN(t *testing.T) {
	tmpDir := t.TempDir()
	correctPIN := "correct-so-pin-12345"
	wrongPIN := "wrong-so-pin-99999"

	// Write HMAC with the correct PIN using the loaded policy.
	policy := loadedPolicy(t)
	hmacPath := config.PolicyHMACPath(tmpDir)
	err := config.WritePolicyHMAC(policy, correctPIN, hmacPath)
	require.NoError(t, err)

	backend := &authMockPINBackend{strategy: pin.StrategySoftware}
	svc := newTestAuthService(backend, tmpDir)

	// Login with the wrong PIN. The mock PINBackend does not actually
	// validate the PIN value, so VerifySOPIN succeeds. But the HMAC
	// verification uses the wrong PIN to derive the key, resulting in
	// a mismatch (tamper detected).
	result := svc.LoginSO(wrongPIN)

	assert.True(t, result.Success)
	assert.Equal(t, "so_admin", result.Mode)
	assert.False(t, result.PolicyVerified, "policy should not be verified with wrong PIN")
	assert.True(t, result.TamperDetected, "tamper should be detected when PIN-derived key mismatches")
}
