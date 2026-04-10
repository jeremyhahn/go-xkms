//go:build linux

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
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/authenticator"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/tokenstore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Extended mock: RPPolicyStore with list error support
// ---------------------------------------------------------------------------

// phase2RPPolicyStore extends the existing mock pattern with list error support.
type phase2RPPolicyStore struct {
	policies  []*authenticator.RPPolicy
	getResult *authenticator.RPPolicy
	getErr    error
	setErr    error
	deleteErr error
	listErr   error
}

func (m *phase2RPPolicyStore) SetPolicy(_ *authenticator.RPPolicy) error { return m.setErr }
func (m *phase2RPPolicyStore) GetPolicy(_ string) (*authenticator.RPPolicy, error) {
	if m.getResult != nil {
		return m.getResult, nil
	}
	return nil, m.getErr
}
func (m *phase2RPPolicyStore) DeletePolicy(_ string) error { return m.deleteErr }
func (m *phase2RPPolicyStore) ListPolicies() ([]*authenticator.RPPolicy, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.policies, nil
}

// ---------------------------------------------------------------------------
// Extended mock: TokenStore with list error support
// ---------------------------------------------------------------------------

// phase2TokenStore extends the existing mock pattern with list error support.
type phase2TokenStore struct {
	entries    []*tokenstore.TokenEntry
	saveErr    error
	loadErr    error
	loadResult *tokenstore.TokenEntry
	listErr    error
}

func (m *phase2TokenStore) Save(_ context.Context, _ *tokenstore.TokenEntry) error {
	return m.saveErr
}
func (m *phase2TokenStore) Load(_ context.Context, _ string) (*tokenstore.TokenEntry, error) {
	if m.loadResult != nil {
		return m.loadResult, nil
	}
	return nil, m.loadErr
}
func (m *phase2TokenStore) Delete(_ context.Context, _ string) error { return nil }
func (m *phase2TokenStore) List(_ context.Context) ([]*tokenstore.TokenEntry, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.entries, nil
}
func (m *phase2TokenStore) Close() error { return nil }

// ---------------------------------------------------------------------------
// Audit logger for phase2 tests
// ---------------------------------------------------------------------------

type phase2AuditLogger struct {
	entries []audit.Entry
}

func (l *phase2AuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *phase2AuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, _ error, _ int64) {
	l.Log(audit.Entry{Operation: op, Backend: backend, KeyID: keyID, Success: success})
}
func (l *phase2AuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *phase2AuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *phase2AuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) {
	l.Log(audit.Entry{Operation: op, Success: true, Details: details})
}
func (l *phase2AuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *phase2AuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {}
func (l *phase2AuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *phase2AuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ===========================================================================
// FIDO2DeviceService: setter coverage with real authenticator
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2DeviceService_SetAuthenticator_Nil(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.SetAuthenticator(nil)
	assert.Nil(t, svc.externalAuth)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetWindowHideFunc_Nil(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// SetWindowHideFunc is a no-op; just verify it doesn't panic.
	svc.SetWindowHideFunc(nil)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetWindowHideFunc_Called(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// SetWindowHideFunc is a no-op; just verify it doesn't panic.
	svc.SetWindowHideFunc(func() {})
}

func TestCoverageBoostPhase2_FIDO2DeviceService_GetRequireUserPresence_WithAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	auth := createPhase2Authenticator(t)
	svc.SetAuthenticator(auth)

	result := svc.GetRequireUserPresence()
	assert.True(t, result)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetRequireUserPresence_WithAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	auth := createPhase2Authenticator(t)
	svc.SetAuthenticator(auth)

	svc.SetRequireUserPresence(false)
	assert.False(t, auth.Config().RequireUserPresence)

	svc.SetRequireUserPresence(true)
	assert.True(t, auth.Config().RequireUserPresence)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetRequireUserPresence_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic.
	svc.SetRequireUserPresence(true)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_GetUserIntentCheck_WithAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	auth := createPhase2Authenticator(t)
	svc.SetAuthenticator(auth)

	result := svc.GetUserIntentCheck()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetUserIntentCheck_WithAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	auth := createPhase2Authenticator(t)
	svc.SetAuthenticator(auth)

	svc.SetUserIntentCheck(true)
	assert.True(t, auth.Config().EnableUserIntentCheck)

	svc.SetUserIntentCheck(false)
	assert.False(t, auth.Config().EnableUserIntentCheck)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_SetUserIntentCheck_NilAuth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic.
	svc.SetUserIntentCheck(true)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_IsAuthenticatorPINSet_RunningNilDevice(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	svc.device = nil

	result := svc.IsAuthenticatorPINSet()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_IsAuthenticatorPINSet_NotRunning(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	result := svc.IsAuthenticatorPINSet()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_Cleanup_NilBoth(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.uhidDev = nil
	svc.device = nil
	// Should not panic.
	svc.cleanup()
	assert.Nil(t, svc.uhidDev)
	assert.Nil(t, svc.device)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_GetStatus_Running_NilSocketHandler(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	svc.running.Store(true)
	svc.socketHandler = nil

	status := svc.GetStatus()
	assert.True(t, status.Running)
	assert.False(t, status.HasPending)
	assert.NotEmpty(t, status.DeviceName)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_Emit_WithFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	var captured string
	svc.SetEmitFunc(func(eventType string, _ any) {
		captured = eventType
	})
	svc.emit("test:phase2", nil)
	assert.Equal(t, "test:phase2", captured)
}

func TestCoverageBoostPhase2_FIDO2DeviceService_Emit_NilFunc(t *testing.T) {
	svc := NewFIDO2DeviceService(slog.Default())
	// Should not panic.
	svc.emit("test:phase2", nil)
}

// ===========================================================================
// FIDO2Service: RP policy operations with store errors
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2Service_ListRPPolicies_WithPolicies(t *testing.T) {
	svc := NewFIDO2Service(nil)
	al := &phase2AuditLogger{}
	svc.SetAuditLogger(al)

	store := &phase2RPPolicyStore{
		policies: []*authenticator.RPPolicy{
			{RPID: "example.com", Enterprise: true},
			{RPID: "test.org", Blocked: true},
		},
	}
	svc.SetRPPolicyStore(store)

	result, err := svc.ListRPPolicies()
	require.NoError(t, err)
	assert.Len(t, result, 2)

	// Verify audit was logged.
	assert.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpFIDO2RPPolicyAccessed, al.entries[0].Operation)
}

func TestCoverageBoostPhase2_FIDO2Service_ListRPPolicies_StoreError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	storeErr := errors.New("disk failure")
	store := &phase2RPPolicyStore{listErr: storeErr}
	svc.SetRPPolicyStore(store)

	result, err := svc.ListRPPolicies()
	assert.Nil(t, result)
	assert.ErrorIs(t, err, storeErr)
}

func TestCoverageBoostPhase2_FIDO2Service_GetRPPolicy_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	al := &phase2AuditLogger{}
	svc.SetAuditLogger(al)

	trueVal := true
	store := &phase2RPPolicyStore{
		getResult: &authenticator.RPPolicy{
			RPID:       "example.com",
			UPOverride: &trueVal,
			Enterprise: true,
		},
	}
	svc.SetRPPolicyStore(store)

	result, err := svc.GetRPPolicy("example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "example.com", result.RPID)
	assert.Equal(t, "true", result.UPOverride)
	assert.True(t, result.Enterprise)

	// Verify audit was logged.
	assert.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpFIDO2RPPolicyAccessed, al.entries[0].Operation)
}

func TestCoverageBoostPhase2_FIDO2Service_GetRPPolicy_StoreError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	storeErr := errors.New("not found")
	store := &phase2RPPolicyStore{getErr: storeErr}
	svc.SetRPPolicyStore(store)

	result, err := svc.GetRPPolicy("example.com")
	assert.Nil(t, result)
	assert.ErrorIs(t, err, storeErr)
}

func TestCoverageBoostPhase2_FIDO2Service_SetRPPolicy_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	al := &phase2AuditLogger{}
	svc.SetAuditLogger(al)

	store := &phase2RPPolicyStore{}
	svc.SetRPPolicyStore(store)

	err := svc.SetRPPolicy(FIDO2RPPolicy{
		RPID:       "example.com",
		UPOverride: "true",
	})
	require.NoError(t, err)

	// Verify audit was logged.
	assert.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpFIDO2RPPolicySet, al.entries[0].Operation)
}

func TestCoverageBoostPhase2_FIDO2Service_SetRPPolicy_ValidationError_EmptyRPID(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &phase2RPPolicyStore{}
	svc.SetRPPolicyStore(store)

	err := svc.SetRPPolicy(FIDO2RPPolicy{RPID: ""})
	assert.Error(t, err)
	assert.ErrorIs(t, err, authenticator.ErrRPPolicyInvalidRPID)
}

func TestCoverageBoostPhase2_FIDO2Service_SetRPPolicy_StoreError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	storeErr := errors.New("write failed")
	store := &phase2RPPolicyStore{setErr: storeErr}
	svc.SetRPPolicyStore(store)

	err := svc.SetRPPolicy(FIDO2RPPolicy{RPID: "example.com"})
	assert.ErrorIs(t, err, storeErr)
}

func TestCoverageBoostPhase2_FIDO2Service_DeleteRPPolicy_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	al := &phase2AuditLogger{}
	svc.SetAuditLogger(al)

	store := &phase2RPPolicyStore{}
	svc.SetRPPolicyStore(store)

	err := svc.DeleteRPPolicy("example.com")
	require.NoError(t, err)

	// Verify audit was logged.
	assert.Len(t, al.entries, 1)
	assert.Equal(t, audit.OpFIDO2RPPolicyDeleted, al.entries[0].Operation)
}

func TestCoverageBoostPhase2_FIDO2Service_DeleteRPPolicy_StoreError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	storeErr := errors.New("delete failed")
	store := &phase2RPPolicyStore{deleteErr: storeErr}
	svc.SetRPPolicyStore(store)

	err := svc.DeleteRPPolicy("example.com")
	assert.ErrorIs(t, err, storeErr)
}

// ===========================================================================
// FIDO2Service: GetAuthResponses with entries
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2Service_GetAuthResponses_WithEntries(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())

	now := time.Now()
	store := &phase2TokenStore{
		entries: []*tokenstore.TokenEntry{
			{
				ServerURL: "fido2:example.com",
				Source:    tokenstore.SourceFIDO2,
				Token:     "jwt-tok-1",
				Issuer:    "example.com",
				Subject:   "cred-1",
				IssuedAt:  now,
				ExpiresAt: now.Add(time.Hour),
			},
			{
				ServerURL: "oidc:other.com",
				Source:    tokenstore.SourceOIDC,
				Token:     "oidc-tok",
				Issuer:    "other.com",
				Subject:   "user-1",
			},
			{
				ServerURL: "fido2:test.org",
				Source:    tokenstore.SourceFIDO2,
				Token:     "jwt-tok-2",
				Issuer:    "test.org",
				Subject:   "cred-2",
				IssuedAt:  now,
				ExpiresAt: now.Add(2 * time.Hour),
			},
		},
	}
	svc.SetTokenStore(store)

	result := svc.GetAuthResponses()
	// Only FIDO2 entries should be returned.
	require.Len(t, result, 2)
	assert.Equal(t, "cred-1", result[0].CredentialID)
	assert.Equal(t, "example.com", result[0].RPID)
	assert.Equal(t, "jwt-tok-1", result[0].Token)
	assert.Equal(t, "jwt", result[0].TokenType)
	assert.Equal(t, "cred-2", result[1].CredentialID)
	assert.Equal(t, "test.org", result[1].RPID)
}

func TestCoverageBoostPhase2_FIDO2Service_GetAuthResponses_ListError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	store := &phase2TokenStore{listErr: errors.New("list failed")}
	svc.SetTokenStore(store)

	result := svc.GetAuthResponses()
	assert.Nil(t, result)
}

func TestCoverageBoostPhase2_FIDO2Service_GetAuthResponses_EmptyEntries(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	store := &phase2TokenStore{entries: []*tokenstore.TokenEntry{}}
	svc.SetTokenStore(store)

	result := svc.GetAuthResponses()
	assert.Nil(t, result)
}

func TestCoverageBoostPhase2_FIDO2Service_GetAuthResponses_NilContext(t *testing.T) {
	svc := NewFIDO2Service(nil)
	// Do not set context -- ctx is nil, should fallback to context.Background().
	store := &phase2TokenStore{
		entries: []*tokenstore.TokenEntry{
			{
				ServerURL: "fido2:rp.com",
				Source:    tokenstore.SourceFIDO2,
				Token:     "tok",
				Issuer:    "rp.com",
				Subject:   "cred",
			},
		},
	}
	svc.SetTokenStore(store)

	result := svc.GetAuthResponses()
	require.Len(t, result, 1)
	assert.Equal(t, "tok", result[0].Token)
}

// ===========================================================================
// FIDO2Service: GetLatestToken success path
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2Service_GetLatestToken_Success(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())
	store := &phase2TokenStore{
		loadResult: &tokenstore.TokenEntry{
			Token: "my-jwt-token",
		},
	}
	svc.SetTokenStore(store)

	tok, err := svc.GetLatestToken("example.com")
	require.NoError(t, err)
	assert.Equal(t, "my-jwt-token", tok)
}

func TestCoverageBoostPhase2_FIDO2Service_GetLatestToken_NilContext(t *testing.T) {
	svc := NewFIDO2Service(nil)
	// Do not set context.
	store := &phase2TokenStore{
		loadResult: &tokenstore.TokenEntry{Token: "fallback-jwt"},
	}
	svc.SetTokenStore(store)

	tok, err := svc.GetLatestToken("example.com")
	require.NoError(t, err)
	assert.Equal(t, "fallback-jwt", tok)
}

// ===========================================================================
// FIDO2Service: StoreAuthResponse error paths
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2Service_StoreAuthResponse_SaveError(t *testing.T) {
	svc := NewFIDO2Service(nil)
	svc.SetContext(context.Background())

	saveErr := errors.New("save failed")
	store := &phase2TokenStore{saveErr: saveErr}
	svc.SetTokenStore(store)

	err := svc.StoreAuthResponse(&FIDO2AuthResponse{
		CredentialID: "cred-1",
		RPID:         "example.com",
		Token:        "jwt-token",
		CreatedAt:    time.Now(),
		ExpiresAt:    time.Now().Add(time.Hour),
	})
	assert.ErrorIs(t, err, saveErr)
}

func TestCoverageBoostPhase2_FIDO2Service_StoreAuthResponse_NilContext(t *testing.T) {
	svc := NewFIDO2Service(nil)
	// Do not set context -- should fallback to context.Background().
	store := &phase2TokenStore{}
	svc.SetTokenStore(store)

	err := svc.StoreAuthResponse(&FIDO2AuthResponse{
		CredentialID: "cred-1",
		RPID:         "example.com",
		Token:        "jwt-token",
	})
	require.NoError(t, err)
}

// ===========================================================================
// FIDO2Service: policy operations without audit logger
// ===========================================================================

func TestCoverageBoostPhase2_FIDO2Service_ListRPPolicies_NoAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &phase2RPPolicyStore{
		policies: []*authenticator.RPPolicy{
			{RPID: "example.com"},
		},
	}
	svc.SetRPPolicyStore(store)

	result, err := svc.ListRPPolicies()
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestCoverageBoostPhase2_FIDO2Service_GetRPPolicy_NoAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &phase2RPPolicyStore{
		getResult: &authenticator.RPPolicy{RPID: "example.com"},
	}
	svc.SetRPPolicyStore(store)

	result, err := svc.GetRPPolicy("example.com")
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "example.com", result.RPID)
}

func TestCoverageBoostPhase2_FIDO2Service_SetRPPolicy_NoAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &phase2RPPolicyStore{}
	svc.SetRPPolicyStore(store)

	err := svc.SetRPPolicy(FIDO2RPPolicy{RPID: "example.com"})
	require.NoError(t, err)
}

func TestCoverageBoostPhase2_FIDO2Service_DeleteRPPolicy_NoAuditLogger(t *testing.T) {
	svc := NewFIDO2Service(nil)
	store := &phase2RPPolicyStore{}
	svc.SetRPPolicyStore(store)

	err := svc.DeleteRPPolicy("example.com")
	require.NoError(t, err)
}

// ===========================================================================
// StorageService: validateVolumeSize edge cases
// ===========================================================================

func TestCoverageBoostPhase2_ValidateVolumeSize_ExactBoundary(t *testing.T) {
	tests := []struct {
		name   string
		size   int
		hasErr bool
	}{
		{"exactly min", 1, false},
		{"exactly max", 100, false},
		{"one below min", 0, true},
		{"one above max", 101, true},
		{"large negative", -1000, true},
		{"large positive", 10000, true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVolumeSize(tc.size)
			if tc.hasErr {
				assert.ErrorIs(t, err, ErrStorageInvalidSize)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestCoverageBoostPhase2_ValidatePassphrase_ExactBoundary(t *testing.T) {
	tests := []struct {
		name       string
		passphrase string
		hasErr     bool
	}{
		{"exactly 8 chars", "12345678", false},
		{"7 chars", "1234567", true},
		{"empty", "", true},
		{"long passphrase", "this is a very long passphrase indeed", false},
		{"unicode 8 bytes", "abcdefgh", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := validatePassphrase(tc.passphrase)
			if tc.hasErr {
				assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// ===========================================================================
// StorageService: MigrateToEncrypted validation paths
// ===========================================================================

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_InvalidSize(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(0, "validpassphrase", false)
	assert.ErrorIs(t, err, ErrStorageInvalidSize)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_TooLarge(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(101, "validpassphrase", false)
	assert.ErrorIs(t, err, ErrStorageInvalidSize)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_WeakPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(5, "short", false)
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_EmptyPassphrase(t *testing.T) {
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(5, "", false)
	assert.ErrorIs(t, err, ErrStorageWeakPassphrase)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_RequiresRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping root-requirement assertion")
		return
	}
	svc := NewStorageService()
	err := svc.MigrateToEncrypted(5, "validpassphrase", false)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_WithElevator(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.MigrateToEncrypted(5, "validpassphrase", true)
	assert.NoError(t, err)
	assert.Greater(t, mock.callCount, 0)
}

func TestCoverageBoostPhase2_StorageService_MigrateToEncrypted_ElevatorError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true, err: ErrElevationDenied}
	svc.SetElevator(mock)

	err := svc.MigrateToEncrypted(5, "validpassphrase", false)
	assert.ErrorIs(t, err, ErrElevationDenied)
}

// ===========================================================================
// StorageService: runElevatedCmd edge cases
// ===========================================================================

func TestCoverageBoostPhase2_StorageService_RunElevatedCmd_NilElevator(t *testing.T) {
	svc := NewStorageService()
	svc.elevator = nil
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

func TestCoverageBoostPhase2_StorageService_RunElevatedCmd_UnavailableElevator(t *testing.T) {
	svc := NewStorageService()
	svc.SetElevator(&mockElevator{available: false})
	err := svc.runElevatedCmd([]string{"test"}, nil)
	assert.ErrorIs(t, err, ErrStorageRequiresRoot)
}

func TestCoverageBoostPhase2_StorageService_RunElevatedCmd_WithData(t *testing.T) {
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	data := []byte("secret-data\n")
	err := svc.runElevatedCmd([]string{"luks2", "test"}, data)
	assert.NoError(t, err)
	assert.Equal(t, []string{"luks2", "test"}, mock.lastArgs)
	assert.Equal(t, data, mock.lastData)
}

// ===========================================================================
// StorageService: WipeVolume elevated with standards
// ===========================================================================

func TestCoverageBoostPhase2_StorageService_WipeVolume_DOD3Elevated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.WipeVolume("dod3")
	assert.NoError(t, err)
	assert.Equal(t, "dod3", mock.lastArgs[3])
}

func TestCoverageBoostPhase2_StorageService_WipeVolume_DOD7Elevated(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Log("running as root; skipping elevation test")
		return
	}
	svc := NewStorageService()
	mock := &mockElevator{available: true}
	svc.SetElevator(mock)

	err := svc.WipeVolume("dod7")
	assert.NoError(t, err)
	assert.Equal(t, "dod7", mock.lastArgs[3])
}

// ===========================================================================
// AutoFillService: saveRegistration paths
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_SaveRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = ""

	svc.credID = []byte{0x01, 0x02}
	svc.saveRegistration([]byte{0x03, 0x04})
	// No panic, no file written -- empty dir is a no-op.
}

func TestCoverageBoostPhase2_AutoFillService_SaveRegistration_ValidDir(t *testing.T) {
	dir := t.TempDir()
	regDir := filepath.Join(dir, "autofill")

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = regDir
	svc.credID = []byte{0x01, 0x02, 0x03}

	pubKey := []byte{0x04, 0x05, 0x06}
	svc.saveRegistration(pubKey)

	data, err := os.ReadFile(filepath.Join(regDir, "registration.json"))
	require.NoError(t, err)

	var reg autofillRegistration
	require.NoError(t, json.Unmarshal(data, &reg))
	assert.Equal(t, []byte{0x01, 0x02, 0x03}, reg.CredentialID)
	assert.Equal(t, pubKey, reg.PublicKeyCOSE)
	assert.False(t, reg.RegisteredAt.IsZero())
}

func TestCoverageBoostPhase2_AutoFillService_SaveRegistration_InvalidDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = "/dev/null/impossible"
	svc.credID = []byte{0x01}

	// Should log error but not panic.
	svc.saveRegistration([]byte{0x02})
}

// ===========================================================================
// AutoFillService: loadRegistration paths
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_EmptyDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = ""

	result := svc.loadRegistration()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_NonexistentFile(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = t.TempDir()

	result := svc.loadRegistration()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "registration.json"), []byte("not-json"), 0600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = dir

	result := svc.loadRegistration()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_EmptyCredentialID(t *testing.T) {
	dir := t.TempDir()
	reg := autofillRegistration{
		CredentialID:  []byte{},
		PublicKeyCOSE: []byte{0x01, 0x02},
		RegisteredAt:  time.Now(),
	}
	data, err := json.Marshal(reg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "registration.json"), data, 0600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = dir

	result := svc.loadRegistration()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_EmptyPublicKey(t *testing.T) {
	dir := t.TempDir()
	reg := autofillRegistration{
		CredentialID:  []byte{0x01, 0x02},
		PublicKeyCOSE: []byte{},
		RegisteredAt:  time.Now(),
	}
	data, err := json.Marshal(reg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "registration.json"), data, 0600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = dir

	result := svc.loadRegistration()
	assert.False(t, result)
}

func TestCoverageBoostPhase2_AutoFillService_LoadRegistration_InvalidPublicKey(t *testing.T) {
	dir := t.TempDir()
	reg := autofillRegistration{
		CredentialID:  []byte{0x01, 0x02},
		PublicKeyCOSE: []byte{0xFF, 0xFF, 0xFF},
		RegisteredAt:  time.Now(),
	}
	data, err := json.Marshal(reg)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "registration.json"), data, 0600))

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = dir

	result := svc.loadRegistration()
	assert.False(t, result)
}

// ===========================================================================
// AutoFillService: ensureRegistered paths
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_EnsureRegistered_FastPath(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	// Simulate already registered state with a zero-value verifier.
	svc.credID = []byte{0x01}
	svc.verifier = &autofill.AssertionVerifier{}

	err := svc.ensureRegistered()
	assert.NoError(t, err)
}

func TestCoverageBoostPhase2_AutoFillService_EnsureRegistered_NoAuthenticator(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = t.TempDir()

	err := svc.ensureRegistered()
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestCoverageBoostPhase2_AutoFillService_EnsureRegistered_LoadFromDisk(t *testing.T) {
	auth := createTestAuthenticatorForAutofill(t)

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.auth = auth
	svc.registrationDir = t.TempDir()

	err := svc.registerCredential()
	require.NoError(t, err)
	require.NotNil(t, svc.credID)
	require.NotNil(t, svc.verifier)

	// Create a new service that loads from disk.
	svc2 := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc2.registrationDir = svc.registrationDir

	err = svc2.ensureRegistered()
	assert.NoError(t, err)
	assert.NotNil(t, svc2.credID)
	assert.NotNil(t, svc2.verifier)
}

// ===========================================================================
// AutoFillService: authenticateWithCTAP2 early failures
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_AuthenticateWithCTAP2_EnsureRegisteredFails(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.registrationDir = t.TempDir()

	_, err := svc.authenticateWithCTAP2("dGVzdA==")
	assert.ErrorIs(t, err, ErrAutoFillNotConfigured)
}

func TestCoverageBoostPhase2_AutoFillService_AuthenticateWithCTAP2_InvalidChallenge(t *testing.T) {
	auth := createTestAuthenticatorForAutofill(t)
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.auth = auth
	svc.registrationDir = t.TempDir()

	require.NoError(t, svc.registerCredential())

	_, err := svc.authenticateWithCTAP2("!!!not-valid-base64!!!")
	assert.ErrorIs(t, err, ErrAutoFillAuthFailed)
	assert.Contains(t, err.Error(), "invalid challenge encoding")
}

func TestCoverageBoostPhase2_AutoFillService_AuthenticateWithCTAP2_Success(t *testing.T) {
	// Create an authenticator with PIN enabled and a PIN hash set so that
	// the UV flag is set in the assertion response (required by the verifier).
	store := authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:             store,
		AAGUID:              [16]byte{0x01, 0x02, 0x03, 0x04},
		EnableResidentKey:   true,
		EnablePIN:           true,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	require.NoError(t, err)

	// Set PIN hash: SHA-256("test-pin")[:16] per CTAP2 spec.
	pinHash := sha256.Sum256([]byte("test-pin"))
	auth.SetFIDO2PINHash(pinHash[:16])

	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.auth = auth
	svc.registrationDir = t.TempDir()

	al := &phase2AuditLogger{}
	svc.auditStore = al

	require.NoError(t, svc.registerCredential())

	assertion, err := svc.authenticateWithCTAP2("dGVzdC1jaGFsbGVuZ2U=")
	require.NoError(t, err)
	require.NotNil(t, assertion)
	assert.NotEmpty(t, assertion.AuthData)
	assert.NotEmpty(t, assertion.Signature)
	assert.NotEmpty(t, assertion.CredentialID)

	// Verify audit was logged.
	assert.NotEmpty(t, al.entries)
}

// ===========================================================================
// AutoFillService: SetRegistrationDir
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_SetRegistrationDir(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.SetRegistrationDir("/tmp/test-reg")
	assert.Equal(t, "/tmp/test-reg", svc.registrationDir)
}

// ===========================================================================
// AutoFillService: enterprise policy rate limiter
// ===========================================================================

func TestCoverageBoostPhase2_AutoFillService_SetEnterprisePolicy_WithRateLimit(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:           true,
		MaxFillsPerMinute: 42,
	})
	ep := svc.GetEnterprisePolicy()
	require.NotNil(t, ep)
	assert.Equal(t, 42, ep.MaxFillsPerMinute)
}

func TestCoverageBoostPhase2_AutoFillService_SetEnterprisePolicy_ZeroRateLimit(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	svc.SetEnterprisePolicy(&EnterpriseExtensionPolicy{
		Enabled:           true,
		MaxFillsPerMinute: 0,
	})
	ep := svc.GetEnterprisePolicy()
	require.NotNil(t, ep)
	assert.Equal(t, 0, ep.MaxFillsPerMinute)
}

func TestCoverageBoostPhase2_AutoFillService_GetEnterprisePolicy_Nil(t *testing.T) {
	svc := NewAutoFillService(nil, nil, nil, nil, slog.Default())
	ep := svc.GetEnterprisePolicy()
	assert.Nil(t, ep)
}

// ===========================================================================
// FIDO2Service: rpPolicyToGUI / guiToRPPolicy edge cases
// ===========================================================================

func TestCoverageBoostPhase2_RPPolicyToGUI_WithFalseUPOverride(t *testing.T) {
	falseVal := false
	policy := &authenticator.RPPolicy{
		RPID:       "test.org",
		UPOverride: &falseVal,
		Blocked:    true,
	}
	gui := rpPolicyToGUI(policy)
	assert.Equal(t, "false", gui.UPOverride)
	assert.True(t, gui.Blocked)
}

func TestCoverageBoostPhase2_RPPolicyToGUI_NilUPOverride(t *testing.T) {
	policy := &authenticator.RPPolicy{
		RPID: "test.org",
	}
	gui := rpPolicyToGUI(policy)
	assert.Equal(t, "", gui.UPOverride)
}

func TestCoverageBoostPhase2_GUIToRPPolicy_UPOverrideFalse(t *testing.T) {
	gui := FIDO2RPPolicy{
		RPID:       "test.org",
		UPOverride: "false",
	}
	domain := guiToRPPolicy(gui)
	require.NotNil(t, domain.UPOverride)
	assert.False(t, *domain.UPOverride)
}

func TestCoverageBoostPhase2_GUIToRPPolicy_UPOverrideTrue(t *testing.T) {
	gui := FIDO2RPPolicy{
		RPID:       "test.org",
		UPOverride: "true",
	}
	domain := guiToRPPolicy(gui)
	require.NotNil(t, domain.UPOverride)
	assert.True(t, *domain.UPOverride)
}

func TestCoverageBoostPhase2_GUIToRPPolicy_UPOverrideEmpty(t *testing.T) {
	gui := FIDO2RPPolicy{
		RPID:       "test.org",
		UPOverride: "",
	}
	domain := guiToRPPolicy(gui)
	assert.Nil(t, domain.UPOverride)
}

func TestCoverageBoostPhase2_GUIToRPPolicy_UPOverrideInvalid(t *testing.T) {
	gui := FIDO2RPPolicy{
		RPID:       "test.org",
		UPOverride: "maybe",
	}
	domain := guiToRPPolicy(gui)
	assert.Nil(t, domain.UPOverride)
}

// ===========================================================================
// FIDO2Service: storedToFIDO2Credential edge cases
// ===========================================================================

func TestCoverageBoostPhase2_StoredToFIDO2Credential_BackendIDSoftware(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -7,
		BackendID:    "software",
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "software", cred.BackendType)
	assert.Equal(t, "software", cred.BackendID)
}

func TestCoverageBoostPhase2_StoredToFIDO2Credential_BackendIDHardware(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -7,
		BackendID:    "tpm2",
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "tpm2", cred.BackendType)
	assert.Equal(t, "tpm2", cred.BackendID)
}

func TestCoverageBoostPhase2_StoredToFIDO2Credential_NoBackendID_WithPrivateKey(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -7,
		BackendID:    "",
		PrivateKey:   []byte{0x01, 0x02, 0x03},
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "software", cred.BackendType)
}

func TestCoverageBoostPhase2_StoredToFIDO2Credential_NoBackendID_NilPrivateKey(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -7,
		BackendID:    "",
		PrivateKey:   nil,
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "hardware", cred.BackendType)
}

func TestCoverageBoostPhase2_StoredToFIDO2Credential_UnknownAlgorithm(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -9999,
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, "COSE(-9999)", cred.Algorithm)
	assert.Contains(t, cred.KeyType, "Unknown")
}

func TestCoverageBoostPhase2_StoredToFIDO2Credential_CredProtect(t *testing.T) {
	stored := &authenticator.StoredCredential{
		CredentialID: []byte{0x01},
		RPID:         "example.com",
		Algorithm:    -7,
		CredProtect:  3,
	}
	cred := storedToFIDO2Credential(stored)
	assert.Equal(t, 3, cred.CredProtect)
}

// ===========================================================================
// Helper
// ===========================================================================

// createPhase2Authenticator creates a minimal authenticator for device service tests.
func createPhase2Authenticator(t *testing.T) *authenticator.Authenticator {
	t.Helper()

	store := authenticator.NewMemoryStorage()
	auth, err := authenticator.NewAuthenticator(&authenticator.Config{
		Storage:             store,
		AAGUID:              [16]byte{0x01, 0x02, 0x03, 0x04},
		EnableResidentKey:   true,
		EnablePIN:           false,
		RequireUserPresence: true,
		UserPresenceHandler: authenticator.NewAutoGrantHandler(),
	})
	require.NoError(t, err)
	return auth
}
