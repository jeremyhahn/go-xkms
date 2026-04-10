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
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/agent"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// ---------------------------------------------------------------------------
// Test-only audit logger that records all Log() calls.
// ---------------------------------------------------------------------------

type phase3AuditLogger struct {
	entries []audit.Entry
}

func (m *phase3AuditLogger) Log(e audit.Entry) { m.entries = append(m.entries, e) }
func (m *phase3AuditLogger) LogKeyOperation(_ audit.OperationType, _, _ string, _ bool, _ error, _ int64) {
}
func (m *phase3AuditLogger) LogCryptoOperation(_ audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) {
}
func (m *phase3AuditLogger) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) {
}
func (m *phase3AuditLogger) LogServiceEvent(_ audit.OperationType, _ map[string]any) {}
func (m *phase3AuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, _ error, _ map[string]any) {
	m.entries = append(m.entries, audit.Entry{Operation: op, Backend: backend, Success: success})
}
func (m *phase3AuditLogger) LogTPMOperation(_ audit.OperationType, _ bool, _ error, _ map[string]any) {
}
func (m *phase3AuditLogger) LogPasswordStoreOperation(op audit.OperationType, _ string, success bool, err error, _ map[string]any) {
	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	m.entries = append(m.entries, audit.Entry{Operation: op, Success: success, Error: errStr})
}
func (m *phase3AuditLogger) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) {
}

var _ audit.Logger = (*phase3AuditLogger)(nil)

// ---------------------------------------------------------------------------
// Test-only OATH store that tracks and fails on demand.
// ---------------------------------------------------------------------------

type phase3OATHStore struct {
	accounts map[string]*oath.Credential
	listErr  error
	addErr   error
	getErr   error
	delErr   error
	updErr   error
}

func newPhase3OATHStore() *phase3OATHStore {
	return &phase3OATHStore{accounts: make(map[string]*oath.Credential)}
}

func (s *phase3OATHStore) Add(c *oath.Credential) error {
	if s.addErr != nil {
		return s.addErr
	}
	s.accounts[c.ID] = c
	return nil
}
func (s *phase3OATHStore) Get(id string) (*oath.Credential, error) {
	if s.getErr != nil {
		return nil, s.getErr
	}
	c, ok := s.accounts[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}
func (s *phase3OATHStore) List() ([]*oath.Credential, error) {
	if s.listErr != nil {
		return nil, s.listErr
	}
	var out []*oath.Credential
	for _, c := range s.accounts {
		out = append(out, c)
	}
	return out, nil
}
func (s *phase3OATHStore) Delete(id string) error {
	if s.delErr != nil {
		return s.delErr
	}
	delete(s.accounts, id)
	return nil
}
func (s *phase3OATHStore) Update(c *oath.Credential) error {
	if s.updErr != nil {
		return s.updErr
	}
	s.accounts[c.ID] = c
	return nil
}
func (s *phase3OATHStore) Close() error { return nil }

var _ oath.Store = (*phase3OATHStore)(nil)

// ---------------------------------------------------------------------------
// Test-only agent enrollment store that fails on demand.
// ---------------------------------------------------------------------------

type phase3FailingAgentStore struct {
	listAgentsErr error
}

func (s *phase3FailingAgentStore) SaveAgent(_ *agent.AgentInfo) error { return nil }
func (s *phase3FailingAgentStore) GetAgent(_ string) (*agent.AgentInfo, error) {
	return nil, errors.New("not found")
}
func (s *phase3FailingAgentStore) ListAgents() ([]*agent.AgentInfo, error) {
	return nil, s.listAgentsErr
}
func (s *phase3FailingAgentStore) DeleteAgent(_ string) error { return nil }

var _ agent.EnrollmentStore = (*phase3FailingAgentStore)(nil)

// ===========================================================================
// Barrier Service - logBarrierEvent
// ===========================================================================

func TestCoverageBoostPhase3_BarrierService_LogBarrierEvent_NilLogger(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	// logBarrierEvent should be a no-op when no audit logger is set.
	svc.logBarrierEvent(audit.OpBarrierInitialized, true, nil, nil)
}

func TestCoverageBoostPhase3_BarrierService_LogBarrierEvent_WithError(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("test barrier error")
	svc.logBarrierEvent(audit.OpBarrierUnsealed, false, testErr, map[string]any{
		"strategy": "software",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpBarrierUnsealed, logger.entries[0].Operation)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "test barrier error", logger.entries[0].Error)
}

func TestCoverageBoostPhase3_BarrierService_LogBarrierEvent_Success(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logBarrierEvent(audit.OpBarrierSealed, true, nil, nil)

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpBarrierSealed, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
	assert.Empty(t, logger.entries[0].Error)
}

// ===========================================================================
// Barrier Service - assembleStrategy
// ===========================================================================

func TestCoverageBoostPhase3_BarrierService_AssembleStrategy_Software(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	strategy, err := svc.assembleStrategy("software")
	require.NoError(t, err)
	assert.NotNil(t, strategy)
}

func TestCoverageBoostPhase3_BarrierService_AssembleStrategy_InvalidStrategy(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	strategy, err := svc.assembleStrategy("invalid")
	assert.Nil(t, strategy)
	require.Error(t, err)
	var strategyErr *ErrBarrierStrategyUnavailable
	assert.True(t, errors.As(err, &strategyErr))
	assert.Equal(t, "invalid", strategyErr.Strategy)
}

func TestCoverageBoostPhase3_BarrierService_AssembleStrategy_TPM2_NilFn(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	// tpmSealerFn is nil by default.
	strategy, err := svc.assembleStrategy("tpm2")
	assert.Nil(t, strategy)
	require.Error(t, err)
}

// ===========================================================================
// Barrier Service - Unseal
// ===========================================================================

func TestCoverageBoostPhase3_BarrierService_Unseal_EmptyStrategy_Fallback(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	// Unseal with empty strategy when no root key exists triggers Initialize fallback.
	err := svc.Unseal("my-password", "")
	require.NoError(t, err)
	assert.True(t, svc.IsUnsealed())
}

func TestCoverageBoostPhase3_BarrierService_Unseal_PostUnsealHook_Error(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return errors.New("hook failed")
	})

	// Initialize the barrier first so Unseal finds it.
	err := svc.Initialize("test-pass", "software")
	require.NoError(t, err)

	// Seal it, then unseal to trigger hook.
	err = svc.Seal()
	require.NoError(t, err)

	err = svc.Unseal("test-pass", "software")
	require.NoError(t, err) // Hook errors are logged but don't fail Unseal.
	assert.True(t, hookCalled)
}

func TestCoverageBoostPhase3_BarrierService_Unseal_PostUnsealHook_Success(t *testing.T) {
	dir := t.TempDir()
	svc := NewBarrierService(dir, slog.Default())
	svc.SetContext(context.Background())

	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return nil
	})

	err := svc.Initialize("test-pass", "software")
	require.NoError(t, err)

	err = svc.Seal()
	require.NoError(t, err)

	err = svc.Unseal("test-pass", "software")
	require.NoError(t, err)
	assert.True(t, hookCalled)
}

// ===========================================================================
// Pairing Service - logPairingEvent
// ===========================================================================

func TestCoverageBoostPhase3_PairingService_LogPairingEvent_NilLogger(t *testing.T) {
	svc := NewPairingService(slog.Default())
	// No audit logger set, should be a no-op.
	svc.logPairingEvent(audit.OpPairingStarted, true, nil, nil)
}

func TestCoverageBoostPhase3_PairingService_LogPairingEvent_WithError(t *testing.T) {
	svc := NewPairingService(slog.Default())
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("pairing test error")
	svc.logPairingEvent(audit.OpPairingFailed, false, testErr, map[string]any{
		"origin": "chrome",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPairingFailed, logger.entries[0].Operation)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "pairing test error", logger.entries[0].Error)
}

func TestCoverageBoostPhase3_PairingService_LogPairingEvent_Success(t *testing.T) {
	svc := NewPairingService(slog.Default())
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPairingEvent(audit.OpPairingCompleted, true, nil, map[string]any{
		"origin": "firefox",
	})

	require.Len(t, logger.entries, 1)
	assert.True(t, logger.entries[0].Success)
	assert.Empty(t, logger.entries[0].Error)
}

// ===========================================================================
// Pairing Service - RequestPairing validation
// ===========================================================================

func TestCoverageBoostPhase3_PairingService_RequestPairing_EmptyIdentityKey(t *testing.T) {
	svc := NewPairingService(slog.Default())
	_, err := svc.RequestPairing("", "chrome")
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestCoverageBoostPhase3_PairingService_RequestPairing_EmptyOrigin(t *testing.T) {
	svc := NewPairingService(slog.Default())
	_, err := svc.RequestPairing("dGVzdA==", "")
	assert.ErrorIs(t, err, ErrPairingInvalidOrigin)
}

func TestCoverageBoostPhase3_PairingService_RequestPairing_InvalidBase64(t *testing.T) {
	svc := NewPairingService(slog.Default())
	_, err := svc.RequestPairing("not-valid-base64!!!", "chrome")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestCoverageBoostPhase3_PairingService_RequestPairing_NilVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	// Valid base64 but no verifier configured.
	_, err := svc.RequestPairing("dGVzdA==", "chrome")
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

// ===========================================================================
// Pairing Service - VerifyPairingCode validation
// ===========================================================================

func TestCoverageBoostPhase3_PairingService_VerifyPairingCode_EmptyIdentityKey(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.VerifyPairingCode("", "chrome", "123456")
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestCoverageBoostPhase3_PairingService_VerifyPairingCode_EmptyOrigin(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.VerifyPairingCode("dGVzdA==", "", "123456")
	assert.ErrorIs(t, err, ErrPairingInvalidOrigin)
}

func TestCoverageBoostPhase3_PairingService_VerifyPairingCode_EmptyCode(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.VerifyPairingCode("dGVzdA==", "chrome", "")
	assert.ErrorIs(t, err, ErrPairingInvalidCode)
}

func TestCoverageBoostPhase3_PairingService_VerifyPairingCode_InvalidBase64(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.VerifyPairingCode("not-valid!!!", "chrome", "123456")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPairingInvalidIdentityKey)
}

func TestCoverageBoostPhase3_PairingService_VerifyPairingCode_NilVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.VerifyPairingCode("dGVzdA==", "chrome", "123456")
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

// ===========================================================================
// Pairing Service - Unpair
// ===========================================================================

func TestCoverageBoostPhase3_PairingService_Unpair_NilVerifier(t *testing.T) {
	svc := NewPairingService(slog.Default())
	err := svc.Unpair("")
	assert.ErrorIs(t, err, ErrPairingNotConfigured)
}

// ===========================================================================
// Pairing Service - parseBrowser
// ===========================================================================

func TestCoverageBoostPhase3_PairingService_ParseBrowser_Chrome(t *testing.T) {
	b, err := parseBrowser("Chrome")
	require.NoError(t, err)
	assert.Equal(t, "chrome", string(b))
}

func TestCoverageBoostPhase3_PairingService_ParseBrowser_Firefox(t *testing.T) {
	b, err := parseBrowser("firefox")
	require.NoError(t, err)
	assert.Equal(t, "firefox", string(b))
}

func TestCoverageBoostPhase3_PairingService_ParseBrowser_Invalid(t *testing.T) {
	_, err := parseBrowser("opera")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrManifestInvalidBrowser)
}

// ===========================================================================
// OATH Service - logOATHEvent
// ===========================================================================

func TestCoverageBoostPhase3_OATHService_LogOATHEvent_NilLogger(t *testing.T) {
	svc := NewOATHService(nil)
	// No audit logger set, should be a no-op.
	svc.logOATHEvent(audit.OpOATHCredentialCreated, true, nil, nil)
}

func TestCoverageBoostPhase3_OATHService_LogOATHEvent_WithError(t *testing.T) {
	svc := NewOATHService(nil)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("oath test error")
	svc.logOATHEvent(audit.OpOATHCredentialCreated, false, testErr, map[string]any{
		"issuer": "test",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpOATHCredentialCreated, logger.entries[0].Operation)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "oath test error", logger.entries[0].Error)
}

func TestCoverageBoostPhase3_OATHService_LogOATHEvent_Success(t *testing.T) {
	svc := NewOATHService(nil)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logOATHEvent(audit.OpOATHCodeGenerated, true, nil, nil)

	require.Len(t, logger.entries, 1)
	assert.True(t, logger.entries[0].Success)
	assert.Empty(t, logger.entries[0].Error)
}

// ===========================================================================
// OATH Service - AddAccountFromURI
// ===========================================================================

func TestCoverageBoostPhase3_OATHService_AddAccountFromURI_EmptyURI(t *testing.T) {
	svc := NewOATHService(newPhase3OATHStore())
	_, err := svc.AddAccountFromURI("")
	assert.ErrorIs(t, err, ErrOATHInvalidURI)
}

func TestCoverageBoostPhase3_OATHService_AddAccountFromURI_InvalidScheme(t *testing.T) {
	svc := NewOATHService(newPhase3OATHStore())
	_, err := svc.AddAccountFromURI("https://example.com")
	assert.ErrorIs(t, err, ErrOATHQRInvalidURI)
}

func TestCoverageBoostPhase3_OATHService_AddAccountFromURI_ValidTOTP(t *testing.T) {
	svc := NewOATHService(newPhase3OATHStore())
	acct, err := svc.AddAccountFromURI("otpauth://totp/Example:user@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, "totp", acct.Type)
	assert.Equal(t, "Example", acct.Issuer)
}

// ===========================================================================
// OATH Service - AddAccountManual
// ===========================================================================

func TestCoverageBoostPhase3_OATHService_AddAccountManual_NilStore(t *testing.T) {
	svc := NewOATHService(nil)
	_, err := svc.AddAccountManual("user", "issuer", "JBSWY3DPEHPK3PXP")
	assert.ErrorIs(t, err, ErrOATHStoreNotSet)
}

func TestCoverageBoostPhase3_OATHService_AddAccountManual_EmptySecret(t *testing.T) {
	svc := NewOATHService(newPhase3OATHStore())
	_, err := svc.AddAccountManual("user", "issuer", "")
	assert.ErrorIs(t, err, ErrOATHMissingSecret)
}

func TestCoverageBoostPhase3_OATHService_AddAccountManual_Success(t *testing.T) {
	store := newPhase3OATHStore()
	svc := NewOATHService(store)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	acct, err := svc.AddAccountManual("user@example.com", "TestIssuer", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	require.NotNil(t, acct)
	assert.Equal(t, "TestIssuer", acct.Issuer)
	assert.Equal(t, "totp", acct.Type)

	// Verify audit entry was logged.
	require.NotEmpty(t, logger.entries)
	assert.Equal(t, audit.OpOATHCredentialCreated, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

func TestCoverageBoostPhase3_OATHService_AddAccountManual_StoreAddError(t *testing.T) {
	store := newPhase3OATHStore()
	store.addErr = errors.New("store add failed")
	svc := NewOATHService(store)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	_, err := svc.AddAccountManual("user", "issuer", "JBSWY3DPEHPK3PXP")
	require.Error(t, err)
	assert.Equal(t, "store add failed", err.Error())

	// Verify failure audit entry.
	require.NotEmpty(t, logger.entries)
	assert.False(t, logger.entries[0].Success)
}

// ===========================================================================
// OATH Service - DeleteAccount
// ===========================================================================

func TestCoverageBoostPhase3_OATHService_DeleteAccount_StoreError(t *testing.T) {
	store := newPhase3OATHStore()
	store.delErr = errors.New("delete failed")
	svc := NewOATHService(store)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.DeleteAccount("some-id")
	require.Error(t, err)
	assert.Equal(t, "delete failed", err.Error())

	// Verify failure audit.
	require.NotEmpty(t, logger.entries)
	assert.Equal(t, audit.OpOATHCredentialDeleted, logger.entries[0].Operation)
	assert.False(t, logger.entries[0].Success)
}

func TestCoverageBoostPhase3_OATHService_DeleteAccount_Success(t *testing.T) {
	store := newPhase3OATHStore()
	store.accounts["test-id"] = &oath.Credential{ID: "test-id"}
	svc := NewOATHService(store)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.DeleteAccount("test-id")
	require.NoError(t, err)

	require.NotEmpty(t, logger.entries)
	assert.Equal(t, audit.OpOATHCredentialDeleted, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

// ===========================================================================
// OATH Service - GenerateHOTP wrong type
// ===========================================================================

func TestCoverageBoostPhase3_OATHService_GenerateHOTP_WrongType(t *testing.T) {
	store := newPhase3OATHStore()
	store.accounts["totp-id"] = &oath.Credential{
		ID:   "totp-id",
		Type: oath.TypeTOTP, // Not HOTP
	}
	svc := NewOATHService(store)

	_, err := svc.GenerateHOTP("totp-id")
	assert.ErrorIs(t, err, ErrOATHGenerateFailed)
}

// ===========================================================================
// PIN Service - logPINOperation
// ===========================================================================

func TestCoverageBoostPhase3_PINService_LogPINOperation_NilLogger(t *testing.T) {
	svc := NewPINService()
	// No audit logger set, should be a no-op.
	svc.logPINOperation(audit.OpPINVerified, true, nil, nil)
}

func TestCoverageBoostPhase3_PINService_LogPINOperation_WithLogger(t *testing.T) {
	svc := NewPINService()
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPINOperation(audit.OpPINVerified, true, nil, map[string]any{"type": "user_pin"})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPINVerified, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

func TestCoverageBoostPhase3_PINService_LogPINOperation_WithLoggerAndPINService(t *testing.T) {
	svc := NewPINService()
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	// Create a real pin.Service and set it.
	backend := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pinSvc)

	svc.logPINOperation(audit.OpPINChanged, true, nil, nil)

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPINChanged, logger.entries[0].Operation)
	// Backend should be populated from the pin.Service strategy.
	assert.NotEmpty(t, logger.entries[0].Backend)
}

// ===========================================================================
// PIN Service - GetPINStatus / IsPINSet / VerifyFIDO2Hash without service
// ===========================================================================

func TestCoverageBoostPhase3_PINService_GetPINStatus_NoService(t *testing.T) {
	svc := NewPINService()
	_, err := svc.GetPINStatus()
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestCoverageBoostPhase3_PINService_IsPINSet_NoService(t *testing.T) {
	svc := NewPINService()
	assert.False(t, svc.IsPINSet())
}

func TestCoverageBoostPhase3_PINService_VerifyFIDO2Hash_NoService(t *testing.T) {
	svc := NewPINService()
	assert.False(t, svc.VerifyFIDO2Hash([]byte("test")))
}

func TestCoverageBoostPhase3_PINService_IsPINSet_WithService(t *testing.T) {
	svc := NewPINService()
	backend := &wizardMockPINBackend{strategy: pin.StrategySoftware}
	pinSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pinSvc)
	// Backend starts with no PIN set.
	assert.False(t, svc.IsPINSet())
}

// ===========================================================================
// Share Service - ListShares
// ===========================================================================

func TestCoverageBoostPhase3_ShareService_ListShares_NilStore(t *testing.T) {
	svc := NewShareService()
	_, err := svc.ListShares()
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestCoverageBoostPhase3_ShareService_ListShares_StoreError(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{
		listErr: errors.New("list failed"),
	})

	_, err := svc.ListShares()
	require.Error(t, err)
	assert.Equal(t, "list failed", err.Error())
}

func TestCoverageBoostPhase3_ShareService_ListShares_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{
		listResult: []*sharestore.ShareEntry{
			{
				ServerURL:  "https://example.com",
				GroupID:    "grp-1",
				ShareIndex: 1,
			},
		},
	})

	infos, err := svc.ListShares()
	require.NoError(t, err)
	require.Len(t, infos, 1)
	assert.Equal(t, "https://example.com", infos[0].ServerURL)
}

// ===========================================================================
// Share Service - ImportShare
// ===========================================================================

func TestCoverageBoostPhase3_ShareService_ImportShare_EmptyPath(t *testing.T) {
	svc := NewShareService()
	_, err := svc.ImportShare("")
	assert.ErrorIs(t, err, ErrEmptyFilePath)
}

func TestCoverageBoostPhase3_ShareService_ImportShare_NilStore(t *testing.T) {
	svc := NewShareService()
	_, err := svc.ImportShare("/some/path")
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestCoverageBoostPhase3_ShareService_ImportShare_FileNotFound(t *testing.T) {
	svc := NewShareService()
	svc.SetShareStore(&mockShareStore{})
	_, err := svc.ImportShare("/nonexistent/file.json")
	assert.ErrorIs(t, err, ErrShareImportFailed)
}

func TestCoverageBoostPhase3_ShareService_ImportShare_InvalidJSON(t *testing.T) {
	svc := NewShareService()
	svc.SetShareStore(&mockShareStore{})

	dir := t.TempDir()
	filePath := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(filePath, []byte("not json"), 0600))

	_, err := svc.ImportShare(filePath)
	assert.ErrorIs(t, err, ErrShareImportFailed)
}

func TestCoverageBoostPhase3_ShareService_ImportShare_ValidationFailure(t *testing.T) {
	svc := NewShareService()
	svc.SetShareStore(&mockShareStore{})

	// Write valid JSON but missing required fields.
	dir := t.TempDir()
	filePath := filepath.Join(dir, "empty.json")
	data, _ := json.Marshal(sharestore.ShareEntry{})
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	_, err := svc.ImportShare(filePath)
	require.Error(t, err)
}

func TestCoverageBoostPhase3_ShareService_ImportShare_SaveError(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{
		saveErr: errors.New("save failed"),
	})

	dir := t.TempDir()
	filePath := filepath.Join(dir, "valid.json")
	entry := sharestore.ShareEntry{
		ServerURL:  "https://example.com",
		GroupID:    "grp-1",
		ShareIndex: 1,
		ShareData:  []byte("secret"),
	}
	data, _ := json.Marshal(entry)
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	_, err := svc.ImportShare(filePath)
	require.Error(t, err)
	assert.Equal(t, "save failed", err.Error())
}

func TestCoverageBoostPhase3_ShareService_ImportShare_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{})

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	dir := t.TempDir()
	filePath := filepath.Join(dir, "valid.json")
	entry := sharestore.ShareEntry{
		ServerURL:  "https://example.com",
		GroupID:    "grp-1",
		ShareIndex: 1,
		ShareData:  []byte("secret"),
	}
	data, _ := json.Marshal(entry)
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	info, err := svc.ImportShare(filePath)
	require.NoError(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "https://example.com", info.ServerURL)
	assert.Equal(t, "grp-1", info.GroupID)

	// Verify event emission.
	require.NotEmpty(t, emittedEvents)
	assert.Equal(t, events.EventShareImported, emittedEvents[0].Type)
}

// ===========================================================================
// Share Service - DeleteShare
// ===========================================================================

func TestCoverageBoostPhase3_ShareService_DeleteShare_EmptyServerURL(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("", "grp-1", 0)
	assert.ErrorIs(t, err, ErrEmptyServerURL)
}

func TestCoverageBoostPhase3_ShareService_DeleteShare_EmptyGroupID(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("https://example.com", "", 0)
	assert.ErrorIs(t, err, ErrEmptyGroupID)
}

func TestCoverageBoostPhase3_ShareService_DeleteShare_NilStore(t *testing.T) {
	svc := NewShareService()
	err := svc.DeleteShare("https://example.com", "grp-1", 0)
	assert.ErrorIs(t, err, ErrShareStoreNil)
}

func TestCoverageBoostPhase3_ShareService_DeleteShare_StoreError(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{
		deleteErr: errors.New("delete failed"),
	})

	err := svc.DeleteShare("https://example.com", "grp-1", 0)
	require.Error(t, err)
	assert.Equal(t, "delete failed", err.Error())
}

func TestCoverageBoostPhase3_ShareService_DeleteShare_Success(t *testing.T) {
	svc := NewShareService()
	svc.SetContext(context.Background())
	svc.SetShareStore(&mockShareStore{})

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	err := svc.DeleteShare("https://example.com", "grp-1", 0)
	require.NoError(t, err)

	// Verify event emission.
	require.NotEmpty(t, emittedEvents)
	assert.Equal(t, events.EventShareDeleted, emittedEvents[0].Type)
}

// ===========================================================================
// Agent Service - ApproveEnrollment
// ===========================================================================

func TestCoverageBoostPhase3_AgentService_ApproveEnrollment_EmptyRequestID(t *testing.T) {
	svc := NewAgentService()
	err := svc.ApproveEnrollment("")
	assert.ErrorIs(t, err, ErrAgentEmptyRequestID)
}

func TestCoverageBoostPhase3_AgentService_ApproveEnrollment_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	err := svc.ApproveEnrollment("req-123")
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

// ===========================================================================
// Agent Service - RejectEnrollment
// ===========================================================================

func TestCoverageBoostPhase3_AgentService_RejectEnrollment_EmptyRequestID(t *testing.T) {
	svc := NewAgentService()
	err := svc.RejectEnrollment("", "bad actor")
	assert.ErrorIs(t, err, ErrAgentEmptyRequestID)
}

func TestCoverageBoostPhase3_AgentService_RejectEnrollment_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	err := svc.RejectEnrollment("req-123", "reason")
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

// ===========================================================================
// Agent Service - ListPendingEnrollments
// ===========================================================================

func TestCoverageBoostPhase3_AgentService_ListPendingEnrollments_NilEnrollment(t *testing.T) {
	svc := NewAgentService()
	_, err := svc.ListPendingEnrollments()
	assert.ErrorIs(t, err, ErrAgentServiceNotReady)
}

// ===========================================================================
// Agent Service - ListAgents
// ===========================================================================

func TestCoverageBoostPhase3_AgentService_ListAgents_NilStore(t *testing.T) {
	svc := NewAgentService()
	_, err := svc.ListAgents()
	assert.ErrorIs(t, err, ErrAgentNilStore)
}

func TestCoverageBoostPhase3_AgentService_ListAgents_StoreError(t *testing.T) {
	svc := NewAgentService()
	svc.SetEnrollmentStore(&phase3FailingAgentStore{
		listAgentsErr: errors.New("list agents failed"),
	})

	_, err := svc.ListAgents()
	assert.ErrorIs(t, err, ErrAgentEnrollmentFailed)
}

// ===========================================================================
// Browser Service - openSystemBrowser
// ===========================================================================

func TestCoverageBoostPhase3_BrowserService_OpenSystemBrowser_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	ctx := context.Background()
	svc.SetContext(ctx)

	var recorded [][]string
	var mu sync.Mutex
	svc.execCommand = fakeExecCommand(&recorded, &mu)

	err = svc.openSystemBrowser(ctx, "https://example.com")
	require.NoError(t, err)

	mu.Lock()
	defer mu.Unlock()
	require.NotEmpty(t, recorded)
}

func TestCoverageBoostPhase3_BrowserService_OpenSystemBrowser_Failure(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	ctx := context.Background()
	svc.SetContext(ctx)
	svc.execCommand = failingExecCommand()

	err = svc.openSystemBrowser(ctx, "https://example.com")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserLaunchFailed)
}

// ===========================================================================
// Browser Service - saveConfig
// ===========================================================================

func TestCoverageBoostPhase3_BrowserService_SaveConfig_Success(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "subdir", "browser.json")
	svc, err := NewBrowserService(configPath, slog.Default())
	require.NoError(t, err)

	config := BrowserConfig{
		DefaultBrowser: BrowserSystem,
	}
	err = svc.saveConfig(config)
	require.NoError(t, err)

	// Verify file was written.
	_, statErr := os.Stat(configPath)
	assert.NoError(t, statErr)
}

func TestCoverageBoostPhase3_BrowserService_SaveConfig_InvalidPath(t *testing.T) {
	svc := &BrowserService{
		configPath: "/dev/null/impossible/path.json",
		logger:     slog.Default(),
	}
	err := svc.saveConfig(BrowserConfig{DefaultBrowser: BrowserSystem})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrBrowserConfigSave)
}

// ===========================================================================
// Browser Service - knownBrowsers
// ===========================================================================

func TestCoverageBoostPhase3_BrowserService_KnownBrowsers(t *testing.T) {
	browsers := knownBrowsers()
	// On Linux or Darwin, we should get a non-empty list.
	// On other platforms, it returns nil.
	if browsers != nil {
		assert.NotEmpty(t, browsers)
		for _, b := range browsers {
			assert.NotEmpty(t, b.Name)
			assert.NotEmpty(t, b.Path)
		}
	}
}

// ===========================================================================
// Connection Service - Connect
// ===========================================================================

func TestCoverageBoostPhase3_ConnectionService_Connect_AlreadyConnected(t *testing.T) {
	svc := NewConnectionService()
	// Simulate connected state.
	svc.state.Store(&ConnectionInfo{State: "connected"})

	_, err := svc.Connect("rest", "localhost:8080", false, "", "")
	assert.ErrorIs(t, err, ErrServerAlreadyConnected)
}

func TestCoverageBoostPhase3_ConnectionService_Connect_EmptyAddress(t *testing.T) {
	svc := NewConnectionService()
	_, err := svc.Connect("rest", "", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidAddress)
}

func TestCoverageBoostPhase3_ConnectionService_Connect_InvalidProtocol(t *testing.T) {
	svc := NewConnectionService()
	_, err := svc.Connect("invalid", "localhost:8080", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidProtocol)
}

// ===========================================================================
// Key Service - BrowseFile / SaveFileAs
// ===========================================================================

func TestCoverageBoostPhase3_KeyService_BrowseFile_NilContext(t *testing.T) {
	svc := NewKeyService()
	_, err := svc.BrowseFile()
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

func TestCoverageBoostPhase3_KeyService_SaveFileAs_NilContext(t *testing.T) {
	svc := NewKeyService()
	_, err := svc.SaveFileAs("test.pem")
	assert.ErrorIs(t, err, ErrKeyServiceNoClient)
}

// ===========================================================================
// Key Service - EncryptFile / DecryptFile
// ===========================================================================

func TestCoverageBoostPhase3_KeyService_EncryptFile_FileReadError(t *testing.T) {
	svc := NewKeyService()
	err := svc.EncryptFile("local", "sw", "key1", "/nonexistent/file", "/tmp/out", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestCoverageBoostPhase3_KeyService_DecryptFile_FileReadError(t *testing.T) {
	svc := NewKeyService()
	err := svc.DecryptFile("local", "sw", "key1", "/nonexistent/file", "/tmp/out", "base64")
	assert.ErrorIs(t, err, ErrFileReadFailed)
}

func TestCoverageBoostPhase3_KeyService_DecryptFile_HexDecodeError(t *testing.T) {
	svc := NewKeyService()

	dir := t.TempDir()
	inPath := filepath.Join(dir, "bad-hex.enc")
	require.NoError(t, os.WriteFile(inPath, []byte("not-valid-hex!@#$"), 0600))

	err := svc.DecryptFile("local", "sw", "key1", inPath, filepath.Join(dir, "out"), "hex")
	require.Error(t, err) // hex.DecodeString should fail
}

// ===========================================================================
// App Lock Service - Unlock
// ===========================================================================

func TestCoverageBoostPhase3_AppLockService_Unlock_EmptyPIN(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.LockForStartup()
	err := svc.Unlock("")
	assert.ErrorIs(t, err, ErrAppLockPINRequired)
}

func TestCoverageBoostPhase3_AppLockService_Unlock_AlreadyUnlocked(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	// Starts unlocked by default.
	err := svc.Unlock("1234")
	assert.ErrorIs(t, err, ErrAppLockAlreadyUnlocked)
}

func TestCoverageBoostPhase3_AppLockService_Unlock_BarrierSealed_Success(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
	}

	svc := NewAppLockService(nil, barrier)
	svc.LockForStartup()

	err := svc.Unlock("test-password")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
}

func TestCoverageBoostPhase3_AppLockService_Unlock_BarrierSealed_Failure(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   errors.New("bad password"),
	}

	svc := NewAppLockService(nil, barrier)
	svc.LockForStartup()

	err := svc.Unlock("wrong-password")
	assert.ErrorIs(t, err, ErrAppLockPINInvalid)
	assert.True(t, svc.IsLocked())
}

func TestCoverageBoostPhase3_AppLockService_Unlock_NoPINService(t *testing.T) {
	// Barrier configured but not initialized = falls to PIN path.
	barrier := &mockBarrierService{
		initialized: false,
		sealed:      true,
	}

	svc := NewAppLockService(nil, barrier)
	svc.LockForStartup()

	err := svc.Unlock("1234")
	assert.ErrorIs(t, err, ErrAppLockPINInvalid) // No PIN service
}

func TestCoverageBoostPhase3_AppLockService_Unlock_BarrierConfigured_NotInitialized(t *testing.T) {
	barrier := &mockBarrierService{
		initialized: false,
		sealed:      true,
	}

	pinSvc := newWizardPINService(&wizardMockPINBackend{})

	svc := NewAppLockService(pinSvc, barrier)
	svc.LockForStartup()

	// PIN not set -> setup incomplete.
	err := svc.Unlock("1234")
	assert.ErrorIs(t, err, ErrAppLockSetupIncomplete)
}

// ===========================================================================
// Seal Protection Service - logSealProtectionEvent
// ===========================================================================

func TestCoverageBoostPhase3_SealProtectionService_LogEvent_NilLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	// Should be a no-op.
	svc.logSealProtectionEvent(audit.OpPasswordStoreUnlocked, true, nil, nil)
}

func TestCoverageBoostPhase3_SealProtectionService_LogEvent_WithLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, true, nil, map[string]any{
		"trigger": "auto_lock",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPasswordStoreLocked, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

func TestCoverageBoostPhase3_SealProtectionService_LogEvent_WithError(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("seal error")
	svc.logSealProtectionEvent(audit.OpPasswordStoreUnlocked, false, testErr, nil)

	require.Len(t, logger.entries, 1)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "seal error", logger.entries[0].Error)
}

// ===========================================================================
// Seal Protection Service - Unlock / Lock already states
// ===========================================================================

func TestCoverageBoostPhase3_PasswordProtection_LogOp_NilLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	// No audit logger set, should be a no-op.
	svc.logPasswordStoreOp(audit.OpPasswordStoreUnlocked, "user", true, nil, nil)
}

func TestCoverageBoostPhase3_PasswordProtection_LogOp_WithLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	logger := &phase3AuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPasswordStoreOp(audit.OpPasswordStoreLocked, "user", true, nil, nil)

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPasswordStoreLocked, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

// ===========================================================================
// Password Protection Service - Unlock / Lock already states
// ===========================================================================

func TestCoverageBoostPhase3_PasswordProtection_Export_NilStore(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	// Starts unlocked, no static pw store.
	_, err := svc.ExportPasswordsDecrypted("")
	assert.ErrorIs(t, err, ErrPPNotConfigured)
}
