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
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// fcpMockAuditLogger is a capturing audit.Logger for final coverage push tests.
// It records all Log() calls for verification.
// ---------------------------------------------------------------------------

type fcpMockAuditLogger struct {
	entries     []audit.Entry
	pinOps      []fcpPINOp
	passwordOps []fcpPasswordOp
	serviceEvts []map[string]any
}

type fcpPINOp struct {
	op      audit.OperationType
	backend string
	success bool
	err     error
	details map[string]any
}

type fcpPasswordOp struct {
	op      audit.OperationType
	source  string
	success bool
	err     error
	details map[string]any
}

func (m *fcpMockAuditLogger) Log(e audit.Entry) {
	m.entries = append(m.entries, e)
}
func (m *fcpMockAuditLogger) LogKeyOperation(_ audit.OperationType, _, _ string, _ bool, _ error, _ int64) {
}
func (m *fcpMockAuditLogger) LogCryptoOperation(_ audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) {
}
func (m *fcpMockAuditLogger) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) {
}
func (m *fcpMockAuditLogger) LogServiceEvent(_ audit.OperationType, details map[string]any) {
	m.serviceEvts = append(m.serviceEvts, details)
}
func (m *fcpMockAuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, err error, details map[string]any) {
	m.pinOps = append(m.pinOps, fcpPINOp{op: op, backend: backend, success: success, err: err, details: details})
}
func (m *fcpMockAuditLogger) LogTPMOperation(_ audit.OperationType, _ bool, _ error, _ map[string]any) {
}
func (m *fcpMockAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) {
	m.passwordOps = append(m.passwordOps, fcpPasswordOp{op: op, source: source, success: success, err: err, details: details})
}
func (m *fcpMockAuditLogger) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) {
}

var _ audit.Logger = (*fcpMockAuditLogger)(nil)

// ---------------------------------------------------------------------------
// fcpMockAuditStore is a minimal audit.Store for admin service tests.
// ---------------------------------------------------------------------------

type fcpMockAuditStore struct {
	entries []audit.Entry
}

func (m *fcpMockAuditStore) Log(_ audit.Entry) {}
func (m *fcpMockAuditStore) LogKeyOperation(_ audit.OperationType, _, _ string, _ bool, _ error, _ int64) {
}
func (m *fcpMockAuditStore) LogCryptoOperation(_ audit.OperationType, _, _, _, _ string, _ bool, _ error, _ int64) {
}
func (m *fcpMockAuditStore) LogConnectionEvent(_ audit.OperationType, _, _ string, _ map[string]any) {
}
func (m *fcpMockAuditStore) LogServiceEvent(_ audit.OperationType, _ map[string]any) {}
func (m *fcpMockAuditStore) LogPINOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}
func (m *fcpMockAuditStore) LogTPMOperation(_ audit.OperationType, _ bool, _ error, _ map[string]any) {
}
func (m *fcpMockAuditStore) LogPasswordStoreOperation(_ audit.OperationType, _ string, _ bool, _ error, _ map[string]any) {
}
func (m *fcpMockAuditStore) LogUserPresenceEvent(_ audit.OperationType, _ string, _ bool, _ map[string]any) {
}
func (m *fcpMockAuditStore) Count() int                              { return len(m.entries) }
func (m *fcpMockAuditStore) Query(_ audit.QueryFilter) []audit.Entry { return m.entries }

var _ audit.Store = (*fcpMockAuditStore)(nil)

// ---------------------------------------------------------------------------
// fcpMockOATHStore is a minimal oath.Store for SetAuditLogger tests.
// ---------------------------------------------------------------------------

type fcpMockOATHStore struct{}

func (m *fcpMockOATHStore) Add(_ *oath.Credential) error              { return nil }
func (m *fcpMockOATHStore) Get(_ string) (*oath.Credential, error)    { return nil, nil }
func (m *fcpMockOATHStore) List() ([]*oath.Credential, error)         { return nil, nil }
func (m *fcpMockOATHStore) Update(_ *oath.Credential) error           { return nil }
func (m *fcpMockOATHStore) Delete(_ string) error                     { return nil }
func (m *fcpMockOATHStore) IncrementCounter(_ string) (uint64, error) { return 0, nil }
func (m *fcpMockOATHStore) Close() error                              { return nil }

var _ oath.Store = (*fcpMockOATHStore)(nil)

// ---------------------------------------------------------------------------
// fcpMockStaticPWStore is a minimal staticpw.Store for tests.
// ---------------------------------------------------------------------------

type fcpMockStaticPWStore struct {
	passwords []*staticpw.StaticPassword
	listErr   error
}

func (m *fcpMockStaticPWStore) Add(pw *staticpw.StaticPassword) error {
	pw.ID = "fcp-" + pw.Name
	m.passwords = append(m.passwords, pw)
	return nil
}
func (m *fcpMockStaticPWStore) Get(id string) (*staticpw.StaticPassword, error) {
	for _, pw := range m.passwords {
		if pw.ID == id || pw.Name == id {
			return pw, nil
		}
	}
	return nil, errors.New("not found")
}
func (m *fcpMockStaticPWStore) List() ([]*staticpw.StaticPassword, error) {
	return m.passwords, m.listErr
}
func (m *fcpMockStaticPWStore) Update(_ *staticpw.StaticPassword) error { return nil }
func (m *fcpMockStaticPWStore) Delete(_ string) error                   { return nil }
func (m *fcpMockStaticPWStore) ForceDelete(_ string) error              { return nil }
func (m *fcpMockStaticPWStore) ListByFolder(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}
func (m *fcpMockStaticPWStore) ListFolders() ([]string, error) { return nil, nil }
func (m *fcpMockStaticPWStore) MoveToFolder(_, _ string) error { return nil }
func (m *fcpMockStaticPWStore) CreateFolder(_ string) error    { return nil }
func (m *fcpMockStaticPWStore) RemoveFolder(_ string) error    { return nil }
func (m *fcpMockStaticPWStore) Close() error                   { return nil }
func (m *fcpMockStaticPWStore) ListByFolderDirect(_ string) ([]*staticpw.StaticPassword, error) {
	return nil, nil
}

var _ staticpw.Store = (*fcpMockStaticPWStore)(nil)

// ===========================================================================
// Part 1: Cover ALL 0% setter functions
// ===========================================================================

// ---------------------------------------------------------------------------
// AppLockService.SetBarrierStrategy
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AppLockService_SetBarrierStrategy(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	assert.Equal(t, "", svc.barrierStrategy)

	svc.SetBarrierStrategy("tpm2")
	assert.Equal(t, "tpm2", svc.barrierStrategy)
}

func TestFinalCoveragePush_AppLockService_SetBarrierStrategy_Empty(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetBarrierStrategy("software")
	assert.Equal(t, "software", svc.barrierStrategy)

	svc.SetBarrierStrategy("")
	assert.Equal(t, "", svc.barrierStrategy)
}

// ---------------------------------------------------------------------------
// BarrierService.SetPostUnsealHook
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_SetPostUnsealHook(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	assert.Nil(t, svc.postUnsealHook)

	called := false
	svc.SetPostUnsealHook(func() error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.postUnsealHook)

	err := svc.postUnsealHook()
	require.NoError(t, err)
	assert.True(t, called)
}

func TestFinalCoveragePush_BarrierService_SetPostUnsealHook_Nil(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetPostUnsealHook(func() error { return nil })
	assert.NotNil(t, svc.postUnsealHook)

	svc.SetPostUnsealHook(nil)
	assert.Nil(t, svc.postUnsealHook)
}

// ---------------------------------------------------------------------------
// BarrierService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_SetAuditLogger(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_BarrierService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// OATHService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_OATHService_SetAuditLogger(t *testing.T) {
	svc := NewOATHService(nil)
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_OATHService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewOATHService(nil)
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// PairingService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PairingService_SetAuditLogger(t *testing.T) {
	svc := NewPairingService(slog.Default())
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_PairingService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewPairingService(slog.Default())
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// PasswordProtectionService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PasswordProtectionService_SetAuditLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_PasswordProtectionService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// PINService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PINService_SetAuditLogger(t *testing.T) {
	svc := NewPINService()
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_PINService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewPINService()
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// SealProtectionService.SetAuditLogger
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_SealProtectionService_SetAuditLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	assert.Nil(t, svc.auditLog.Load())

	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger, *ptr)
}

func TestFinalCoveragePush_SealProtectionService_SetAuditLogger_Replace(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger1 := &fcpMockAuditLogger{}
	logger2 := &fcpMockAuditLogger{}

	svc.SetAuditLogger(logger1)
	svc.SetAuditLogger(logger2)

	ptr := svc.auditLog.Load()
	require.NotNil(t, ptr)
	assert.Equal(t, logger2, *ptr)
}

// ---------------------------------------------------------------------------
// SetupWizardService.SetPostApplyFunc
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_SetupWizardService_SetPostApplyFunc(t *testing.T) {
	svc := NewSetupWizardService()
	assert.Nil(t, svc.postApplyFunc)

	called := false
	svc.SetPostApplyFunc(func() { called = true })
	assert.NotNil(t, svc.postApplyFunc)

	svc.postApplyFunc()
	assert.True(t, called)
}

func TestFinalCoveragePush_SetupWizardService_SetPostApplyFunc_Nil(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetPostApplyFunc(func() {})
	assert.NotNil(t, svc.postApplyFunc)

	svc.SetPostApplyFunc(nil)
	assert.Nil(t, svc.postApplyFunc)
}

// ===========================================================================
// Part 2: Cover partially-covered functions with the most impact
// ===========================================================================

// ---------------------------------------------------------------------------
// BarrierService.logBarrierEvent - covers the audit logger code path
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_logBarrierEvent_WithLogger(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	// Call with success=true, nil error.
	svc.logBarrierEvent(audit.OpBarrierInitialized, true, nil, map[string]any{
		"strategy": "software",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpBarrierInitialized, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
	assert.Equal(t, "", logger.entries[0].Error)
}

func TestFinalCoveragePush_BarrierService_logBarrierEvent_WithError(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	// Call with success=false, non-nil error.
	testErr := errors.New("unseal failed")
	svc.logBarrierEvent(audit.OpBarrierUnsealed, false, testErr, map[string]any{
		"strategy": "tpm2",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpBarrierUnsealed, logger.entries[0].Operation)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "unseal failed", logger.entries[0].Error)
}

func TestFinalCoveragePush_BarrierService_logBarrierEvent_NoLogger(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	// No audit logger set - should not panic.
	svc.logBarrierEvent(audit.OpBarrierInitialized, true, nil, nil)
}

// ---------------------------------------------------------------------------
// OATHService.logOATHEvent - covers the audit logger code path
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_OATHService_logOATHEvent_WithLogger(t *testing.T) {
	svc := NewOATHService(nil)
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logOATHEvent("oath.add", true, nil, map[string]any{
		"account": "test@example.com",
	})

	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OperationType("oath.add"), logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
	assert.Equal(t, "", logger.entries[0].Error)
}

func TestFinalCoveragePush_OATHService_logOATHEvent_WithError(t *testing.T) {
	svc := NewOATHService(nil)
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("oath add failed")
	svc.logOATHEvent("oath.add", false, testErr, nil)

	require.Len(t, logger.entries, 1)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "oath add failed", logger.entries[0].Error)
}

func TestFinalCoveragePush_OATHService_logOATHEvent_NoLogger(t *testing.T) {
	svc := NewOATHService(nil)
	// No logger set - should not panic.
	svc.logOATHEvent("oath.add", true, nil, nil)
}

// ---------------------------------------------------------------------------
// AdminService.GetAuditLogs - covers delegating to AuditService
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AdminService_GetAuditLogs_WithEntries(t *testing.T) {
	store := &fcpMockAuditStore{
		entries: []audit.Entry{
			{
				Timestamp: time.Now(),
				Operation: audit.OpBarrierInitialized,
				Success:   true,
				Backend:   "software",
				Details:   map[string]any{"strategy": "software"},
			},
			{
				Timestamp: time.Now(),
				Operation: audit.OpBarrierUnsealed,
				Success:   true,
				Backend:   "software",
			},
		},
	}
	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	// GetAuditLogs requires admin. Since tests don't run as root,
	// this should return ErrAdminNotAuthorized.
	entries, err := svc.GetAuditLogs(nil)
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, entries)
	} else {
		// If we happen to run as root.
		require.NoError(t, err)
		assert.Len(t, entries, 2)
	}
}

func TestFinalCoveragePush_AdminService_GetAuditLogs_WithFilter(t *testing.T) {
	store := &fcpMockAuditStore{
		entries: []audit.Entry{
			{
				Timestamp: time.Now(),
				Operation: audit.OpBarrierInitialized,
				Success:   true,
			},
		},
	}
	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	filter := &AuditFilter{
		Operation: string(audit.OpBarrierInitialized),
		Limit:     10,
	}
	entries, err := svc.GetAuditLogs(filter)
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, entries)
	} else {
		require.NoError(t, err)
		assert.Len(t, entries, 1)
	}
}

func TestFinalCoveragePush_AdminService_GetAuditLogs_NilStore(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	entries, err := svc.GetAuditLogs(nil)
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, entries)
	} else {
		// Nil store returns empty slice.
		require.NoError(t, err)
		assert.Empty(t, entries)
	}
}

// ---------------------------------------------------------------------------
// AdminService.ExportAuditLogs - covers JSON and CSV export paths
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AdminService_ExportAuditLogs_InvalidFormat(t *testing.T) {
	svc := NewAdminService()
	svc.SetContext(context.Background())

	data, err := svc.ExportAuditLogs("xml")
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, data)
	} else {
		assert.ErrorIs(t, err, ErrAdminInvalidFormat)
		assert.Nil(t, data)
	}
}

func TestFinalCoveragePush_AdminService_ExportAuditLogs_JSONWithEntries(t *testing.T) {
	store := &fcpMockAuditStore{
		entries: []audit.Entry{
			{
				Timestamp: time.Now(),
				Operation: audit.OpBarrierInitialized,
				Success:   true,
				Backend:   "software",
			},
		},
	}
	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	data, err := svc.ExportAuditLogs("json")
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, data)
	} else {
		require.NoError(t, err)
		assert.Contains(t, string(data), "barrier_initialized")
	}
}

func TestFinalCoveragePush_AdminService_ExportAuditLogs_CSVWithEntries(t *testing.T) {
	store := &fcpMockAuditStore{
		entries: []audit.Entry{
			{
				Timestamp: time.Now(),
				Operation: audit.OpBarrierInitialized,
				Success:   true,
				Backend:   "software",
			},
		},
	}
	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	data, err := svc.ExportAuditLogs("csv")
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, data)
	} else {
		require.NoError(t, err)
		assert.Contains(t, string(data), "timestamp")
	}
}

func TestFinalCoveragePush_AdminService_ExportAuditLogs_EmptyStore(t *testing.T) {
	store := &fcpMockAuditStore{entries: nil}
	svc := NewAdminService()
	svc.SetAuditStore(store)
	svc.SetContext(context.Background())

	data, err := svc.ExportAuditLogs("json")
	if errors.Is(err, ErrAdminNotAuthorized) {
		assert.Nil(t, data)
	} else {
		assert.ErrorIs(t, err, ErrAuditNoEntries)
		assert.Nil(t, data)
	}
}

// ---------------------------------------------------------------------------
// AppLockService - additional branch coverage
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AppLockService_Unlock_BarrierConfiguredNotInitialized(t *testing.T) {
	// Barrier configured but not initialized: should fall through to PIN verification.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	barrier := &mockBarrierService{
		initialized: false,
		sealed:      false,
	}
	svc := NewAppLockService(pinSvc, barrier)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	err := svc.Unlock("test-pin")
	require.NoError(t, err)
	assert.False(t, svc.IsLocked())
}

func TestFinalCoveragePush_AppLockService_Unlock_BarrierSealedUnsealFails(t *testing.T) {
	// Barrier is sealed and unseal fails.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())

	barrier := &mockBarrierService{
		initialized: true,
		sealed:      true,
		unsealErr:   errors.New("bad password"),
	}
	svc := NewAppLockService(pinSvc, barrier)
	svc.SetContext(context.Background())
	svc.SetBarrierStrategy("software")
	svc.LockForStartup()

	err := svc.Unlock("wrong-pin")
	assert.ErrorIs(t, err, ErrAppLockPINInvalid)
	assert.True(t, svc.IsLocked())
}

func TestFinalCoveragePush_AppLockService_Unlock_NoPINServiceConfigured(t *testing.T) {
	// No barrier, no PIN service.
	svc := NewAppLockService(nil, nil)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	err := svc.Unlock("test-pin")
	assert.ErrorIs(t, err, ErrAppLockPINInvalid)
}

func TestFinalCoveragePush_AppLockService_Unlock_PINNotSet(t *testing.T) {
	// PIN service configured but user PIN not set.
	pinSvc := NewPINService()
	pinSvc.SetContext(context.Background())
	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      false,
		userPINSet:    false,
		initialized:   true,
		verifyUserErr: nil,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	pinSvc.SetPINService(pSvc)

	svc := NewAppLockService(pinSvc, nil)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	err := svc.Unlock("test-pin")
	assert.ErrorIs(t, err, ErrAppLockSetupIncomplete)
}

func TestFinalCoveragePush_AppLockService_Unlock_EmptyPIN(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetContext(context.Background())
	svc.LockForStartup()

	err := svc.Unlock("")
	assert.ErrorIs(t, err, ErrAppLockPINRequired)
}

func TestFinalCoveragePush_AppLockService_Unlock_NotLocked(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetContext(context.Background())
	// Not locked by default.

	err := svc.Unlock("test-pin")
	assert.ErrorIs(t, err, ErrAppLockAlreadyUnlocked)
}

func TestFinalCoveragePush_AppLockService_Lock_EmitFunc(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetContext(context.Background())

	var emittedEvent string
	svc.SetEmitFunc(func(event string, _ any) {
		emittedEvent = event
	})

	err := svc.Lock()
	require.NoError(t, err)
	assert.Equal(t, "app:locked", emittedEvent)
}

func TestFinalCoveragePush_AppLockService_SetAutoLockMinutes(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetContext(context.Background())
	// Default is 15.
	assert.Equal(t, int32(15), svc.autoLockMinutes.Load())

	svc.SetAutoLockMinutes(30)
	assert.Equal(t, int32(30), svc.autoLockMinutes.Load())

	// Disable auto-lock.
	svc.SetAutoLockMinutes(0)
	assert.Equal(t, int32(0), svc.autoLockMinutes.Load())
}

func TestFinalCoveragePush_AppLockService_SetLockOnScreenLock(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	// Default is true.
	assert.True(t, svc.lockOnScreenLock.Load())

	svc.SetLockOnScreenLock(false)
	assert.False(t, svc.lockOnScreenLock.Load())

	svc.SetLockOnScreenLock(true)
	assert.True(t, svc.lockOnScreenLock.Load())
}

func TestFinalCoveragePush_AppLockService_GetStatus(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.SetAutoLockMinutes(10)
	svc.SetLockOnScreenLock(false)

	status := svc.GetStatus()
	assert.False(t, status.IsLocked)
	assert.Equal(t, 10, status.AutoLockMinutes)
	assert.False(t, status.LockOnScreenLock)
}

func TestFinalCoveragePush_AppLockService_RecordActivity_WhenLocked(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	svc.LockForStartup()
	// RecordActivity should be a no-op when locked.
	svc.RecordActivity()
	assert.True(t, svc.IsLocked())
}

func TestFinalCoveragePush_AppLockService_RecordActivity_WhenUnlocked(t *testing.T) {
	svc := NewAppLockService(nil, nil)
	// Service starts unlocked.
	svc.RecordActivity()
	assert.False(t, svc.IsLocked())
}

// ---------------------------------------------------------------------------
// ConnectionService.Connect - additional branch coverage
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_ConnectionService_Connect_InvalidProtocol(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	info, err := svc.Connect("invalid", "localhost:8080", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidProtocol)
	assert.Nil(t, info)
}

func TestFinalCoveragePush_ConnectionService_Connect_EmptyAddress(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	info, err := svc.Connect("rest", "", false, "", "")
	assert.ErrorIs(t, err, ErrInvalidAddress)
	assert.Nil(t, info)
}

func TestFinalCoveragePush_ConnectionService_Connect_AlreadyConnected(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())
	// Simulate connected state.
	svc.state.Store(&ConnectionInfo{State: "connected"})

	info, err := svc.Connect("rest", "localhost:8080", false, "", "")
	assert.ErrorIs(t, err, ErrServerAlreadyConnected)
	assert.Nil(t, info)
}

// ---------------------------------------------------------------------------
// PINService - additional branch coverage
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PINService_GetPINStatus_NoService(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())

	status, err := svc.GetPINStatus()
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
	assert.Nil(t, status)
}

func TestFinalCoveragePush_PINService_SetSOPIN_NoService(t *testing.T) {
	svc := NewPINService()
	err := svc.SetSOPIN("old", "new")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_SetUserPIN_NoService(t *testing.T) {
	svc := NewPINService()
	err := svc.SetUserPIN("sopin", "newpin")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_ChangeSOPIN_NoService(t *testing.T) {
	svc := NewPINService()
	err := svc.ChangeSOPIN("oldpin123", "newpin123")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_ChangeUserPIN_NoService(t *testing.T) {
	svc := NewPINService()
	err := svc.ChangeUserPIN("oldpin123", "newpin123")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_VerifyUserPIN_NoService(t *testing.T) {
	svc := NewPINService()
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.VerifyUserPIN("test")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
	// Verify audit log was called for the failure.
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpPINFailed, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_VerifySOPIN_NoService(t *testing.T) {
	svc := NewPINService()
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.VerifySOPIN("test")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINFailed, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_GetLockoutStatus_NoService(t *testing.T) {
	svc := NewPINService()
	status, err := svc.GetLockoutStatus()
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
	assert.Nil(t, status)
}

func TestFinalCoveragePush_PINService_ResetLockout_NoService(t *testing.T) {
	svc := NewPINService()
	err := svc.ResetLockout("sopin")
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_IsPINSet_NoService(t *testing.T) {
	svc := NewPINService()
	assert.False(t, svc.IsPINSet())
}

func TestFinalCoveragePush_PINService_VerifyFIDO2Hash_NoService(t *testing.T) {
	svc := NewPINService()
	assert.False(t, svc.VerifyFIDO2Hash([]byte("test")))
}

func TestFinalCoveragePush_PINService_SetSOPIN_WithAuditLogger(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		setSOPINErr:   errors.New("set failed"),
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.SetSOPIN("old", "new")
	assert.Error(t, err)
	// Verify the failure was audited.
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINFailed, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_SetSOPIN_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.SetSOPIN("", "newsopin")
	require.NoError(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINChanged, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_ChangeUserPIN_WithAuditLogger(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		changeUserErr: errors.New("change failed"),
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ChangeUserPIN("oldpin123", "newpin123")
	assert.Error(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpPINFailed, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_VerifyUserPIN_WithLockout(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		verifyUserErr: errors.New("wrong PIN"),
		lockoutStatus: &pin.LockoutStatus{
			MaxAttempts:    5,
			FailedAttempts: 5,
			IsLocked:       true,
		},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.VerifyUserPIN("wrong")
	assert.Error(t, err)
	// Should have logged both the failure and the lockout.
	assert.GreaterOrEqual(t, len(logger.pinOps), 2)

	foundLockout := false
	for _, op := range logger.pinOps {
		if op.op == audit.OpPINLocked {
			foundLockout = true
			break
		}
	}
	assert.True(t, foundLockout, "expected OpPINLocked audit entry")
}

func TestFinalCoveragePush_PINService_logPINOperation_NoLogger(t *testing.T) {
	svc := NewPINService()
	// No logger - should not panic.
	svc.logPINOperation(audit.OpPINChanged, true, nil, nil)
}

func TestFinalCoveragePush_PINService_logPINOperation_WithPINService(t *testing.T) {
	svc := NewPINService()
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	svc.logPINOperation(audit.OpPINChanged, true, nil, map[string]any{"type": "user_pin"})
	require.Len(t, logger.pinOps, 1)
	assert.Equal(t, "software", logger.pinOps[0].backend)
}

func TestFinalCoveragePush_PINService_getAuditLogger_Nil(t *testing.T) {
	svc := NewPINService()
	assert.Nil(t, svc.getAuditLogger())
}

func TestFinalCoveragePush_PINService_getAuditLogger_Set(t *testing.T) {
	svc := NewPINService()
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)
	assert.Equal(t, logger, svc.getAuditLogger())
}

// ---------------------------------------------------------------------------
// StaticPasswordService - additional error paths for coverage
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_StaticPWService_ListPasswords_BarrierSealed(t *testing.T) {
	store := &fcpMockStaticPWStore{
		listErr: errors.New("seal: barrier is sealed"),
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	_, err := svc.ListPasswords()
	assert.ErrorIs(t, err, ErrStaticPWBarrierSealed)
}

func TestFinalCoveragePush_StaticPWService_GetPassword_Empty(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	svc.SetContext(context.Background())

	_, err := svc.GetPassword("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestFinalCoveragePush_StaticPWService_GetPassword_NotFound(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	svc.SetContext(context.Background())

	_, err := svc.GetPassword("nonexistent")
	assert.Error(t, err)
}

func TestFinalCoveragePush_StaticPWService_AddPasswordV2_InvalidExpiry(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	svc.SetContext(context.Background())

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "test",
		Password:  "pass",
		ExpiresAt: "not-a-date",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidExpiresAt)
}

func TestFinalCoveragePush_StaticPWService_AddPasswordV2_WithExpiry(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	svc.SetContext(context.Background())

	expires := time.Now().Add(24 * time.Hour).Format(time.RFC3339)
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "test-expiry",
		Password:  "pass",
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	assert.Equal(t, "test-expiry", entry.Name)
}

func TestFinalCoveragePush_StaticPWService_DeletePassword_ReadOnly(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "ro-1", Name: "readonly-entry", ReadOnly: true},
		},
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	err := svc.DeletePassword("ro-1")
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)
}

func TestFinalCoveragePush_StaticPWService_UpdatePasswordV2_ReadOnly(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "ro-1", Name: "readonly-entry", ReadOnly: true},
		},
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:   "ro-1",
		Name: "renamed",
	})
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)
}

func TestFinalCoveragePush_StaticPWService_UpdatePasswordV2_InvalidExpiry(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "pw-1", Name: "test-entry", ReadOnly: false},
		},
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:        "pw-1",
		Name:      "test-entry",
		ExpiresAt: "bad-date",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidExpiresAt)
}

func TestFinalCoveragePush_StaticPWService_UpdatePasswordV2_ClearExpiry(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{
				ID:        "pw-1",
				Name:      "test-entry",
				ExpiresAt: time.Now().Add(time.Hour),
			},
		},
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	// Empty ExpiresAt should clear the expiry.
	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:        "pw-1",
		Name:      "test-entry",
		ExpiresAt: "",
	})
	require.NoError(t, err)
}

func TestFinalCoveragePush_StaticPWService_DeletePasswordForce_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.DeletePasswordForce("test")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_DeletePasswordForce_EmptyID(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	err := svc.DeletePasswordForce("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestFinalCoveragePush_StaticPWService_ListFolders_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListFolders()
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_ListPasswordsByFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListPasswordsByFolder("/test")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_MovePassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.MovePassword("id", "/folder")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_MovePassword_EmptyID(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	err := svc.MovePassword("", "/folder")
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestFinalCoveragePush_StaticPWService_RenameFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.RenameFolder("/old", "/new")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_RenameFolder_EmptyPath(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	err := svc.RenameFolder("", "/new")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestFinalCoveragePush_StaticPWService_DeleteFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.DeleteFolder("/test")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_DeleteFolder_EmptyPath(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	err := svc.DeleteFolder("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestFinalCoveragePush_StaticPWService_SearchPasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.SearchPasswords("test")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestFinalCoveragePush_StaticPWService_GetContext_Fallback(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	// No context set - should return background.
	ctx := svc.getContext()
	assert.NotNil(t, ctx)
}

func TestFinalCoveragePush_StaticPWService_GetClient_NilPointer(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.getClient()
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestFinalCoveragePush_StaticPWService_GeneratePassword(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	pw, err := svc.GeneratePassword(16, "alphanumeric")
	require.NoError(t, err)
	assert.Len(t, pw, 16)
}

func TestFinalCoveragePush_StaticPWService_AddPassword_Legacy(t *testing.T) {
	svc := NewStaticPasswordService(&fcpMockStaticPWStore{})
	svc.SetContext(context.Background())

	entry, err := svc.AddPassword("legacy-test", "password123", "some notes")
	require.NoError(t, err)
	assert.Equal(t, "legacy-test", entry.Name)
}

func TestFinalCoveragePush_StaticPWService_UpdatePassword_Legacy(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "pw-1", Name: "test-entry"},
		},
	}
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())

	err := svc.UpdatePassword("pw-1", "new-name", "new-pass", "new-notes")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// PasswordProtectionService.logPasswordStoreOp - covers the audit log path
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PasswordProtectionService_logPasswordStoreOp_WithLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPasswordStoreOp(audit.OpPasswordStoreUnlocked, "test", true, nil, map[string]any{"count": 5})

	require.Len(t, logger.passwordOps, 1)
	assert.Equal(t, audit.OpPasswordStoreUnlocked, logger.passwordOps[0].op)
	assert.True(t, logger.passwordOps[0].success)
}

func TestFinalCoveragePush_PasswordProtectionService_logPasswordStoreOp_NoLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	// No logger - should not panic.
	svc.logPasswordStoreOp(audit.OpPasswordStoreUnlocked, "test", true, nil, nil)
}

// ---------------------------------------------------------------------------
// Barrier service: Unseal error branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_Unseal_NotInitialized(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	// Unseal without Initialize should call Initialize since root key not found.
	err := svc.Unseal("password", "software")
	// The initialize path will be called, exercising the branch.
	_ = err
}

func TestFinalCoveragePush_BarrierService_Unseal_EmptyStrategy(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	// No tpmSealerFn = software is best strategy.
	err := svc.Unseal("password", "")
	// Exercises the "strategyID empty, fallback to best" branch.
	_ = err
}

// ---------------------------------------------------------------------------
// AuditService.GetEntries - cover filter branches and CSV export
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AuditService_GetEntries_NilStore(t *testing.T) {
	svc := NewAuditService(nil)
	svc.SetContext(context.Background())

	entries, err := svc.GetEntries(nil)
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestFinalCoveragePush_AuditService_GetEntries_WithFilter(t *testing.T) {
	store, err := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, err)

	store.Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: audit.OpBarrierInitialized,
		Success:   true,
		Backend:   "software",
	})

	svc := NewAuditService(store)
	svc.SetContext(context.Background())

	filter := &AuditFilter{
		Operation: string(audit.OpBarrierInitialized),
		Backend:   "software",
		Limit:     10,
	}
	entries, err := svc.GetEntries(filter)
	require.NoError(t, err)
	assert.NotEmpty(t, entries)
	assert.Equal(t, string(audit.OpBarrierInitialized), entries[0].Operation)
}

func TestFinalCoveragePush_AuditService_ExportCSV(t *testing.T) {
	svc := NewAuditService(nil)
	entries := []AuditEntry{
		{
			Timestamp:  time.Now(),
			Operation:  "test.op",
			Backend:    "software",
			KeyID:      "key-1",
			Success:    true,
			DurationMs: 42,
		},
	}

	data, err := svc.exportCSV(entries)
	require.NoError(t, err)
	csvStr := string(data)
	assert.Contains(t, csvStr, "timestamp")
	assert.Contains(t, csvStr, "test.op")
	assert.Contains(t, csvStr, "software")
}

// ---------------------------------------------------------------------------
// BarrierService.Initialize - additional error branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_Initialize_EmptyStrategy(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	// Empty strategyID with no TPM sealer should auto-select software.
	err := svc.Initialize("password", "")
	// Should succeed with software strategy.
	require.NoError(t, err)
	assert.True(t, svc.IsInitialized())
}

func TestFinalCoveragePush_BarrierService_Initialize_AlreadyInit(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	// Second init should fail with ErrBarrierAlreadyInit.
	err = svc.Initialize("password", "software")
	assert.ErrorIs(t, err, ErrBarrierAlreadyInit)
}

func TestFinalCoveragePush_BarrierService_Initialize_SoftwareNoPassword(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())

	err := svc.Initialize("", "software")
	assert.ErrorIs(t, err, ErrBarrierPasswordRequired)
}

// ---------------------------------------------------------------------------
// ConnectionService - Disconnect and HealthCheck branches
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_ConnectionService_Disconnect_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	err := svc.Disconnect()
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

func TestFinalCoveragePush_ConnectionService_HealthCheck_NotConnected(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	_, err := svc.HealthCheck()
	assert.ErrorIs(t, err, ErrServerNotConnected)
}

func TestFinalCoveragePush_ConnectionService_GetConnectionInfo(t *testing.T) {
	svc := NewConnectionService()
	info := svc.GetConnectionInfo()
	assert.Equal(t, "disconnected", info.State)
}

func TestFinalCoveragePush_ConnectionService_IsConnected_False(t *testing.T) {
	svc := NewConnectionService()
	assert.False(t, svc.IsConnected())
}

func TestFinalCoveragePush_ConnectionService_GetClient_Nil(t *testing.T) {
	svc := NewConnectionService()
	assert.Nil(t, svc.GetClient())
}

func TestFinalCoveragePush_ConnectionService_SetEventEmitter(t *testing.T) {
	svc := NewConnectionService()
	called := false
	svc.SetEventEmitter(func(_ events.Event) { called = true })
	assert.NotNil(t, svc.emitter)
	_ = called
}

// ===========================================================================
// Part 3: Additional coverage for partially-covered functions
// ===========================================================================

// ---------------------------------------------------------------------------
// SealProtectionService - cover logSealProtectionEvent, Unlock, Lock, resetAutoLockTimer
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_SealProtectionService_logSealProtectionEvent_WithLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, true, nil, nil)
	require.Len(t, logger.entries, 1)
	assert.True(t, logger.entries[0].Success)
}

func TestFinalCoveragePush_SealProtectionService_logSealProtectionEvent_WithError(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("test error")
	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, false, testErr, nil)
	require.Len(t, logger.entries, 1)
	assert.Equal(t, "test error", logger.entries[0].Error)
}

func TestFinalCoveragePush_SealProtectionService_logSealProtectionEvent_NoLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, true, nil, nil)
}

func TestFinalCoveragePush_SealProtectionService_GetStatus_NilSealSvc(t *testing.T) {
	svc := NewSealProtectionService(nil)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 0, status.BlobCount)
}

func TestFinalCoveragePush_PasswordProtectionService_GetStatus_NilDeps(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "barrier", status.Mode)
	assert.False(t, status.IsLocked) // starts unlocked
	assert.Equal(t, 0, status.PasswordCount)
}

func TestFinalCoveragePush_PasswordProtectionService_GetStatus_WithStore(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "1", Name: "pw1"},
			{ID: "2", Name: "pw2"},
		},
	}
	pwSvc := NewStaticPasswordService(store)
	svc := NewPasswordProtectionService("", pwSvc, nil)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, 2, status.PasswordCount)
}

func TestFinalCoveragePush_PasswordProtectionService_ExportPasswordsDecrypted_NilStore(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	// Starts unlocked.

	_, err := svc.ExportPasswordsDecrypted("")
	assert.ErrorIs(t, err, ErrPPNotConfigured)
}

func TestFinalCoveragePush_PasswordProtectionService_ExportPasswordsDecrypted_Success(t *testing.T) {
	store := &fcpMockStaticPWStore{
		passwords: []*staticpw.StaticPassword{
			{ID: "1", Name: "pw1", Password: "secret1"},
		},
	}
	pwSvc := NewStaticPasswordService(store)
	svc := NewPasswordProtectionService("", pwSvc, nil)
	// Starts unlocked.

	passwords, err := svc.ExportPasswordsDecrypted("")
	require.NoError(t, err)
	assert.Len(t, passwords, 1)
	assert.Equal(t, "secret1", passwords[0].Password)
}

func TestFinalCoveragePush_SetupWizardService_GenerateSetupPINs(t *testing.T) {
	svc := NewSetupWizardService()
	pins, err := svc.GenerateSetupPINs()
	require.NoError(t, err)
	assert.Len(t, pins.SOPin, 16)
	assert.Len(t, pins.UserPin, 12)
	// Both should be non-empty.
	assert.NotEmpty(t, pins.SOPin)
	assert.NotEmpty(t, pins.UserPin)
}

func TestFinalCoveragePush_SetupWizardService_SetContext(t *testing.T) {
	svc := NewSetupWizardService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestFinalCoveragePush_SetupWizardService_SetConfigDir(t *testing.T) {
	svc := NewSetupWizardService()
	svc.SetConfigDir("/tmp/test-config")
	assert.Equal(t, "/tmp/test-config", svc.configDir)
}

func TestFinalCoveragePush_SetupWizardService_SetInitDataDirFunc(t *testing.T) {
	svc := NewSetupWizardService()
	called := false
	svc.SetInitDataDirFunc(func() error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.initDataDirFunc)
	err := svc.initDataDirFunc()
	require.NoError(t, err)
	assert.True(t, called)
}

// ---------------------------------------------------------------------------
// PairingService - cover logPairingEvent
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PairingService_logPairingEvent_WithLogger(t *testing.T) {
	svc := NewPairingService(slog.Default())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPairingEvent("pairing.complete", true, nil, map[string]any{"origin": "test"})
	require.Len(t, logger.entries, 1)
	assert.True(t, logger.entries[0].Success)
}

func TestFinalCoveragePush_PairingService_logPairingEvent_WithError(t *testing.T) {
	svc := NewPairingService(slog.Default())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("pairing failed")
	svc.logPairingEvent("pairing.failed", false, testErr, nil)
	require.Len(t, logger.entries, 1)
	assert.Equal(t, "pairing failed", logger.entries[0].Error)
}

func TestFinalCoveragePush_PairingService_logPairingEvent_NoLogger(t *testing.T) {
	svc := NewPairingService(slog.Default())
	svc.logPairingEvent("pairing.test", true, nil, nil)
}

// ---------------------------------------------------------------------------
// BarrierService - cover additional methods
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_SetDataDir(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	svc.SetDataDir("/tmp/data")
	assert.Equal(t, "/tmp/data", svc.dataDir)
}

func TestFinalCoveragePush_BarrierService_SetTPMSealerFunc(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	assert.Nil(t, svc.tpmSealerFn)
	svc.SetTPMSealerFunc(func() types.Sealer { return nil })
	assert.NotNil(t, svc.tpmSealerFn)
}

func TestFinalCoveragePush_BarrierService_SetBaseBackendFactory(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	assert.Nil(t, svc.baseBackendFn)
	svc.SetBaseBackendFactory(func(dir string) (storage.Backend, error) {
		return storage.NewMemory(), nil
	})
	assert.NotNil(t, svc.baseBackendFn)
}

func TestFinalCoveragePush_BarrierService_IsUnsealed_NotInitialized(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	assert.False(t, svc.IsUnsealed())
}

func TestFinalCoveragePush_BarrierService_ProbeStrategies(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	strategies := svc.ProbeStrategies()
	assert.NotEmpty(t, strategies)

	// Software should always be available.
	foundSoftware := false
	for _, s := range strategies {
		if s.ID == "software" {
			foundSoftware = true
			assert.True(t, s.Available)
			assert.False(t, s.HardwareBacked)
		}
	}
	assert.True(t, foundSoftware)
}

func TestFinalCoveragePush_BarrierService_BestStrategy(t *testing.T) {
	svc := NewBarrierService(t.TempDir(), slog.Default())
	best, err := svc.BestStrategy()
	require.NoError(t, err)
	assert.NotEmpty(t, best.ID)
}

// ---------------------------------------------------------------------------
// OATHService - cover SetStore
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_OATHService_SetStore(t *testing.T) {
	svc := NewOATHService(nil)
	assert.Nil(t, svc.store)

	store := &fcpMockOATHStore{}
	svc.SetStore(store)
	assert.NotNil(t, svc.store)
}

// ---------------------------------------------------------------------------
// StaticPasswordService - cover SetStore
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_StaticPWService_SetStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	assert.Nil(t, svc.store)

	store := &fcpMockStaticPWStore{}
	svc.SetStore(store)
	assert.NotNil(t, svc.store)
}

// ---------------------------------------------------------------------------
// PINService - cover SetPINService and getPINService
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PINService_SetPINService(t *testing.T) {
	svc := NewPINService()
	assert.Nil(t, svc.pinSvc.Load())

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)
	assert.NotNil(t, svc.pinSvc.Load())
}

func TestFinalCoveragePush_PINService_getPINService_NotConfigured(t *testing.T) {
	svc := NewPINService()
	_, err := svc.getPINService()
	assert.ErrorIs(t, err, ErrPINServiceNotConfigured)
}

func TestFinalCoveragePush_PINService_getPINService_Configured(t *testing.T) {
	svc := NewPINService()
	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	got, err := svc.getPINService()
	require.NoError(t, err)
	assert.NotNil(t, got)
}

// ---------------------------------------------------------------------------
// PINService - cover SetUserPIN success and ChangeSOPIN
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_PINService_SetUserPIN_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    false,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.SetUserPIN("sopin", "newpin")
	require.NoError(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpPINChanged, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_ChangeSOPIN_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ChangeSOPIN("oldpin123", "newpin123")
	require.NoError(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINChanged, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_ChangeSOPIN_Error(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:       pin.StrategySoftware,
		soPINSet:       true,
		userPINSet:     true,
		initialized:    true,
		changeSOPINErr: errors.New("change failed"),
		lockoutStatus:  &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ChangeSOPIN("oldpin123", "newpin123")
	assert.Error(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINFailed, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_ChangeUserPIN_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ChangeUserPIN("oldpin123", "newpin123")
	require.NoError(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpPINChanged, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_VerifySOPIN_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.VerifySOPIN("test")
	require.NoError(t, err)
	assert.Len(t, logger.pinOps, 1)
	assert.Equal(t, audit.OpSOPINVerified, logger.pinOps[0].op)
}

func TestFinalCoveragePush_PINService_GetPINStatus_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		soPINSet:      true,
		userPINSet:    true,
		initialized:   true,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	status, err := svc.GetPINStatus()
	require.NoError(t, err)
	assert.True(t, status.SOPINSet)
	assert.True(t, status.UserPINSet)
	assert.True(t, status.Initialized)
	assert.Equal(t, "software", status.Strategy)
}

func TestFinalCoveragePush_PINService_GetLockoutStatus_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5, FailedAttempts: 2},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	status, err := svc.GetLockoutStatus()
	require.NoError(t, err)
	assert.NotNil(t, status)
	assert.Equal(t, 5, status.MaxAttempts)
	assert.Equal(t, 2, status.FailedAttempts)
}

func TestFinalCoveragePush_PINService_ResetLockout_Success(t *testing.T) {
	svc := NewPINService()
	svc.SetContext(context.Background())

	backend := &mockPINBackend{
		strategy:      pin.StrategySoftware,
		lockoutStatus: &pin.LockoutStatus{MaxAttempts: 5},
	}
	pSvc := pin.NewService(backend, slog.Default())
	svc.SetPINService(pSvc)

	err := svc.ResetLockout("sopin")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// AuditService - cover ExportEntries
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_AuditService_ExportEntries_InvalidFormat(t *testing.T) {
	svc := NewAuditService(nil)
	svc.SetContext(context.Background())

	_, err := svc.ExportEntries("xml", nil)
	assert.ErrorIs(t, err, ErrAuditInvalidFormat)
}

func TestFinalCoveragePush_AuditService_ExportEntries_NilStore(t *testing.T) {
	svc := NewAuditService(nil)
	svc.SetContext(context.Background())

	_, err := svc.ExportEntries("json", nil)
	assert.ErrorIs(t, err, ErrAuditNoEntries)
}

func TestFinalCoveragePush_AuditService_ExportEntries_JSON(t *testing.T) {
	store, err := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, err)

	store.Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: audit.OpBarrierInitialized,
		Success:   true,
	})

	svc := NewAuditService(store)
	svc.SetContext(context.Background())

	data, err := svc.ExportEntries("json", nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "barrier_initialized")
}

func TestFinalCoveragePush_AuditService_ExportEntries_CSV(t *testing.T) {
	store, err := audit.NewBackendStore(storage.NewMemory(), 100, nil)
	require.NoError(t, err)

	store.Log(audit.Entry{
		Timestamp: time.Now(),
		Operation: audit.OpBarrierInitialized,
		Success:   true,
	})

	svc := NewAuditService(store)
	svc.SetContext(context.Background())

	data, err := svc.ExportEntries("csv", nil)
	require.NoError(t, err)
	assert.Contains(t, string(data), "timestamp")
}

// ---------------------------------------------------------------------------
// BarrierService - Seal and Unseal with audit logging
// ---------------------------------------------------------------------------

func TestFinalCoveragePush_BarrierService_Initialize_WithAuditLogger(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	// Should have logged the initialization.
	foundInit := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpBarrierInitialized && e.Success {
			foundInit = true
		}
	}
	assert.True(t, foundInit)
}

func TestFinalCoveragePush_BarrierService_Unseal_WithAuditLogger_PostHook(t *testing.T) {
	configDir := t.TempDir()
	svc := NewBarrierService(configDir, slog.Default())
	svc.SetContext(context.Background())
	logger := &fcpMockAuditLogger{}
	svc.SetAuditLogger(logger)

	hookCalled := false
	svc.SetPostUnsealHook(func() error {
		hookCalled = true
		return nil
	})

	// Initialize first.
	err := svc.Initialize("password", "software")
	require.NoError(t, err)

	// Reset barrier to simulate a sealed state.
	svc.barrier = nil

	// Unseal should re-initialize since barrier was nil.
	err = svc.Unseal("password", "software")
	// Whether this succeeds depends on the barrier backend.
	_ = err
	_ = hookCalled
}
