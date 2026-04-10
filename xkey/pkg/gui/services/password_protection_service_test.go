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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestPasswordProtectionService creates a PasswordProtectionService with
// in-memory store for testing.
func newTestPasswordProtectionService(t *testing.T) (
	*PasswordProtectionService, *StaticPasswordService,
) {
	t.Helper()

	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	staticPWSvc := NewStaticPasswordService(store)
	staticPWSvc.SetContext(context.Background())

	ppSvc := NewPasswordProtectionService("", staticPWSvc, nil)
	ppSvc.SetContext(context.Background())

	return ppSvc, staticPWSvc
}

// --- NewPasswordProtectionService ---

func TestNewPasswordProtectionService(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestPasswordProtectionService_SetContext(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	svc.SetContext(context.Background())
	assert.NotNil(t, svc.ctx)
}

// --- GetStatus ---

func TestPasswordProtectionService_GetStatus(t *testing.T) {
	ppSvc, _ := newTestPasswordProtectionService(t)

	status, err := ppSvc.GetStatus()
	require.NoError(t, err)
	assert.Equal(t, "barrier", status.Mode)
	assert.False(t, status.TPMAvailable)
	assert.Equal(t, "barrier", status.KeySource)
	assert.False(t, status.IsLocked, "IsLocked must always be false")
	assert.Equal(t, 0, status.PasswordCount)
}

func TestPasswordProtectionService_GetStatus_WithPasswords(t *testing.T) {
	ppSvc, _ := newTestPasswordProtectionService(t)

	err := ppSvc.staticPWSvc.store.Add(&staticpw.StaticPassword{
		Name:     "test-entry",
		Username: "user@example.com",
		Password: "s3cret",
	})
	require.NoError(t, err)

	status, err := ppSvc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 1, status.PasswordCount)
}

// --- ExportPasswordsDecrypted ---

func TestPasswordProtectionService_ExportPasswordsDecrypted_NilStaticPWSvc(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)

	passwords, err := svc.ExportPasswordsDecrypted("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPPNotConfigured))
	assert.Nil(t, passwords)
}

func TestPasswordProtectionService_ExportPasswordsDecrypted_NilStore(t *testing.T) {
	staticPWSvc := NewStaticPasswordService(nil)
	svc := NewPasswordProtectionService("", staticPWSvc, nil)

	passwords, err := svc.ExportPasswordsDecrypted("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrPPNotConfigured))
	assert.Nil(t, passwords)
}

func TestPasswordProtectionService_ExportPasswordsDecrypted_Success(t *testing.T) {
	ppSvc, _ := newTestPasswordProtectionService(t)

	err := ppSvc.staticPWSvc.store.Add(&staticpw.StaticPassword{
		Name:     "test-entry",
		Username: "user@example.com",
		Password: "s3cret",
	})
	require.NoError(t, err)

	passwords, err := ppSvc.ExportPasswordsDecrypted("")
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "test-entry", passwords[0].Name)
	assert.Equal(t, "user@example.com", passwords[0].Username)
	assert.Equal(t, "s3cret", passwords[0].Password)
}

// --- Audit logging ---

func TestPasswordProtectionService_SetAuditLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	logger := &ppTestAuditLogger{}
	svc.SetAuditLogger(logger)

	loaded := svc.auditLog.Load()
	require.NotNil(t, loaded)
}

func TestPasswordProtectionService_LogPasswordStoreOp_NoLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	// Should not panic when no logger is set.
	svc.logPasswordStoreOp(audit.OpPasswordStoreLocked, "test", true, nil, nil)
}

func TestPasswordProtectionService_LogPasswordStoreOp_WithLogger(t *testing.T) {
	svc := NewPasswordProtectionService("", nil, nil)
	logger := &ppTestAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logPasswordStoreOp(audit.OpPasswordStoreLocked, "test", true, nil, map[string]any{"key": "val"})
	assert.True(t, logger.called)
}

// ppTestAuditLogger is a minimal audit logger for testing.
type ppTestAuditLogger struct {
	called bool
}

func (l *ppTestAuditLogger) Log(audit.Entry) {}
func (l *ppTestAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) {
}
func (l *ppTestAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *ppTestAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {}
func (l *ppTestAuditLogger) LogServiceEvent(audit.OperationType, map[string]any)                    {}
func (l *ppTestAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *ppTestAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {}
func (l *ppTestAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) {
	l.called = true
}
func (l *ppTestAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {}
