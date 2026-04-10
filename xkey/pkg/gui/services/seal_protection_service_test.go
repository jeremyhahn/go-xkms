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
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- NewSealProtectionService ---

func TestNewSealProtectionService(t *testing.T) {
	svc := NewSealProtectionService(nil)
	assert.NotNil(t, svc)
	assert.NotNil(t, svc.log)
}

func TestSealProtectionService_SetContext(t *testing.T) {
	svc := NewSealProtectionService(nil)
	svc.SetContext(context.Background())
	assert.NotNil(t, svc.ctx)
}

// --- GetStatus ---

func TestSealProtectionService_GetStatus_NilSealService(t *testing.T) {
	svc := NewSealProtectionService(nil)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.IsLocked, "IsLocked must always be false")
	assert.Equal(t, 0, status.BlobCount)
}

func TestSealProtectionService_GetStatus_WithSealService(t *testing.T) {
	dir := t.TempDir()
	sealSvc := NewSealService(dir)
	svc := NewSealProtectionService(sealSvc)

	status, err := svc.GetStatus()
	require.NoError(t, err)
	assert.False(t, status.IsLocked)
	assert.Equal(t, 0, status.BlobCount)
}

// --- Audit logging ---

func TestSealProtectionService_SetAuditLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &sealTestAuditLogger{}
	svc.SetAuditLogger(logger)

	loaded := svc.auditLog.Load()
	require.NotNil(t, loaded)
}

func TestSealProtectionService_LogSealProtectionEvent_NoLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	// Should not panic when no logger is set.
	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, true, nil, nil)
}

func TestSealProtectionService_LogSealProtectionEvent_WithLogger(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &sealTestAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, true, nil, map[string]any{"key": "val"})
	require.Len(t, logger.entries, 1)
	assert.Equal(t, audit.OpPasswordStoreLocked, logger.entries[0].Operation)
	assert.True(t, logger.entries[0].Success)
}

func TestSealProtectionService_LogSealProtectionEvent_WithError(t *testing.T) {
	svc := NewSealProtectionService(nil)
	logger := &sealTestAuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := assert.AnError
	svc.logSealProtectionEvent(audit.OpPasswordStoreLocked, false, testErr, nil)
	require.Len(t, logger.entries, 1)
	assert.Equal(t, testErr.Error(), logger.entries[0].Error)
	assert.False(t, logger.entries[0].Success)
}

// sealTestAuditLogger is a minimal audit logger for testing.
type sealTestAuditLogger struct {
	entries []audit.Entry
}

func (l *sealTestAuditLogger) Log(e audit.Entry) {
	e.Timestamp = time.Now()
	l.entries = append(l.entries, e)
}
func (l *sealTestAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) {
}
func (l *sealTestAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *sealTestAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *sealTestAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) {}
func (l *sealTestAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *sealTestAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {}
func (l *sealTestAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *sealTestAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}
