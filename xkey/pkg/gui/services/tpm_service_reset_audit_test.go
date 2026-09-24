// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// tpmResetRecordingAuditLogger records TPM operation entries for assertions.
type tpmResetRecordingAuditLogger struct {
	entries []audit.Entry
	logErr  error
}

func (l *tpmResetRecordingAuditLogger) Log(audit.Entry) error { return nil }
func (l *tpmResetRecordingAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	if l.logErr != nil {
		return l.logErr
	}
	l.entries = append(l.entries, audit.Entry{Operation: op, Success: success, Details: details})
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (l *tpmResetRecordingAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return nil
}

var _ audit.Logger = (*tpmResetRecordingAuditLogger)(nil)

// TestTPMService_ClearTPM_RecordsOpTPMReset verifies that a successful
// standard TPM2_Clear records audit.OpTPMReset.
func TestTPMService_ClearTPM_RecordsOpTPMReset(t *testing.T) {
	mock := defaultMockTPM()
	mock.clearAllowed = true

	svc, _ := ftCreateService(t, mock)
	rec := &tpmResetRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	result, err := svc.ClearTPM(&TPMClearRequest{LockoutAuth: "lockout"})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.True(t, result.Success)

	require.Len(t, rec.entries, 1)
	assert.Equal(t, audit.OpTPMReset, rec.entries[0].Operation)
	assert.True(t, rec.entries[0].Success)
	assert.Equal(t, "standard", rec.entries[0].Details["method"])
}

// TestTPMService_ClearTPM_Failure_RecordsOpTPMReset verifies that a failed
// TPM2_Clear also records audit.OpTPMReset, with Success false.
func TestTPMService_ClearTPM_Failure_RecordsOpTPMReset(t *testing.T) {
	mock := defaultMockTPM()
	mock.clearAllowed = true
	mock.clearErr = errors.New("tpm: clear failed")

	svc, _ := ftCreateService(t, mock)
	rec := &tpmResetRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	_, err := svc.ClearTPM(&TPMClearRequest{LockoutAuth: "lockout"})
	require.Error(t, err)

	require.Len(t, rec.entries, 1)
	assert.Equal(t, audit.OpTPMReset, rec.entries[0].Operation)
	assert.False(t, rec.entries[0].Success)
}

// TestTPMService_ClearTPM_AuditWriteFailureFailsOperation verifies the
// issue #688 policy: OpTPMReset is SeveritySecurity, so a failed audit
// write fails ClearTPM even though the underlying TPM2_Clear succeeded.
func TestTPMService_ClearTPM_AuditWriteFailureFailsOperation(t *testing.T) {
	mock := defaultMockTPM()
	mock.clearAllowed = true

	svc, _ := ftCreateService(t, mock)
	auditErr := errors.New("audit backend unavailable")
	svc.SetAuditLogger(&tpmResetRecordingAuditLogger{logErr: auditErr})

	_, err := svc.ClearTPM(&TPMClearRequest{LockoutAuth: "lockout"})
	require.Error(t, err)
	assert.True(t, mock.clearCalled, "the TPM clear itself must have run before the audit write was attempted")
}
