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

// spwRecordingAuditLogger records every password-store audit entry so tests
// can assert on the operation and fields recorded.
type spwRecordingAuditLogger struct {
	entries []audit.Entry
	logErr  error
}

func (l *spwRecordingAuditLogger) Log(e audit.Entry) error {
	if l.logErr != nil {
		return l.logErr
	}
	l.entries = append(l.entries, e)
	return nil
}
func (l *spwRecordingAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) error {
	return nil
}
func (l *spwRecordingAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) error {
	if l.logErr != nil {
		return l.logErr
	}
	l.entries = append(l.entries, audit.Entry{Operation: op, Success: success, Details: details})
	return nil
}
func (l *spwRecordingAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return nil
}

var _ audit.Logger = (*spwRecordingAuditLogger)(nil)

func (l *spwRecordingAuditLogger) last() audit.Entry {
	return l.entries[len(l.entries)-1]
}

func TestStaticPasswordService_AddPassword_RecordsOpPasswordCreated(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	_, err := svc.AddPassword(AddPasswordParams{Name: "site", Password: "secret"})
	require.NoError(t, err)

	require.NotEmpty(t, rec.entries)
	assert.Equal(t, audit.OpPasswordCreated, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_UpdatePassword_RecordsOpPasswordUpdated(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	entry, err := svc.AddPassword(AddPasswordParams{Name: "site", Password: "secret"})
	require.NoError(t, err)

	err = svc.UpdatePassword(UpdatePasswordParams{ID: entry.ID, Name: "site", Password: "new-secret"})
	require.NoError(t, err)

	assert.Equal(t, audit.OpPasswordUpdated, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_DeletePassword_RecordsOpPasswordDeleted(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	entry, err := svc.AddPassword(AddPasswordParams{Name: "site", Password: "secret"})
	require.NoError(t, err)

	require.NoError(t, svc.DeletePassword(entry.ID))

	assert.Equal(t, audit.OpPasswordDeleted, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_GetPassword_RecordsOpPasswordAccessed(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	entry, err := svc.AddPassword(AddPasswordParams{Name: "site", Password: "secret"})
	require.NoError(t, err)

	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	_, err = svc.GetPassword(entry.ID)
	require.NoError(t, err)

	assert.Equal(t, audit.OpPasswordAccessed, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_Unlock_RecordsOpPasswordStoreUnlocked(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	require.NoError(t, svc.Unlock("1234"))

	assert.Equal(t, audit.OpPasswordStoreUnlocked, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

func TestStaticPasswordService_Lock_RecordsOpPasswordStoreLocked(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)
	rec := &spwRecordingAuditLogger{}
	svc.SetAuditLogger(rec)

	require.NoError(t, svc.Lock())

	assert.Equal(t, audit.OpPasswordStoreLocked, rec.last().Operation)
	assert.True(t, rec.last().Success)
}

// TestStaticPasswordService_AddPassword_AuditWriteFailureFailsOperation
// verifies the issue #688 policy: OpPasswordCreated is SeveritySecurity, so
// a failed audit write fails AddPassword even though the store write
// itself succeeded.
func TestStaticPasswordService_AddPassword_AuditWriteFailureFailsOperation(t *testing.T) {
	svc, store := newTestStaticPWService(t)
	svc.SetAuditLogger(&spwRecordingAuditLogger{logErr: errors.New("audit backend unavailable")})

	_, err := svc.AddPassword(AddPasswordParams{Name: "site", Password: "secret"})
	require.Error(t, err)

	// The store write already committed; only the caller's success signal
	// is withheld until the trail can be trusted.
	entries, listErr := store.List()
	require.NoError(t, listErr)
	assert.Len(t, entries, 1)
}
