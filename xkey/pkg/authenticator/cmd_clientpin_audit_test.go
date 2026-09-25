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

package authenticator

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// pinOpCall records one LogPINOperation invocation, for asserting the fields
// establishPINLocked hands to the audit logger on success.
type pinOpCall struct {
	op      audit.OperationType
	backend string
	success bool
}

// recordingAuditLogger implements audit.Logger, recording every
// LogPINOperation/LogKeyOperation call and optionally failing every write
// with a fixed error, so the write-failure handling in this package can be
// exercised without a real backend.
type recordingAuditLogger struct {
	failWith error
	pinCalls []pinOpCall
}

func (l *recordingAuditLogger) Log(audit.Entry) error { return l.failWith }

func (l *recordingAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, err error, details map[string]any) error {
	l.pinCalls = append(l.pinCalls, pinOpCall{op: op, backend: backend, success: success})
	return l.failWith
}

func (l *recordingAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) error {
	return l.failWith
}

func (l *recordingAuditLogger) LogUserPresenceEvent(op audit.OperationType, source string, success bool, details map[string]any) error {
	return l.failWith
}

var _ audit.Logger = (*recordingAuditLogger)(nil)

// TestSetInitialPIN_EmitsAuditEvent_OnSuccess verifies OpPINSeeded is
// recorded, with the correct fields, when a PIN is established.
func TestSetInitialPIN_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingAuditLogger{}
	auth.SetAuditLogger(logger)

	require.NoError(t, auth.SetInitialPIN([]byte("123456")))

	require.Len(t, logger.pinCalls, 1)
	assert.Equal(t, audit.OpPINSeeded, logger.pinCalls[0].op)
	assert.True(t, logger.pinCalls[0].success)
}

// TestSetInitialPIN_AuditWriteFailure_FailsAndDoesNotPersistPIN verifies that
// a failed audit write refuses PIN establishment: the caller gets the audit
// logger's error back, and no PIN state is persisted.
func TestSetInitialPIN_AuditWriteFailure_FailsAndDoesNotPersistPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	auditErr := errors.New("audit backend unavailable")
	auth.SetAuditLogger(&recordingAuditLogger{failWith: auditErr})

	err := auth.SetInitialPIN([]byte("123456"))
	require.ErrorIs(t, err, auditErr)

	// The audit gate sits immediately before storage.SaveState (owner
	// ruling, go-xkms#688/#766): a failed write must refuse before the PIN
	// state reaches storage, exactly as a SaveState failure itself does
	// (TestSetInitialPIN_StorageFailureIsTyped).
	if persisted, loadErr := auth.storage.LoadState(); loadErr == nil {
		require.False(t, persisted.PINSet, "no PIN state must be persisted when its audit record could not be written")
	} else {
		require.ErrorIs(t, loadErr, ErrStateNotFound)
	}
}

// TestSetInitialPIN_OperationFailure_DoesNotReachAuditGate verifies that a
// PIN refused for policy reasons (too short) never calls the audit logger:
// the gate sits after establishPINLocked's own validation, so a rejected
// operation is not audited as a seeded PIN.
func TestSetInitialPIN_OperationFailure_DoesNotReachAuditGate(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingAuditLogger{}
	auth.SetAuditLogger(logger)

	err := auth.SetInitialPIN([]byte("123"))
	require.ErrorIs(t, err, ErrPINPolicyViolation)
	assert.Empty(t, logger.pinCalls, "a policy-refused PIN must not be audited as seeded")
}
