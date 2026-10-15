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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingAuditLogger implements AuditLogger, recording every call and
// optionally failing every write with a fixed error, so the write-failure
// handling in this package can be exercised without a real audit store.
type recordingAuditLogger struct {
	failWith    error
	credentials []string
	pinSeeded   int
}

func (l *recordingAuditLogger) LogCredentialCreated(credentialID string) error {
	l.credentials = append(l.credentials, credentialID)
	return l.failWith
}

func (l *recordingAuditLogger) LogPINSeeded() error {
	l.pinSeeded++
	return l.failWith
}

var _ AuditLogger = (*recordingAuditLogger)(nil)

// TestSetInitialPIN_EmitsAuditEvent_OnSuccess verifies the PIN seeding is
// recorded exactly once when a PIN is established.
func TestSetInitialPIN_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingAuditLogger{}
	auth.SetAuditLogger(logger)

	require.NoError(t, auth.SetInitialPIN([]byte("123456")))

	assert.Equal(t, 1, logger.pinSeeded)
	assert.Empty(t, logger.credentials)
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
	assert.Zero(t, logger.pinSeeded, "a policy-refused PIN must not be audited as seeded")
}
