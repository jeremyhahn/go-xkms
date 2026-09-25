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
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// keyOpCall records one LogKeyOperation invocation.
type keyOpCall struct {
	op      audit.OperationType
	backend string
	keyID   string
	success bool
}

// recordingKeyAuditLogger implements audit.Logger, recording every
// LogKeyOperation call and optionally failing every write with a fixed
// error.
type recordingKeyAuditLogger struct {
	failWith error
	keyCalls []keyOpCall
}

func (l *recordingKeyAuditLogger) Log(audit.Entry) error { return l.failWith }

func (l *recordingKeyAuditLogger) LogKeyOperation(op audit.OperationType, backend, keyID string, success bool, err error, durationMs int64) error {
	l.keyCalls = append(l.keyCalls, keyOpCall{op: op, backend: backend, keyID: keyID, success: success})
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogCryptoOperation(op audit.OperationType, backend, keyID, deviceID, deviceName string, success bool, err error, durationMs int64) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogConnectionEvent(op audit.OperationType, deviceID, deviceName string, details map[string]any) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogServiceEvent(op audit.OperationType, details map[string]any) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogPINOperation(op audit.OperationType, backend string, success bool, err error, details map[string]any) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogTPMOperation(op audit.OperationType, success bool, err error, details map[string]any) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogPasswordStoreOperation(op audit.OperationType, source string, success bool, err error, details map[string]any) error {
	return l.failWith
}

func (l *recordingKeyAuditLogger) LogUserPresenceEvent(op audit.OperationType, source string, success bool, details map[string]any) error {
	return l.failWith
}

var _ audit.Logger = (*recordingKeyAuditLogger)(nil)

// TestMakeCredential_EmitsAuditEvent_OnSuccess verifies OpFIDO2CredentialCreated
// is recorded, with the correct fields, when a credential is created.
func TestMakeCredential_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingKeyAuditLogger{}
	auth.SetAuditLogger(logger)

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-123"), Name: "john.doe@example.com", DisplayName: "John Doe"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, logger.keyCalls, 1)
	assert.Equal(t, audit.OpFIDO2CredentialCreated, logger.keyCalls[0].op)
	assert.Equal(t, "fido2", logger.keyCalls[0].backend)
	assert.True(t, logger.keyCalls[0].success)
	assert.NotEmpty(t, logger.keyCalls[0].keyID)
}

// TestMakeCredential_AuditWriteFailure_FailsAndDoesNotPersistCredential
// verifies that a failed audit write refuses credential creation and the
// credential is not persisted to storage.
func TestMakeCredential_AuditWriteFailure_FailsAndDoesNotPersistCredential(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	auditErr := errors.New("audit backend unavailable")
	auth.SetAuditLogger(&recordingKeyAuditLogger{failWith: auditErr})

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-456"), Name: "jane.doe@example.com", DisplayName: "Jane Doe"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	_, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, nil)
	require.ErrorIs(t, err, auditErr)

	count, countErr := auth.storage.Count()
	require.NoError(t, countErr)
	assert.Zero(t, count, "no credential must be persisted when its audit record could not be written")
}

// TestMakeCredential_OperationFailure_DoesNotReachAuditGate verifies that a
// MakeCredential call refused before key generation (an unsupported
// algorithm) never calls the audit logger.
func TestMakeCredential_OperationFailure_DoesNotReachAuditGate(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingKeyAuditLogger{}
	auth.SetAuditLogger(logger)

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-789"), Name: "no-alg@example.com", DisplayName: "No Alg"}

	// No acceptable algorithm: refused before any key is generated or
	// stored.
	_, err := auth.MakeCredential(clientDataHash[:], rp, user, nil, nil)
	require.Error(t, err)
	assert.Empty(t, logger.keyCalls, "a request refused before credential creation must not be audited as created")
}
