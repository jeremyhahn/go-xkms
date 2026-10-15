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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestMakeCredential_EmitsAuditEvent_OnSuccess verifies the credential
// creation is recorded exactly once, with its credential ID.
func TestMakeCredential_EmitsAuditEvent_OnSuccess(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	logger := &recordingAuditLogger{}
	auth.SetAuditLogger(logger)

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-123"), Name: "john.doe@example.com", DisplayName: "John Doe"}
	pubKeyCredParams := []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}

	resp, err := auth.MakeCredential(clientDataHash[:], rp, user, pubKeyCredParams, nil)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, logger.credentials, 1)
	assert.NotEmpty(t, logger.credentials[0])
	assert.Zero(t, logger.pinSeeded)
}

// TestMakeCredential_AuditWriteFailure_FailsAndDoesNotPersistCredential
// verifies that a failed audit write refuses credential creation and the
// credential is not persisted to storage.
func TestMakeCredential_AuditWriteFailure_FailsAndDoesNotPersistCredential(t *testing.T) {
	auth := createMakeCredentialTestAuthenticator(t)
	defer func() { _ = auth.Close() }()

	auditErr := errors.New("audit backend unavailable")
	auth.SetAuditLogger(&recordingAuditLogger{failWith: auditErr})

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

	logger := &recordingAuditLogger{}
	auth.SetAuditLogger(logger)

	clientData := []byte("test client data for hashing")
	clientDataHash := sha256.Sum256(clientData)
	rp := RelyingParty{ID: "example.com", Name: "Example Corp"}
	user := User{ID: []byte("user-789"), Name: "no-alg@example.com", DisplayName: "No Alg"}

	// No acceptable algorithm: refused before any key is generated or
	// stored.
	_, err := auth.MakeCredential(clientDataHash[:], rp, user, nil, nil)
	require.Error(t, err)
	assert.Empty(t, logger.credentials, "a request refused before credential creation must not be audited as created")
}
