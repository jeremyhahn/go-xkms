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

package ca

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/audit/audittest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockAuditLoggerCA records every audit event it receives, for asserting the
// fields a CA lifecycle event carries on success.
type mockAuditLoggerCA = audittest.Recorder

// failingAuditLoggerCA always fails to persist, so the CA lifecycle
// write-failure handling can be exercised without a real backend.
type failingAuditLoggerCA = audittest.Failing

// =============================================================================
// CA_INITIALIZED (root)
// =============================================================================

func TestCAInit_EmitsAuditEvent_OnSuccess(t *testing.T) {
	ca := setupUninitializedCA(t)
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger

	require.NoError(t, ca.Init(context.Background()))

	events := logger.Events()
	require.NotEmpty(t, events)
	ev := events[0]
	assert.Equal(t, auditActionCAInit, ev.Action)
	assert.Equal(t, auditResourceCA, ev.Resource)
	assert.Equal(t, "Uninitialized Root CA", ev.ResourceID)
	assert.Equal(t, audit.OutcomeAllow, ev.Outcome)
	assert.Equal(t, "system", ev.Subject)
}

func TestCAInit_AuditWriteFailure_FailsInitAndDoesNotPersistCert(t *testing.T) {
	ca := setupUninitializedCA(t)
	auditErr := errors.New("audit backend unavailable")
	ca.auditLogger = &failingAuditLoggerCA{Err: auditErr}

	err := ca.Init(context.Background())
	require.Error(t, err)

	var writeErr *qrdbsdk.AuditGateError
	require.ErrorAs(t, err, &writeErr)
	assert.ErrorIs(t, writeErr, auditErr)

	// The root certificate must not have been persisted: the audit write
	// gates the commit.
	_, getErr := ca.certStore.GetCertificate("Uninitialized Root CA")
	assert.Error(t, getErr)
	assert.False(t, ca.initialized.Load())
}

func TestCAInit_OperationFailure_DoesNotReachAuditGate(t *testing.T) {
	ca := setupUninitializedCA(t)
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger
	ca.initialized.Store(true) // Simulate an already-initialized CA.

	err := ca.Init(context.Background())
	require.ErrorIs(t, err, ErrAlreadyInitialized)

	// Init refused before it ever reached createRootCertificate's audit
	// gate, so no CA_INITIALIZED event was fabricated for an operation that
	// never ran.
	assert.Empty(t, logger.Events())
}

// =============================================================================
// CA_CRL_GENERATED
// =============================================================================

func TestGenerateCRL_EmitsAuditEvent_OnSuccess(t *testing.T) {
	ca := setupTestCA(t)
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger

	_, err := ca.GenerateCRL(context.Background())
	require.NoError(t, err)

	events := logger.Events()
	require.NotEmpty(t, events)
	ev := events[len(events)-1]
	assert.Equal(t, auditActionCACRLGenerate, ev.Action)
	assert.Equal(t, auditResourceCRL, ev.Resource)
	assert.Equal(t, audit.OutcomeAllow, ev.Outcome)
}

func TestGenerateCRL_AuditWriteFailure_FailsAndDoesNotPersistCRL(t *testing.T) {
	ca := setupTestCA(t)
	auditErr := errors.New("audit backend unavailable")
	ca.auditLogger = &failingAuditLoggerCA{Err: auditErr}

	_, err := ca.GenerateCRL(context.Background())
	require.Error(t, err)

	var writeErr *qrdbsdk.AuditGateError
	require.ErrorAs(t, err, &writeErr)

	issuingCert := ca.getIssuingCertificate()
	require.NotNil(t, issuingCert)
	_, getErr := ca.getCRLBlob(context.Background(), issuingCert.SubjectKeyId)
	assert.ErrorIs(t, getErr, ErrCRLNotFound)
}

func TestGenerateCRL_OperationFailure_DoesNotReachAuditGate(t *testing.T) {
	ca := setupUninitializedCA(t)
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger

	_, err := ca.GenerateCRL(context.Background())
	require.ErrorIs(t, err, ErrNotInitialized)

	// GenerateCRL refused before it ever reached generateAndPersistCRL's
	// audit gate.
	assert.Empty(t, logger.Events())
}

// =============================================================================
// CA_CROSS_SIGN
// =============================================================================

func TestImportXSignedCertificate_EmitsAuditEvent_OnSuccess(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger
	cert, _ := makeSelfSignedCert(t, "leaf")

	require.NoError(t, ca.ImportXSignedCertificate("external-issuer", cert))

	events := logger.Events()
	require.NotEmpty(t, events)
	ev := events[len(events)-1]
	assert.Equal(t, auditActionCACrossSign, ev.Action)
	assert.Equal(t, auditResourceCrossSigned, ev.Resource)
	assert.Equal(t, crossSignedStoreKey("external-issuer", "leaf"), ev.ResourceID)
	assert.Equal(t, audit.OutcomeAllow, ev.Outcome)
}

func TestImportXSignedCertificate_AuditWriteFailure_FailsAndDoesNotPersist(t *testing.T) {
	ca := setupTestCAWithObjectStore(t)
	auditErr := errors.New("audit backend unavailable")
	ca.auditLogger = &failingAuditLoggerCA{Err: auditErr}
	cert, _ := makeSelfSignedCert(t, "leaf")

	err := ca.ImportXSignedCertificate("external-issuer", cert)
	require.Error(t, err)

	var writeErr *qrdbsdk.AuditGateError
	require.ErrorAs(t, err, &writeErr)

	key := crossSignedStoreKey("external-issuer", "leaf")
	_, getErr := ca.objectStore.Get(key)
	assert.Error(t, getErr)
}

func TestImportXSignedCertificate_OperationFailure_DoesNotReachAuditGate(t *testing.T) {
	ca := setupTestCA(t) // No object store configured.
	logger := &mockAuditLoggerCA{}
	ca.auditLogger = logger
	cert, _ := makeSelfSignedCert(t, "leaf")

	err := ca.ImportXSignedCertificate("external-issuer", cert)
	require.ErrorIs(t, err, ErrObjectStoreRequired)

	// Refused before it ever reached the audit gate.
	assert.Empty(t, logger.Events())
}
