// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package seal

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/audit/audittest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingAuditLogger records events for assertions.
type recordingAuditLogger = audittest.Recorder

// failingAuditLogger fails every write.
type failingAuditLogger = audittest.Failing

func TestAuditLoggerFromXKMS_NilReturnsNil(t *testing.T) {
	result := AuditLoggerFromXKMS(nil)
	assert.Nil(t, result)
}

func TestAuditLoggerFromXKMS_WrapsLogger(t *testing.T) {
	inner := &recordingAuditLogger{}
	adapter := AuditLoggerFromXKMS(inner)
	require.NotNil(t, adapter)

	event := &qrdbsdk.AuditEvent{
		Timestamp:  time.Now(),
		Subject:    "test-subject",
		Action:     "test-action",
		Resource:   "test-resource",
		ResourceID: "test-id",
		Outcome:    "allow",
		Details:    map[string]string{"key": "value"},
	}
	err := adapter.Log(context.Background(), event)
	require.NoError(t, err)

	events := inner.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "test-subject", events[0].Subject)
	assert.Equal(t, "test-action", events[0].Action)
	assert.Equal(t, "test-resource", events[0].Resource)
	assert.Equal(t, "test-id", events[0].ResourceID)
	assert.Equal(t, "allow", events[0].Outcome)
	assert.Equal(t, map[string]string{"key": "value"}, events[0].Details)
}

func TestAuditLoggerAdapter_LogFailureSurfaces(t *testing.T) {
	logErr := errors.New("log failed")
	adapter := AuditLoggerFromXKMS(&failingAuditLogger{Err: logErr})

	err := adapter.Log(context.Background(), &qrdbsdk.AuditEvent{Action: "seal"})

	assert.ErrorIs(t, err, logErr)
}

// The adapter does not own the sink: the node that created it closes it.
func TestAuditLoggerAdapter_CloseLeavesSinkOpen(t *testing.T) {
	adapter := AuditLoggerFromXKMS(&failingAuditLogger{CloseErr: errors.New("must not be called")})
	require.NotNil(t, adapter)

	assert.NoError(t, adapter.Close())
}

func TestEmitAudit_NilLoggerIsNoOp(t *testing.T) {
	// Should not panic with nil logger, and reports no error.
	err := emitAudit(nil, "seal", "resource", "id", "allow", nil)
	require.NoError(t, err)
}

func TestEmitAudit_WithLogger(t *testing.T) {
	recorder := &recordingAuditLogger{}
	err := emitAudit(recorder, "seal", "platform_sealer", "software", "allow",
		map[string]string{"detail": "value"})
	require.NoError(t, err)

	events := recorder.Events()
	require.Len(t, events, 1)
	assert.Equal(t, "seal", events[0].Subject)
	assert.Equal(t, "seal", events[0].Action)
	assert.Equal(t, "platform_sealer", events[0].Resource)
	assert.Equal(t, "software", events[0].ResourceID)
	assert.Equal(t, "allow", events[0].Outcome)
}

// TestEmitAudit_LogErrorFailsSecurityOperation verifies the issue #688
// policy: a failed audit write on seal/unseal must be surfaced as
// *qrdbsdk.AuditGateError rather than swallowed, so the caller fails the
// seal/unseal request.
func TestEmitAudit_LogErrorFailsSecurityOperation(t *testing.T) {
	logErr := errors.New("log failed")
	inner := &failingAuditLogger{Err: logErr}

	err := emitAudit(inner, "seal", "resource", "id", "deny", nil)

	require.Error(t, err)
	var gateErr *qrdbsdk.AuditGateError
	require.ErrorAs(t, err, &gateErr)
	assert.Equal(t, "seal", gateErr.Component)
	assert.ErrorIs(t, err, logErr)
}
