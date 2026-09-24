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
	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingAuditLogger records events for assertions.
type recordingAuditLogger struct {
	events []*audit.Event
}

func (r *recordingAuditLogger) Log(_ context.Context, event *audit.Event) error {
	r.events = append(r.events, event)
	return nil
}

func (r *recordingAuditLogger) Close() error { return nil }

// failingAuditLogger returns errors.
type failingAuditLogger struct {
	logErr   error
	closeErr error
}

func (f *failingAuditLogger) Log(_ context.Context, _ *audit.Event) error { return f.logErr }
func (f *failingAuditLogger) Close() error                                { return f.closeErr }

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

	require.Len(t, inner.events, 1)
	assert.Equal(t, "test-subject", inner.events[0].Subject)
	assert.Equal(t, "test-action", inner.events[0].Action)
	assert.Equal(t, "test-resource", inner.events[0].Resource)
	assert.Equal(t, "test-id", inner.events[0].ResourceID)
	assert.Equal(t, "allow", inner.events[0].Outcome)
	assert.Equal(t, map[string]string{"key": "value"}, inner.events[0].Details)
}

func TestAuditLoggerAdapter_Close(t *testing.T) {
	inner := &recordingAuditLogger{}
	adapter := AuditLoggerFromXKMS(inner)
	require.NotNil(t, adapter)

	err := adapter.Close()
	require.NoError(t, err)
}

func TestAuditLoggerAdapter_CloseError(t *testing.T) {
	closeErr := errors.New("close failed")
	inner := &failingAuditLogger{closeErr: closeErr}
	adapter := AuditLoggerFromXKMS(inner)
	require.NotNil(t, adapter)

	err := adapter.Close()
	assert.ErrorIs(t, err, closeErr)
}

func TestEmitAudit_NilLoggerIsNoOp(t *testing.T) {
	// Should not panic with nil logger, and reports no error.
	err := emitAudit(nil, nil, "seal", "resource", "id", "allow", nil)
	require.NoError(t, err)
}

func TestEmitAudit_WithLogger(t *testing.T) {
	recorder := &recordingAuditLogger{}
	err := emitAudit(recorder, nil, "seal", "platform_sealer", "software", "allow",
		map[string]string{"detail": "value"})
	require.NoError(t, err)

	require.Len(t, recorder.events, 1)
	assert.Equal(t, "seal", recorder.events[0].Subject)
	assert.Equal(t, "seal", recorder.events[0].Action)
	assert.Equal(t, "platform_sealer", recorder.events[0].Resource)
	assert.Equal(t, "software", recorder.events[0].ResourceID)
	assert.Equal(t, "allow", recorder.events[0].Outcome)
}

// TestEmitAudit_LogErrorFailsSecurityOperation verifies the issue #688
// policy: seal/unseal is a SeveritySecurity action, so a failed audit
// write must be surfaced as *audit.ErrAuditWriteFailed rather than
// swallowed, so the caller fails the seal/unseal request.
func TestEmitAudit_LogErrorFailsSecurityOperation(t *testing.T) {
	logErr := errors.New("log failed")
	inner := &failingAuditLogger{logErr: logErr}

	err := emitAudit(inner, nil, "seal", "resource", "id", "deny", nil)

	require.Error(t, err)
	var writeErr *audit.ErrAuditWriteFailed
	require.ErrorAs(t, err, &writeErr)
	assert.Equal(t, "seal", writeErr.Action)
	assert.ErrorIs(t, err, logErr)
}
