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

package nativemsg

import (
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHostAuditLogger implements audit.Logger, recording only what
// logHostEvent uses (Log) and failing loudly if an unexpected method runs.
type mockHostAuditLogger struct {
	logErr    error
	entries   []audit.Entry
	callCount int
}

func (m *mockHostAuditLogger) Log(entry audit.Entry) error {
	m.callCount++
	m.entries = append(m.entries, entry)
	return m.logErr
}
func (m *mockHostAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return errNotImplementedHostAudit
}
func (m *mockHostAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return errNotImplementedHostAudit
}

var errNotImplementedHostAudit = errors.New("not implemented")

var _ audit.Logger = (*mockHostAuditLogger)(nil)

// TestHost_LogHostEvent_NoLoggerIsNoop verifies a Host with no audit logger
// configured is a silent no-op, so Run's unconditional logHostEvent calls
// never fail a host that was not given one.
func TestHost_LogHostEvent_NoLoggerIsNoop(t *testing.T) {
	h := NewHost("", testLogger(), nil)
	err := h.logHostEvent(audit.OpExtensionHandshake, true, nil, map[string]any{"x": 1})
	assert.NoError(t, err)
}

// TestHost_SetAuditLogger_LogHostEvent verifies SetAuditLogger wires the
// logger logHostEvent uses, and that the entry carries the operation,
// success flag, error text, and details given to it.
func TestHost_SetAuditLogger_LogHostEvent(t *testing.T) {
	h := NewHost("", testLogger(), nil)
	al := &mockHostAuditLogger{}
	h.SetAuditLogger(al)

	cause := errors.New("boom")
	err := h.logHostEvent(audit.OpExtensionHandshake, false, cause, map[string]any{"origin": "example.com"})
	require.NoError(t, err)

	require.Equal(t, 1, al.callCount)
	entry := al.entries[0]
	assert.Equal(t, audit.OpExtensionHandshake, entry.Operation)
	assert.False(t, entry.Success)
	assert.Equal(t, "boom", entry.Error)
	assert.Equal(t, "example.com", entry.Details["origin"])
}

// TestHost_LogHostEvent_NilErrorLeavesErrorStringEmpty verifies a nil error
// produces an empty Error field rather than "<nil>".
func TestHost_LogHostEvent_NilErrorLeavesErrorStringEmpty(t *testing.T) {
	h := NewHost("", testLogger(), nil)
	al := &mockHostAuditLogger{}
	h.SetAuditLogger(al)

	require.NoError(t, h.logHostEvent(audit.OpExtensionHandshake, true, nil, nil))
	require.Len(t, al.entries, 1)
	assert.Empty(t, al.entries[0].Error)
}

// TestHost_LogHostEvent_PropagatesWriteFailure verifies a failing audit
// write is returned to the caller rather than swallowed.
func TestHost_LogHostEvent_PropagatesWriteFailure(t *testing.T) {
	h := NewHost("", testLogger(), nil)
	al := &mockHostAuditLogger{logErr: errors.New("audit store unavailable")}
	h.SetAuditLogger(al)

	err := h.logHostEvent(audit.OpExtensionHandshake, false, errors.New("cause"), nil)
	assert.Error(t, err)
}
