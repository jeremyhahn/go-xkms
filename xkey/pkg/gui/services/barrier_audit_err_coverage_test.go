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

package services

import (
	"errors"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
)

// failingBarrierAuditLogger implements audit.Logger, failing every Log call
// so barrierAuditErr's audit-write-failure branch can be exercised
// deterministically.
type failingBarrierAuditLogger struct{ err error }

func (f *failingBarrierAuditLogger) Log(audit.Entry) error { return f.err }
func (f *failingBarrierAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) error {
	return nil
}
func (f *failingBarrierAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) error {
	return nil
}

var _ audit.Logger = (*failingBarrierAuditLogger)(nil)

// TestBarrierService_BarrierAuditErr_AuditWriteFailureWins covers the
// branch where the audit write itself fails: that failure must be
// returned instead of the original error, since a SeveritySecurity event
// that never reached the audit log needs to be visible to the caller.
func TestBarrierService_BarrierAuditErr_AuditWriteFailureWins(t *testing.T) {
	s := NewBarrierService(t.TempDir(), slog.Default())
	auditErr := errors.New("audit store unavailable")
	s.SetAuditLogger(&failingBarrierAuditLogger{err: auditErr})

	origErr := errors.New("original failure")
	got := s.barrierAuditErr(audit.OpBarrierInitialized, false, origErr, nil)

	assert.Equal(t, auditErr, got)
}

// TestBarrierService_BarrierAuditErr_ReturnsOriginalErrorOnSuccess covers
// the branch where the audit write succeeds: the caller's original error
// (which may be nil) must be returned unchanged.
func TestBarrierService_BarrierAuditErr_ReturnsOriginalErrorOnSuccess(t *testing.T) {
	s := NewBarrierService(t.TempDir(), slog.Default())
	s.SetAuditLogger(&failingBarrierAuditLogger{err: nil})

	origErr := errors.New("original failure")
	got := s.barrierAuditErr(audit.OpBarrierInitialized, false, origErr, nil)

	assert.Equal(t, origErr, got)
}
