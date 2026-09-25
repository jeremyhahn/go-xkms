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

package audit

import (
	"bytes"
	"errors"
	"log/slog"
	"testing"
)

// TestHandleWriteFailure_NilWriteErrIsNoop verifies a successful write
// (writeErr == nil) never produces an error, regardless of severity.
func TestHandleWriteFailure_NilWriteErrIsNoop(t *testing.T) {
	if err := handleWriteFailure(nil, OpConnectionEstablished, nil); err != nil {
		t.Fatalf("handleWriteFailure(nil writeErr) = %v, want nil", err)
	}
}

// TestHandleWriteFailure_SecurityOperationFails verifies a failed write for
// a SeveritySecurity operation returns *ErrAuditWriteFailed wrapping the
// cause, so the caller is forced to fail the triggering operation.
func TestHandleWriteFailure_SecurityOperationFails(t *testing.T) {
	cause := errors.New("dao: save failed")

	err := handleWriteFailure(nil, OpKeyCreated, cause)

	var writeFailed *ErrAuditWriteFailed
	if !errors.As(err, &writeFailed) {
		t.Fatalf("handleWriteFailure() = %v (%T), want *ErrAuditWriteFailed", err, err)
	}
	if writeFailed.Operation != OpKeyCreated {
		t.Errorf("Operation = %v, want %v", writeFailed.Operation, OpKeyCreated)
	}
	if !errors.Is(err, cause) {
		t.Errorf("errors.Is(err, cause) = false, want true (Unwrap must expose the cause)")
	}
}

// TestHandleWriteFailure_InformationalOperationLogsAndCounts verifies a
// failed write for a SeverityInformational operation is logged and counted
// but does not fail the caller.
func TestHandleWriteFailure_InformationalOperationLogsAndCounts(t *testing.T) {
	var buf bytes.Buffer
	slogger := slog.New(slog.NewTextHandler(&buf, nil))
	cause := errors.New("dao: save failed")

	err := handleWriteFailure(slogger, OpConnectionEstablished, cause)

	if err != nil {
		t.Fatalf("handleWriteFailure(informational) = %v, want nil", err)
	}
	if buf.Len() == 0 {
		t.Error("expected the write failure to be logged, got no output")
	}
}

// TestHandleWriteFailure_InformationalOperationNilLoggerIsSafe verifies a
// nil *slog.Logger is permitted for an informational failure: the counter
// still increments but there is nothing to log to, so it must not panic.
func TestHandleWriteFailure_InformationalOperationNilLoggerIsSafe(t *testing.T) {
	cause := errors.New("dao: save failed")

	err := handleWriteFailure(nil, OpConnectionEstablished, cause)

	if err != nil {
		t.Fatalf("handleWriteFailure(nil logger) = %v, want nil", err)
	}
}

// TestOperationType_Severity verifies the informational/security
// classification a caller relies on to decide whether handleWriteFailure can
// swallow a write failure.
func TestOperationType_Severity(t *testing.T) {
	tests := []struct {
		op   OperationType
		want Severity
	}{
		{OpConnectionEstablished, SeverityInformational},
		{OpAutofillRequested, SeverityInformational},
		{OpKeyCreated, SeveritySecurity},
		{OpSignRequest, SeveritySecurity},
		{OperationType("not_a_registered_operation"), SeveritySecurity},
	}

	for _, tc := range tests {
		t.Run(string(tc.op), func(t *testing.T) {
			if got := tc.op.Severity(); got != tc.want {
				t.Errorf("%s.Severity() = %v, want %v", tc.op, got, tc.want)
			}
		})
	}
}
