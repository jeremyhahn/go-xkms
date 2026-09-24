// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package audit

import (
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/metrics"
)

func TestClassifyAction_KnownSecurityActions(t *testing.T) {
	for _, action := range []string{"authorize", "seal", "unseal"} {
		t.Run(action, func(t *testing.T) {
			assert.Equal(t, SeveritySecurity, ClassifyAction(action))
		})
	}
}

func TestClassifyAction_UnknownActionDefaultsToSecurity(t *testing.T) {
	assert.Equal(t, SeveritySecurity, ClassifyAction("some_action_nobody_has_reviewed"))
}

// withInformationalAction temporarily classifies action as
// SeverityInformational for the duration of the test, restoring the
// package's classification set afterward. There is no production
// informational action in this package today (see informationalActions),
// so HandleWriteFailure's informational branch is exercised this way.
func withInformationalAction(t *testing.T, action string) {
	t.Helper()
	informationalActions[action] = true
	t.Cleanup(func() { delete(informationalActions, action) })
}

func TestHandleWriteFailure_NilErrorIsNoOp(t *testing.T) {
	err := HandleWriteFailure(nil, "authorize", nil)
	require.NoError(t, err)
}

// TestHandleWriteFailure_SecurityActionReturnsTypedError verifies the
// issue #688 policy: a failed write for a SeveritySecurity action returns
// *ErrAuditWriteFailed so the caller fails the operation.
func TestHandleWriteFailure_SecurityActionReturnsTypedError(t *testing.T) {
	writeErr := errors.New("backend unavailable")

	err := HandleWriteFailure(nil, "authorize", writeErr)

	require.Error(t, err)
	var typed *ErrAuditWriteFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, "authorize", typed.Action)
	assert.ErrorIs(t, err, writeErr)
}

// TestHandleWriteFailure_InformationalActionLogsAndIncrementsMetric
// verifies the issue #688 policy: a failed write for a
// SeverityInformational action does not fail the caller, and increments
// metrics.AuditWriteFailuresTotal.
func TestHandleWriteFailure_InformationalActionLogsAndIncrementsMetric(t *testing.T) {
	const action = "test_informational_action"
	withInformationalAction(t, action)

	before := testutil.ToFloat64(metrics.AuditWriteFailuresTotal.WithLabelValues(action))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := HandleWriteFailure(logger, action, errors.New("backend unavailable"))

	require.NoError(t, err)
	after := testutil.ToFloat64(metrics.AuditWriteFailuresTotal.WithLabelValues(action))
	assert.Equal(t, before+1, after)
}

func TestHandleWriteFailure_InformationalActionNilLoggerDoesNotPanic(t *testing.T) {
	const action = "test_informational_action_nil_logger"
	withInformationalAction(t, action)

	require.NotPanics(t, func() {
		err := HandleWriteFailure(nil, action, errors.New("backend unavailable"))
		require.NoError(t, err)
	})
}
