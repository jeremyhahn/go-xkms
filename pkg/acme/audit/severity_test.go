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

func TestEventType_Severity_KnownSecurityEvents(t *testing.T) {
	for _, e := range []EventType{
		EventCertificateIssued,
		EventCertificateRevoked,
		EventAuthenticationFailed,
		EventAuthorizationFailed,
		EventInvalidSignature,
		EventInvalidNonce,
		EventRateLimitExceeded,
		EventChallengeFailed,
		EventAccountKeyChanged,
		EventTPMEnrollment,
	} {
		t.Run(string(e), func(t *testing.T) {
			assert.Equal(t, SeveritySecurity, e.Severity())
		})
	}
}

func TestEventType_Severity_KnownInformationalEvents(t *testing.T) {
	for _, e := range []EventType{
		EventAccountCreated,
		EventOrderCreated,
		EventAuthorizationCreated,
		EventChallengeInitiated,
		EventChallengeCompleted,
	} {
		t.Run(string(e), func(t *testing.T) {
			assert.Equal(t, SeverityInformational, e.Severity())
		})
	}
}

func TestEventType_Severity_UnknownEventDefaultsToSecurity(t *testing.T) {
	assert.Equal(t, SeveritySecurity, EventType("nobody_has_reviewed_this").Severity())
}

func TestHandleWriteFailure_NilErrorIsNoOp(t *testing.T) {
	require.NoError(t, HandleWriteFailure(nil, EventCertificateIssued, nil))
}

// TestHandleWriteFailure_SecurityEventReturnsTypedError verifies the issue
// #688 policy: a failed write for a SeveritySecurity event returns
// *ErrAuditWriteFailed so the caller fails the operation.
func TestHandleWriteFailure_SecurityEventReturnsTypedError(t *testing.T) {
	writeErr := errors.New("audit backend unavailable")

	err := HandleWriteFailure(nil, EventCertificateRevoked, writeErr)

	require.Error(t, err)
	var typed *ErrAuditWriteFailed
	require.ErrorAs(t, err, &typed)
	assert.Equal(t, EventCertificateRevoked, typed.EventType)
	assert.ErrorIs(t, err, writeErr)
}

// TestHandleWriteFailure_InformationalEventLogsAndIncrementsMetric verifies
// the issue #688 policy: a failed write for a SeverityInformational event
// does not fail the caller, and increments metrics.AuditWriteFailuresTotal.
func TestHandleWriteFailure_InformationalEventLogsAndIncrementsMetric(t *testing.T) {
	before := testutil.ToFloat64(metrics.AuditWriteFailuresTotal.WithLabelValues(string(EventAccountCreated)))

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	err := HandleWriteFailure(logger, EventAccountCreated, errors.New("backend unavailable"))

	require.NoError(t, err)
	after := testutil.ToFloat64(metrics.AuditWriteFailuresTotal.WithLabelValues(string(EventAccountCreated)))
	assert.Equal(t, before+1, after)
}

func TestHandleWriteFailure_InformationalEventNilLoggerDoesNotPanic(t *testing.T) {
	require.NotPanics(t, func() {
		err := HandleWriteFailure(nil, EventOrderCreated, errors.New("backend unavailable"))
		require.NoError(t, err)
	})
}
