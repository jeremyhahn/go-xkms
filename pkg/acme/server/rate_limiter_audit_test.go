// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.

package server

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// recordingRateLimitAuditLogger records events for assertions.
type recordingRateLimitAuditLogger struct {
	events []*audit.AuditEvent
	logErr error
}

func (r *recordingRateLimitAuditLogger) Log(_ context.Context, event *audit.AuditEvent) error {
	if r.logErr != nil {
		return r.logErr
	}
	r.events = append(r.events, event)
	return nil
}

func (r *recordingRateLimitAuditLogger) LogWithContext(ctx context.Context, eventType audit.EventType, actor, resource, action string, result audit.Result, details map[string]interface{}) error {
	return r.Log(ctx, &audit.AuditEvent{
		EventType: eventType,
		Actor:     actor,
		Resource:  resource,
		Action:    action,
		Result:    result,
		Details:   details,
	})
}

func (r *recordingRateLimitAuditLogger) Flush() error  { return nil }
func (r *recordingRateLimitAuditLogger) Close() error  { return nil }
func (r *recordingRateLimitAuditLogger) Enabled() bool { return true }

// TestRateLimiter_RecordsEventRateLimitExceeded verifies that a throttled
// request emits audit.EventRateLimitExceeded with the resource key and
// limiter configuration recorded.
func TestRateLimiter_RecordsEventRateLimitExceeded(t *testing.T) {
	limiter := NewRateLimiter(1, time.Minute)
	recorder := &recordingRateLimitAuditLogger{}
	limiter.SetAuditLogger(recorder)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := limiter.MiddlewareFunc(func(r *http.Request) string { return "client-1" })(handler)

	// First request consumes the only token.
	req1 := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec1 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusOK, rec1.Code)
	require.Empty(t, recorder.events)

	// Second request is throttled and must be audited.
	req2 := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec2 := httptest.NewRecorder()
	wrapped.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusTooManyRequests, rec2.Code)

	require.Len(t, recorder.events, 1)
	event := recorder.events[0]
	assert.Equal(t, audit.EventRateLimitExceeded, event.EventType)
	assert.Equal(t, "client-1", event.Actor)
	assert.Equal(t, audit.ResultFailure, event.Result)
	assert.Equal(t, 1, event.Details["max_requests"])
}

// TestRateLimiter_AuditWriteFailureStillDeniesRequest verifies the issue
// #688 policy in context: EventRateLimitExceeded is SeveritySecurity, but
// the rate limiter has already decided to deny the request either way, so
// a failed audit write cannot make the outcome any more permissive — the
// response stays 429 and the failure is only observable through the
// default logger.
func TestRateLimiter_AuditWriteFailureStillDeniesRequest(t *testing.T) {
	limiter := NewRateLimiter(0, time.Minute)
	limiter.SetAuditLogger(&recordingRateLimitAuditLogger{logErr: errors.New("audit backend unavailable")})

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := limiter.MiddlewareFunc(func(r *http.Request) string { return "client-2" })(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	wrapped.ServeHTTP(rec, req)

	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// TestRateLimiter_NilAuditLoggerIsNoOp verifies that rate limiting works
// without audit wiring (the default for NewRateLimiter).
func TestRateLimiter_NilAuditLoggerIsNoOp(t *testing.T) {
	limiter := NewRateLimiter(0, time.Minute)

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	wrapped := limiter.MiddlewareFunc(func(r *http.Request) string { return "client-3" })(handler)

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	require.NotPanics(t, func() { wrapped.ServeHTTP(rec, req) })
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}
