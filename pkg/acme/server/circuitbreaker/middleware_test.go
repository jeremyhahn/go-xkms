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

package circuitbreaker

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// middlewareTestBreaker returns a breaker whose transitions this file can
// drive deterministically: MaxFailures 1 so a single 5xx opens it,
// ResetTimeout 0 so the very next request probes half-open immediately, and
// SuccessThreshold 1 so a single successful probe closes it again.
func middlewareTestBreaker(name string) *CircuitBreaker {
	return New(&Config{
		Name:                name,
		MaxFailures:         1,
		ResetTimeout:        0,
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    1,
	})
}

// TestMiddleware_ClosedPassesThroughAndRecordsSuccess verifies that a
// request reaching a healthy handler is let through and settles the breaker
// with a success.
func TestMiddleware_ClosedPassesThroughAndRecordsSuccess(t *testing.T) {
	cb := middlewareTestBreaker("mw-closed-success")
	handler := Middleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, StateClosed, cb.State())
	failures, successes := cb.Counts()
	assert.Equal(t, uint32(0), failures)
	assert.Equal(t, uint32(1), successes)
}

// TestMiddleware_ClosedRecordsFailureAndOpens verifies that a 5xx response
// from the wrapped handler counts as a breaker failure, and with
// MaxFailures 1 trips the breaker open.
func TestMiddleware_ClosedRecordsFailureAndOpens(t *testing.T) {
	cb := middlewareTestBreaker("mw-closed-failure")
	handler := Middleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	// The handler's own response reaches the client unmodified -- Middleware
	// observes the outcome, it does not rewrite it.
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Equal(t, StateOpen, cb.State())
}

// TestMiddleware_OpenRejectsWithServiceUnavailable verifies that a request
// arriving while the breaker is open never reaches the wrapped handler, and
// gets a 503 with a Retry-After header instead.
func TestMiddleware_OpenRejectsWithServiceUnavailable(t *testing.T) {
	cb := New(&Config{
		Name:         "mw-open",
		MaxFailures:  1,
		ResetTimeout: time.Hour, // long enough that this test cannot race past it
	})
	cb.Trip()
	require.Equal(t, StateOpen, cb.State())

	var handlerCalled bool
	handler := Middleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		handlerCalled = true
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.False(t, handlerCalled, "the wrapped handler must not run while the breaker is open")
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("Retry-After"))
	assert.Equal(t, "application/json", rec.Header().Get("Content-Type"))
}

// TestMiddleware_OpenRetryAfterFloorsAtOneSecond verifies that
// writeCircuitOpenError clamps a sub-second remaining-reset-timeout to one
// second rather than advertising a Retry-After of 0. ResetTimeout is short
// enough that the elapsed time since Trip is a small fraction of it, so the
// clamp is exercised deterministically without any wall-clock wait.
func TestMiddleware_OpenRetryAfterFloorsAtOneSecond(t *testing.T) {
	cb := New(&Config{
		Name:         "mw-open-short-reset",
		MaxFailures:  1,
		ResetTimeout: 500 * time.Millisecond,
	})
	cb.Trip()
	require.Equal(t, StateOpen, cb.State())

	handler := Middleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
	assert.Equal(t, "1", rec.Header().Get("Retry-After"))
}

// TestMiddleware_HalfOpenProbeCloses verifies the full cycle: a failure
// opens the breaker, the next request (ResetTimeout 0) is admitted as a
// half-open probe, and a successful probe closes the breaker again.
func TestMiddleware_HalfOpenProbeCloses(t *testing.T) {
	cb := middlewareTestBreaker("mw-half-open")
	status := http.StatusInternalServerError
	handler := Middleware(cb)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
	}))

	// First request fails and opens the breaker.
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	require.Equal(t, StateOpen, cb.State())

	// Second request: ResetTimeout 0 admits it as a half-open probe. Make it
	// succeed so the probe demonstrates recovery.
	status = http.StatusOK
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, StateClosed, cb.State())
}
