//go:build codec_json

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

package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/acme/server/circuitbreaker"
	"github.com/jeremyhahn/go-xkms/pkg/acme/server/degradation"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// resilientTestBreaker returns a breaker whose transitions these tests can
// drive deterministically: MaxFailures 1 so a single failure opens it, and a
// long ResetTimeout so an open breaker stays open for the duration of a test
// instead of racing a half-open probe.
func resilientTestBreaker(name string) *circuitbreaker.CircuitBreaker {
	return circuitbreaker.New(&circuitbreaker.Config{
		Name:                name,
		MaxFailures:         1,
		ResetTimeout:        time.Hour,
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    1,
	})
}

// enableResilience wires a storage breaker and degradation caches onto an
// already-constructed service, exactly as NewRestService would with
// Params.Breakers set. Tests use this instead of threading Params.Breakers
// through setupTestService so the CA-mock-swapping tests already covering
// CABundleHandler's non-degraded behavior are unaffected.
func enableResilience(s *RestService, cb *circuitbreaker.CircuitBreaker) {
	s.storageBreaker = cb
	s.directoryCache = degradation.NewCache("acme-directory-test", 4)
	s.caBundleCache = degradation.NewCache("acme-ca-bundle-test", 4)
	s.degradationCacheTTL = time.Minute
	s.degradationStaleTTL = 5 * time.Minute
}

// TestCABundleHandler_DegradesToCache_WhenStorageBreakerOpen verifies that
// once a good response has been cached, a live failure that trips the
// storage breaker falls back to serving that cached bundle instead of
// failing the request, and marks the response degraded.
func TestCABundleHandler_DegradesToCache_WhenStorageBreakerOpen(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	cb := resilientTestBreaker("ca-bundle-storage")
	enableResilience(service, cb)
	// A near-zero cache TTL makes the entry set below stale by the time the
	// third request reads it, without a real sleep: this test is about the
	// stale-serving path, not the still-fresh one (see
	// TestCABundleHandler_ServesFreshCache_NotDegraded_WhenBreakerOpen).
	service.degradationCacheTTL = time.Nanosecond

	// First request succeeds through the breaker and populates the cache.
	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()
	service.CABundleHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Equal(t, []byte("mock-bundle"), w.Body.Bytes())
	require.Equal(t, circuitbreaker.StateClosed, cb.State())
	require.Empty(t, w.Header().Get("Warning"), "a fresh response must not be marked degraded")

	// The CA starts failing, which trips the breaker (MaxFailures 1).
	service.ca = &MockCAWithError{}
	req = httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w = httptest.NewRecorder()
	service.CABundleHandler(w, req)
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())

	// A third request never reaches the failing CA at all -- the breaker is
	// open -- and instead serves the cached bundle from the first request,
	// marked degraded.
	req = httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w = httptest.NewRecorder()
	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []byte("mock-bundle"), w.Body.Bytes())
	assert.NotEmpty(t, w.Header().Get("Warning"), "a cache-served response must be marked degraded")
	assert.Equal(t, circuitbreaker.StateOpen, cb.State())
}

// TestCABundleHandler_ServesFreshCache_NotDegraded_WhenBreakerOpen verifies
// that a cache entry still within its TTL is served as a normal (not
// degraded) response even while the breaker is open: it is still valid data,
// not a fallback.
func TestCABundleHandler_ServesFreshCache_NotDegraded_WhenBreakerOpen(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	cb := resilientTestBreaker("ca-bundle-storage-fresh")
	enableResilience(service, cb) // default degradationCacheTTL: one minute

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()
	service.CABundleHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	cb.Trip()
	require.Equal(t, circuitbreaker.StateOpen, cb.State())

	req = httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w = httptest.NewRecorder()
	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, []byte("mock-bundle"), w.Body.Bytes())
	assert.Empty(t, w.Header().Get("Warning"), "a still-fresh cached response is not degraded")
}

// TestCABundleHandler_NoCacheAndBreakerOpen_Fails verifies that an open
// breaker with nothing cached yet still fails the request -- degradation has
// nothing to fall back to, so it must not fabricate a response.
func TestCABundleHandler_NoCacheAndBreakerOpen_Fails(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	cb := resilientTestBreaker("ca-bundle-storage-empty")
	enableResilience(service, cb)
	cb.Trip()
	require.Equal(t, circuitbreaker.StateOpen, cb.State())

	req := httptest.NewRequest(http.MethodGet, "/acme/ca-bundle", nil)
	w := httptest.NewRecorder()
	service.CABundleHandler(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestDirectoryHandler_DegradesToCache_WhenStorageBreakerOpen verifies that
// DirectoryHandler serves its last computed response from cache while the
// storage breaker is open, even though building the directory itself cannot
// fail -- the point is consistent behavior with CABundleHandler during an
// incident, not recovering from a directory-specific failure.
func TestDirectoryHandler_DegradesToCache_WhenStorageBreakerOpen(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	cb := resilientTestBreaker("directory-storage")
	enableResilience(service, cb)

	// First request computes fresh and populates the cache.
	req := httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
	w := httptest.NewRecorder()
	service.DirectoryHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)
	require.Empty(t, w.Header().Get("Warning"))

	var fresh map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &fresh))

	// Trip the breaker directly: DirectoryHandler has no fallible call of its
	// own to trip it through, so the test drives the state the same way an
	// incident on the real dependency (CABundleHandler's storage access)
	// would.
	cb.Trip()
	require.Equal(t, circuitbreaker.StateOpen, cb.State())

	req = httptest.NewRequest(http.MethodGet, "/acme/directory", nil)
	w = httptest.NewRecorder()
	service.DirectoryHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.NotEmpty(t, w.Header().Get("Warning"), "a cache-served response must be marked degraded")

	var degraded map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &degraded))
	assert.Equal(t, fresh, degraded, "the degraded response must be exactly the cached one")
}

// TestHealthHandler_NoBreakersConfigured verifies the default, opt-out
// behavior: a RestService built without Params.Breakers reports healthy with
// no breakers listed.
func TestHealthHandler_NoBreakersConfigured(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	req := httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w := httptest.NewRecorder()
	service.HealthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var status HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	assert.True(t, status.Healthy)
	assert.Empty(t, status.Breakers)
	assert.False(t, status.Degradation.Active)
}

// TestHealthHandler_ReportsOpenBreakerAndDegradation verifies that
// HealthHandler surfaces a breaker's open state, its counters, and marks the
// server unhealthy (503) and degraded once the storage breaker trips.
func TestHealthHandler_ReportsOpenBreakerAndDegradation(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	manager := circuitbreaker.NewManager()
	cb := resilientTestBreaker("storage")
	manager.Register(cb)
	service.breakers = manager
	enableResilience(service, cb)

	// Healthy before anything trips.
	req := httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w := httptest.NewRecorder()
	service.HealthHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var healthy HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &healthy))
	require.True(t, healthy.Healthy)
	require.False(t, healthy.Degradation.Active)
	require.Equal(t, "closed", healthy.Breakers["storage"].State)

	// Trip the breaker and check again.
	cb.Trip()

	req = httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w = httptest.NewRecorder()
	service.HealthHandler(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var unhealthy HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &unhealthy))
	assert.False(t, unhealthy.Healthy)
	assert.True(t, unhealthy.Degradation.Active)
	require.Contains(t, unhealthy.Breakers, "storage")
	assert.Equal(t, "open", unhealthy.Breakers["storage"].State)
}

// TestHealthHandler_ReportsTargetGroupsWithoutAffectingHealthy verifies that
// HealthHandler reports a bounded per-target breaker group summary in
// TargetGroups, and that an open target breaker does NOT flip Healthy or
// the response status the way an open named breaker (e.g. "storage") does
// -- one account's failing validation target is expected, isolated behavior
// (go-xkms#1189/#1190), not evidence the server itself is degraded.
func TestHealthHandler_ReportsTargetGroupsWithoutAffectingHealthy(t *testing.T) {
	service, _, cleanup := setupTestService(t)
	defer cleanup()

	manager := circuitbreaker.NewManager()
	service.breakers = manager

	cfg := circuitbreaker.TargetConfig{
		Group: "http01",
		NewConfig: func(name string) *circuitbreaker.Config {
			return &circuitbreaker.Config{Name: name, MaxFailures: 1, ResetTimeout: time.Hour}
		},
		Capacity: 10,
	}
	manager.RegisterTargetGroup(cfg)
	manager.TargetBreaker(cfg, "bad.example.com").Trip()
	manager.TargetBreaker(cfg, "good.example.com")

	req := httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w := httptest.NewRecorder()
	service.HealthHandler(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "an open target-group breaker must not make the server report unhealthy")

	var status HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	assert.True(t, status.Healthy)
	require.Contains(t, status.TargetGroups, "http01")
	group := status.TargetGroups["http01"]
	assert.Equal(t, 10, group.Capacity)
	assert.Equal(t, 2, group.Tracked)
	assert.Equal(t, 1, group.Open)
	assert.Equal(t, 1, group.Closed)
	assert.Contains(t, group.TopOpen, "bad.example.com")
}

// TestHealthHandler_ReportsDatastoreHealthThroughSDK verifies that
// HealthHandler reports the go-qrdb SDK readiness checks on Params.Health:
// the datastore check on a real in-process node reports healthy (200), and
// once the datastore closes the same check reports unhealthy (503).
func TestHealthHandler_ReportsDatastoreHealthThroughSDK(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}
	ds, err := datastore.Open(context.Background(), cfg, slog.New(slog.NewTextHandler(io.Discard, nil)))
	require.NoError(t, err)

	health := qrdbsdk.NewHealthChecker()
	health.RegisterCheck(datastore.HealthCheckName, ds.HealthCheck)

	service, _, cleanup := setupTestService(t)
	defer cleanup()
	service.health = health

	req := httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w := httptest.NewRecorder()
	service.HealthHandler(w, req)
	require.Equal(t, http.StatusOK, w.Code)

	var healthy HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &healthy))
	assert.True(t, healthy.Healthy)
	require.Len(t, healthy.Checks, 1)
	assert.Equal(t, datastore.HealthCheckName, healthy.Checks[0].Name)
	assert.Equal(t, qrdbsdk.HealthCheckStatusHealthy, healthy.Checks[0].Status)

	require.NoError(t, ds.Close())

	req = httptest.NewRequest(http.MethodGet, "/acme/health", nil)
	w = httptest.NewRecorder()
	service.HealthHandler(w, req)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var unhealthy HealthStatus
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &unhealthy))
	assert.False(t, unhealthy.Healthy)
	require.Len(t, unhealthy.Checks, 1)
	assert.Equal(t, qrdbsdk.HealthCheckStatusUnhealthy, unhealthy.Checks[0].Status)
}
