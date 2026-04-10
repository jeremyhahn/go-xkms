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

package quic

import (
	"crypto/tls"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger creates a discard logger for testing
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// setupTestXKMS initializes the xkms service with a mock backend
func setupTestXKMS(t *testing.T) *xkmsmocks.MockKeyStore {
	t.Helper()

	// Reset any existing xkms state
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	return mockKS
}

// cleanupXKMS resets the xkms state after test
func cleanupXKMS() {
	xkms.Reset()
}

func TestNewServer_Success(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "localhost:8444", server.Addr())
	assert.NotNil(t, server.handler)
}

func TestNewServer_DefaultAddr(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:   "",
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, "localhost:8444", server.Addr())
}

func TestNewServer_WithTLSConfig(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"},
	}

	cfg := &Config{
		Addr:      "localhost:8444",
		TLSConfig: tlsCfg,
		Logger:    testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, tlsCfg, server.tlsConfig)
}

func TestNewServer_WithAuthenticator(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	authenticator := auth.NewNoOpAuthenticator()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: authenticator,
		Logger:        testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, authenticator, server.authenticator)
}

func TestNewServer_WithRateLimiter(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	rateLimiter := ratelimit.New(&ratelimit.Config{
		RequestsPerMinute: 6000, // 100 per second
		Burst:             10,
		Enabled:           true,
	})
	defer rateLimiter.Stop()

	cfg := &Config{
		Addr:        "localhost:8444",
		RateLimiter: rateLimiter,
		Logger:      testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, rateLimiter, server.rateLimiter)
}

func TestNewServer_XKMSNotInitialized(t *testing.T) {
	// Make sure xkms is not initialized
	xkms.Reset()

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	assert.Nil(t, server)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "xkms service must be initialized")
}

func TestNewServer_DefaultLogger(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: nil, // Should use default
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.logger)
}

func TestNewServer_DefaultAuthenticator(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: nil, // Should use NoOp
		Logger:        testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.NotNil(t, server.authenticator)
	assert.Equal(t, "noop", server.authenticator.Name())
}

func TestServer_Stop_NotStarted(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Stop without starting should work
	err = server.Stop()
	assert.NoError(t, err)
}

// TestServerMiddleware tests the middleware chain
func TestServerMiddleware_CorrelationID(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	cfg := &Config{
		Addr:   "localhost:8444",
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("generates correlation ID if not provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		correlationID := w.Header().Get("X-Correlation-ID")
		assert.NotEmpty(t, correlationID)
	})

	t.Run("uses provided correlation ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("X-Correlation-ID", "test-correlation-123")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		correlationID := w.Header().Get("X-Correlation-ID")
		assert.Equal(t, "test-correlation-123", correlationID)
	})

	t.Run("uses X-Request-ID as fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("X-Request-ID", "request-456")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		correlationID := w.Header().Get("X-Correlation-ID")
		assert.Equal(t, "request-456", correlationID)
	})
}

func TestServerMiddleware_Authentication(t *testing.T) {
	mockKS := setupTestXKMS(t)
	defer cleanupXKMS()
	_ = mockKS

	// Create a test authenticator that requires valid token
	testAuth := &testAuthenticator{validToken: "valid-token"}

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: testAuth,
		Logger:        testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("health endpoint skips auth", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("unauthenticated request to API fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("authenticated request to API succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("invalid token fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.Header.Set("Authorization", "Bearer invalid-token")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})
}
