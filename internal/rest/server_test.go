// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package rest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/adapters/logger"
	"github.com/jeremyhahn/go-keychain/pkg/health"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	keychainmocks "github.com/jeremyhahn/go-keychain/pkg/keychain/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// mockHealthChecker implements HealthChecker for testing
type mockHealthChecker struct{}

func (m *mockHealthChecker) Live(ctx context.Context) health.CheckResult {
	return health.CheckResult{Status: health.StatusHealthy}
}

func (m *mockHealthChecker) Ready(ctx context.Context) []health.CheckResult {
	return []health.CheckResult{{Status: health.StatusHealthy}}
}

func (m *mockHealthChecker) Startup(ctx context.Context) health.CheckResult {
	return health.CheckResult{Status: health.StatusHealthy}
}

// testAuthenticator is a simple authenticator for testing that validates
// requests based on a Bearer token header
type testAuthenticator struct {
	validToken string
}

func (a *testAuthenticator) Name() string {
	return "test"
}

func (a *testAuthenticator) AuthenticateHTTP(r *http.Request) (*auth.Identity, error) {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return nil, fmt.Errorf("no authorization header")
	}
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return nil, fmt.Errorf("invalid authorization header format")
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token != a.validToken {
		return nil, fmt.Errorf("invalid token")
	}
	return &auth.Identity{Subject: "test-user"}, nil
}

func (a *testAuthenticator) AuthenticateGRPC(ctx context.Context, md metadata.MD) (*auth.Identity, error) {
	return nil, fmt.Errorf("not implemented")
}

// Helper to create a test logger
func testLogger() logger.Logger {
	return logger.NewSlogAdapter(&logger.SlogConfig{
		Level: logger.LevelError, // Suppress logs during tests
	})
}

// newMockKeyStore creates a new MockKeyStore for testing (wrapper for convenience)
func newMockKeyStore() *keychainmocks.MockKeyStore {
	return keychainmocks.NewMockKeyStore()
}

// TestNewServer_NilConfig tests that NewServer returns error with nil config
func TestNewServer_NilConfig(t *testing.T) {
	server, err := NewServer(nil)
	assert.Nil(t, server)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "config is required")
}

// TestNewServer_NoBackends tests that NewServer returns error with no backends
func TestNewServer_NoBackends(t *testing.T) {
	cfg := &Config{
		Port:     8443,
		Backends: map[string]keychain.KeyStore{},
	}

	server, err := NewServer(cfg)
	assert.Nil(t, server)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "at least one backend is required")
}

// TestNewServer_Defaults tests that NewServer sets proper defaults
func TestNewServer_Defaults(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Check defaults were applied
	assert.Equal(t, 8443, server.Port())
}

// TestNewServer_CustomPort tests that custom port is used
func TestNewServer_CustomPort(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Port: 9000,
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	assert.Equal(t, 9000, server.Port())
}

// TestNewServer_WithLogger tests server creation with custom logger
func TestNewServer_WithLogger(t *testing.T) {
	ks := newMockKeyStore()
	log := testLogger()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: log,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, log, server.logger)
}

// TestNewServer_WithAuthenticator tests server creation with custom authenticator
func TestNewServer_WithAuthenticator(t *testing.T) {
	ks := newMockKeyStore()
	authenticator := auth.NewNoOpAuthenticator()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Authenticator: authenticator,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)
	assert.Equal(t, authenticator, server.authenticator)
}

// TestNewServer_WithWebAuthn tests server creation with WebAuthn enabled
func TestNewServer_WithWebAuthn(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// Verify WebAuthn handler and stores are set up
	assert.NotNil(t, server.webauthnHandler)
	assert.NotNil(t, server.webauthnStores)
}

// TestNewServer_WithInvalidWebAuthn tests server creation with invalid WebAuthn config
func TestNewServer_WithInvalidWebAuthn(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			// Missing required RPID
			RPDisplayName: "Test App",
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	assert.Nil(t, server)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "webauthn")
}

// TestNewServer_WithTimeouts tests custom timeout configuration
func TestNewServer_WithTimeouts(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	require.NotNil(t, server)

	// The http.Server is private, but we can verify the server was created
	assert.NotNil(t, server.server)
}

// TestServer_SetHealthChecker tests setting the health checker
func TestServer_SetHealthChecker(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	checker := &mockHealthChecker{}
	server.SetHealthChecker(checker)

	assert.Equal(t, checker, server.handlers.HealthChecker)
}

// TestSetupRouter_HealthEndpoints tests that health endpoints are properly configured
func TestSetupRouter_HealthEndpoints(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Create a test request to health endpoint
	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetupRouter_LivenessProbe tests the liveness probe endpoint
func TestSetupRouter_LivenessProbe(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health/live", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetupRouter_ReadinessProbe tests the readiness probe endpoint
func TestSetupRouter_ReadinessProbe(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health/ready", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetupRouter_StartupProbe tests the startup probe endpoint
func TestSetupRouter_StartupProbe(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health/startup", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetupRouter_HealthHead tests HEAD method on health endpoint
func TestSetupRouter_HealthHead(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodHead, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

// TestSetupRouter_WebAuthnRoutes tests that WebAuthn routes are mounted when configured
func TestSetupRouter_WebAuthnRoutes(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	routes := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/webauthn/registration/begin"},
		{http.MethodPost, "/api/v1/webauthn/registration/finish"},
		{http.MethodGet, "/api/v1/webauthn/registration/status"},
		{http.MethodPost, "/api/v1/webauthn/login/begin"},
		{http.MethodPost, "/api/v1/webauthn/login/finish"},
	}

	for _, route := range routes {
		t.Run(fmt.Sprintf("%s_%s", route.method, route.path), func(t *testing.T) {
			var body string
			if route.method == http.MethodPost {
				body = "{}"
			}
			req := httptest.NewRequest(route.method, route.path, strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			server.server.Handler.ServeHTTP(w, req)

			// WebAuthn routes should respond (not 404)
			// They may return 400 for invalid requests, but not 404
			assert.NotEqual(t, http.StatusNotFound, w.Code,
				"Route %s %s should be registered", route.method, route.path)
		})
	}
}

// TestSetupRouter_WebAuthnNotMountedWithoutConfig tests that WebAuthn routes are not mounted without config
func TestSetupRouter_WebAuthnNotMountedWithoutConfig(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// WebAuthn routes should return 404 when not configured
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestSetupRouter_APIRoutes tests that API routes are properly authenticated
func TestSetupRouter_APIRoutes(t *testing.T) {
	ks := newMockKeyStore()

	// Use test authenticator to verify auth middleware is applied
	authenticator := &testAuthenticator{validToken: "valid-token"}

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Authenticator: authenticator,
		Logger:        testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Unauthenticated request fails", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
	})

	t.Run("Authenticated request succeeds", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		req.Header.Set("Authorization", "Bearer valid-token")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestSetupRouter_CORSMiddleware tests that CORS middleware is applied
func TestSetupRouter_CORSMiddleware(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodOptions, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "*", w.Header().Get("Access-Control-Allow-Origin"))
}

// TestSetupRouter_CorrelationMiddleware tests that correlation middleware is applied
func TestSetupRouter_CorrelationMiddleware(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Generates correlation ID if not provided", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		correlationID := w.Header().Get("X-Correlation-ID")
		assert.NotEmpty(t, correlationID)
	})

	t.Run("Uses provided correlation ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("X-Correlation-ID", "test-correlation-id")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		correlationID := w.Header().Get("X-Correlation-ID")
		assert.Equal(t, "test-correlation-id", correlationID)
	})
}

// TestWebAuthnStores_IntegrationWithServer tests WebAuthn stores integration
func TestWebAuthnStores_IntegrationWithServer(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Verify stores are accessible
	stores := server.webauthnStores
	assert.NotNil(t, stores.UserStore())
	assert.NotNil(t, stores.SessionStore())
	assert.NotNil(t, stores.CredentialStore())
}

// TestWebAuthnRoutes_BeginRegistration tests the registration begin endpoint
func TestWebAuthnRoutes_BeginRegistration(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Valid registration request", func(t *testing.T) {
		body := `{"email": "test@example.com", "display_name": "Test User"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		// Should have session ID header
		sessionID := w.Header().Get("X-Session-Id")
		assert.NotEmpty(t, sessionID)

		// Response should contain WebAuthn options
		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Contains(t, response, "publicKey")
	})

	t.Run("Missing email", func(t *testing.T) {
		body := `{"display_name": "Test User"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Invalid JSON", func(t *testing.T) {
		body := `{invalid json}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Wrong method", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/webauthn/registration/begin", nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		// Chi router returns 405 for wrong method
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// TestWebAuthnRoutes_RegistrationStatus tests the registration status endpoint
func TestWebAuthnRoutes_RegistrationStatus(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Check unregistered user", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/webauthn/registration/status?email=unknown@example.com", nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, false, response["registered"])
	})

	t.Run("No user identifier", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/webauthn/registration/status", nil)
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var response map[string]interface{}
		err := json.Unmarshal(w.Body.Bytes(), &response)
		require.NoError(t, err)
		assert.Equal(t, false, response["registered"])
	})
}

// TestWebAuthnRoutes_BeginLogin tests the login begin endpoint
func TestWebAuthnRoutes_BeginLogin(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Discoverable credentials flow", func(t *testing.T) {
		// Empty body for discoverable credentials
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/begin", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		// Should succeed with discoverable credentials options
		assert.Equal(t, http.StatusOK, w.Code)

		sessionID := w.Header().Get("X-Session-Id")
		assert.NotEmpty(t, sessionID)
	})

	t.Run("Unknown user email", func(t *testing.T) {
		body := `{"email": "unknown@example.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/begin", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestWebAuthnRoutes_FinishRegistration tests the registration finish endpoint
func TestWebAuthnRoutes_FinishRegistration(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Missing session ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/finish", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Invalid session ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/finish", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-Id", "invalid-session")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestWebAuthnRoutes_FinishLogin tests the login finish endpoint
func TestWebAuthnRoutes_FinishLogin(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		WebAuthnConfig: &webauthn.Config{
			RPID:          "localhost",
			RPDisplayName: "Test App",
			RPOrigins:     []string{"https://localhost"},
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("Missing session ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("Invalid session ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/login/finish", strings.NewReader("{}"))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Session-Id", "invalid-session")
		w := httptest.NewRecorder()

		server.server.Handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestServer_Version tests that version is properly set
func TestServer_Version(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Version: "2.0.0",
		Logger:  testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "2.0.0", response["version"])
}

// TestServer_DefaultVersion tests that default version is set
func TestServer_DefaultVersion(t *testing.T) {
	ks := newMockKeyStore()

	cfg := &Config{
		Backends: map[string]keychain.KeyStore{
			"test": ks,
		},
		Logger: testLogger(),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/health", nil)
	w := httptest.NewRecorder()

	server.server.Handler.ServeHTTP(w, req)

	var response map[string]interface{}
	err = json.Unmarshal(w.Body.Bytes(), &response)
	require.NoError(t, err)
	assert.Equal(t, "1.0.0", response["version"])
}
