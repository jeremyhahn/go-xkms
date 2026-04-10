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

package rest

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jeremyhahn/go-xkms/pkg/health"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockHealthChecker implements HealthChecker for testing
type mockHealthChecker struct {
	LiveResult    health.CheckResult
	ReadyResults  []health.CheckResult
	StartupResult health.CheckResult
}

func (m *mockHealthChecker) Live(ctx context.Context) health.CheckResult {
	return m.LiveResult
}

func (m *mockHealthChecker) Ready(ctx context.Context) []health.CheckResult {
	return m.ReadyResults
}

func (m *mockHealthChecker) Startup(ctx context.Context) health.CheckResult {
	return m.StartupResult
}

// Helper to create a new HandlerContext for testing
func newTestHandlerContext() *HandlerContext {
	return NewHandlerContext("1.0.0")
}

// setupTestService initializes the xkms service with a mock backend for testing
func setupTestService(t *testing.T, backendName string) *xkmsmocks.MockKeyStore {
	t.Helper()
	ks := xkmsmocks.NewMockKeyStore()

	// Reset any previous initialization
	xkms.Reset()

	// Initialize with the mock backend
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			backendName: ks,
		},
		DefaultBackend: backendName,
	})
	require.NoError(t, err)

	t.Cleanup(func() {
		xkms.Reset()
	})

	return ks
}

// createRouterWithHandler creates a chi router with URL parameters
func createRouterWithHandler(method, pattern string, handler http.HandlerFunc) *chi.Mux {
	r := chi.NewRouter()
	switch method {
	case http.MethodGet:
		r.Get(pattern, handler)
	case http.MethodPost:
		r.Post(pattern, handler)
	case http.MethodDelete:
		r.Delete(pattern, handler)
	case http.MethodHead:
		r.Head(pattern, handler)
	case http.MethodPut:
		r.Put(pattern, handler)
	}
	return r
}

// generateTestCertificate creates a self-signed certificate for testing
func generateTestCertificate(t *testing.T, key crypto.PrivateKey) *x509.Certificate {
	t.Helper()

	var pubKey crypto.PublicKey
	switch k := key.(type) {
	case *rsa.PrivateKey:
		pubKey = &k.PublicKey
	case *ecdsa.PrivateKey:
		pubKey = &k.PublicKey
	case ed25519.PrivateKey:
		pubKey = k.Public()
	default:
		t.Fatalf("unsupported key type: %T", key)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(24 * time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	require.NoError(t, err)

	return cert
}

// generateTestCertificatePEM creates a self-signed certificate and returns it as PEM
func generateTestCertificatePEM(t *testing.T, key crypto.PrivateKey) string {
	t.Helper()
	cert := generateTestCertificate(t, key)
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})
	return string(certPEM)
}

// TestNewHandlerContext tests HandlerContext creation
func TestNewHandlerContext(t *testing.T) {
	t.Run("creates context with version", func(t *testing.T) {
		ctx := NewHandlerContext("2.0.0")
		assert.NotNil(t, ctx)
		assert.Equal(t, "2.0.0", ctx.Version)
		assert.Nil(t, ctx.HealthChecker)
	})

	t.Run("creates context with empty version", func(t *testing.T) {
		ctx := NewHandlerContext("")
		assert.NotNil(t, ctx)
		assert.Equal(t, "", ctx.Version)
	})
}

// TestHandlerContext_SetHealthChecker tests setting health checker
func TestHandlerContext_SetHealthChecker(t *testing.T) {
	ctx := NewHandlerContext("1.0.0")
	checker := &mockHealthChecker{}

	ctx.SetHealthChecker(checker)

	assert.Equal(t, checker, ctx.HealthChecker)
}

// TestHealthHandler tests the basic health endpoint
func TestHealthHandler(t *testing.T) {
	t.Run("returns healthy status", func(t *testing.T) {
		ctx := NewHandlerContext("1.0.0")
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		ctx.HealthHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp HealthResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "healthy", resp.Status)
		assert.Equal(t, "1.0.0", resp.Version)
	})

	t.Run("returns correct content type", func(t *testing.T) {
		ctx := NewHandlerContext("1.0.0")
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		ctx.HealthHandler(w, req)

		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// TestListBackendsHandler tests listing backends
func TestListBackendsHandler(t *testing.T) {
	t.Run("returns empty list when not initialized", func(t *testing.T) {
		xkms.Reset() // Ensure not initialized
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		ctx.ListBackendsHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListBackendsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Backends)
	})

	t.Run("returns backends when registered", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		ctx.ListBackendsHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListBackendsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Backends, 1)
		assert.Equal(t, "test-backend", resp.Backends[0].ID)
	})
}

// TestGetBackendHandler tests getting a specific backend
func TestGetBackendHandler(t *testing.T) {
	t.Run("returns error for empty backend ID", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns backend info when found", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/backends/{id}", ctx.GetBackendHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BackendInfo
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-backend", resp.ID)
	})
}

// TestGenerateKeyHandler tests key generation
func TestGenerateKeyHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Error, "key_id")
	})

	t.Run("returns error for invalid key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "../../../etc/passwd", "backend": "test", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "test-key", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "test-key", "backend": "INVALID_BACKEND!", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "test-key", "backend": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"key_id": "test-key", "backend": "nonexistent", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("generates RSA key successfully", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "rsa-key", "backend": "test-backend", "key_type": "rsa", "key_size": 2048}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp GenerateKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "rsa-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
		assert.Contains(t, resp.Message, "generated successfully")
	})

	t.Run("generates ECDSA key successfully", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "ecdsa-key", "backend": "test-backend", "key_type": "ecdsa", "curve": "P256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp GenerateKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "ecdsa-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
	})

	t.Run("generates Ed25519 key successfully", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "ed25519-key", "backend": "test-backend", "key_type": "ed25519"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp GenerateKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "ed25519-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
	})

	t.Run("returns error for unknown key type", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		body := `{"key_id": "unknown-key", "backend": "test-backend", "key_type": "unknown"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GenerateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestListKeysHandler tests listing keys
func TestListKeysHandler(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		w := httptest.NewRecorder()

		ctx.ListKeysHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		ctx.ListKeysHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns empty list when no keys", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.ListKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListKeysResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Keys)
	})

	t.Run("returns keys when present", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate a key first
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.ListKeysHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListKeysResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Keys, 1)
	})
}

// TestGetKeyHandler tests getting a specific key
func TestGetKeyHandler(t *testing.T) {
	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/?backend=test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns key info when found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate a key first
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		router := createRouterWithHandler(http.MethodGet, "/api/v1/keys/{id}", ctx.GetKeyHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
	})
}

// TestSignHandler tests signing data
func TestSignHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		// When calling the handler directly without chi router providing params
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/sign?backend=test", strings.NewReader(`{"data": "dGVzdA=="}`))
		w := httptest.NewRecorder()

		// Direct call - key_id from chi.URLParam will be empty
		ctx.SignHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/sign", strings.NewReader(`{"data": "dGVzdA=="}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/sign?backend=test-backend", strings.NewReader("invalid json"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		body := `{"data": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/sign?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("signs data successfully with RSA key", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate a key first
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/sign", ctx.SignHandler)

		body := `{"data": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/sign?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SignResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Signature)
	})
}

// TestVerifyHandler tests signature verification
func TestVerifyHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		// Direct call without chi router - key_id from chi.URLParam will be empty
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/verify?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.VerifyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/verify", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/verify?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("verifies valid signature", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate a key and sign some data
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		data := []byte("test data")
		hasher := crypto.SHA256.New()
		hasher.Write(data)
		digest := hasher.Sum(nil)
		signature, _ := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		// Use proper base64 encoding
		dataB64 := base64.StdEncoding.EncodeToString(data)
		sigB64 := base64.StdEncoding.EncodeToString(signature)

		body := fmt.Sprintf(`{"data": "%s", "signature": "%s", "hash": "sha256"}`, dataB64, sigB64)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/verify?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Valid)
	})

	t.Run("rejects invalid signature", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/verify", ctx.VerifyHandler)

		body := `{"data": "dGVzdA==", "signature": "aW52YWxpZA==", "hash": "sha256"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/verify?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Valid)
		assert.Contains(t, resp.Message, "invalid")
	})
}

// TestDeleteKeyHandler tests key deletion
func TestDeleteKeyHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		// Direct call - key_id from chi.URLParam will be empty
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test?backend=test", nil)
		w := httptest.NewRecorder()

		ctx.DeleteKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/nonexistent?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("deletes key successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		router := createRouterWithHandler(http.MethodDelete, "/api/v1/keys/{id}", ctx.DeleteKeyHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/test-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DeleteKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "deleted successfully")
	})
}

// TestRotateKeyHandler tests key rotation
func TestRotateKeyHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		// Direct call - key_id from chi.URLParam will be empty
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/rotate?backend=test", nil)
		w := httptest.NewRecorder()

		ctx.RotateKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/rotate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/rotate?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("rotates key successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/rotate", ctx.RotateKeyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/rotate?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp RotateKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
		assert.Contains(t, resp.Message, "rotated successfully")
	})
}

// TestEncryptHandler tests symmetric encryption
func TestEncryptHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/encrypt?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.EncryptHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt", strings.NewReader(`{"plaintext": "dGVzdA=="}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt", ctx.EncryptHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/encrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestDecryptHandler tests symmetric decryption
func TestDecryptHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/decrypt?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.DecryptHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt", strings.NewReader(`{"ciphertext": "dGVzdA=="}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/decrypt", ctx.DecryptHandler)

		body := `{"ciphertext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/decrypt?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestEncryptAsymHandler tests asymmetric encryption
func TestEncryptAsymHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		// Direct call - key_id from chi.URLParam will be empty
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/encrypt-asym?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.EncryptAsymHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt-asym", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt-asym?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("encrypts data with RSA key successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("rsa-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp EncryptAsymResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Ciphertext)
	})

	t.Run("returns error for non-RSA key", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate ECDSA key (not supported for asymmetric encryption)
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		ks.SetKey("ecdsa-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ecdsa-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("supports different hash algorithms", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("rsa-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		hashAlgos := []string{"sha256", "sha384", "sha512"}
		for _, hashAlgo := range hashAlgos {
			body := fmt.Sprintf(`{"plaintext": "dGVzdA==", "hash": "%s"}`, hashAlgo)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
			w := httptest.NewRecorder()

			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code, "hash algorithm %s should work", hashAlgo)
		}
	})

	t.Run("returns error for invalid hash algorithm", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("rsa-key", key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/encrypt-asym", ctx.EncryptAsymHandler)

		body := `{"plaintext": "dGVzdA==", "hash": "invalid-hash"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-key/encrypt-asym?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestSaveCertHandler tests saving certificates
func TestSaveCertHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test&backend=test", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"certificate_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?backend=test", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"certificate_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"certificate_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test&backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for invalid certificate PEM", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"certificate_pem": "not-a-valid-pem"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test&backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("saves certificate successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)
		certPEM := generateTestCertificatePEM(t, key)

		body := fmt.Sprintf(`{"certificate_pem": %q}`, certPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=test-key&backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.SaveCertHandler(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "saved successfully")
	})
}

// TestDeleteCertHandler tests deleting certificates
func TestDeleteCertHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test?backend=test", nil)
		w := httptest.NewRecorder()

		ctx.DeleteCertHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test-key?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("deletes certificate successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)
		ks.SetCert("test-key", cert)

		router := createRouterWithHandler(http.MethodDelete, "/api/v1/certs/{id}", ctx.DeleteCertHandler)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
		assert.Contains(t, resp.Message, "deleted successfully")
	})
}

// TestGetCertHandler tests getting certificates
func TestGetCertHandler(t *testing.T) {
	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/?backend=test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns certificate when found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		// Generate a key and certificate
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)
		cert := generateTestCertificate(t, key)
		ks.SetCert("test-key", cert)

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}", ctx.GetCertHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetCertResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-key", resp.KeyID)
		assert.Contains(t, resp.CertificatePEM, "BEGIN CERTIFICATE")
	})
}

// TestListCertsHandler tests listing certificates
func TestListCertsHandler(t *testing.T) {
	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		ctx.ListCertsHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		ctx.ListCertsHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns empty list when no certificates", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.ListCertsHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListCertsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Empty(t, resp.Certificates)
	})

	t.Run("returns certificates when present", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)
		ks.SetCert("test-key", cert)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs?backend=test-backend", nil)
		w := httptest.NewRecorder()

		ctx.ListCertsHandler(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListCertsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Len(t, resp.Certificates, 1)
		assert.Equal(t, "test-key", resp.Certificates[0].KeyID)
	})
}

// TestCertExistsHandler tests certificate existence check
func TestCertExistsHandler(t *testing.T) {
	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodHead, "/api/v1/certs/{id}", ctx.CertExistsHandler)

		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/?backend=test", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodHead, "/api/v1/certs/{id}", ctx.CertExistsHandler)

		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns 404 for non-existent certificate", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodHead, "/api/v1/certs/{id}", ctx.CertExistsHandler)

		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/nonexistent?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns 200 for existing certificate", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)
		ks.SetCert("test-key", cert)

		router := createRouterWithHandler(http.MethodHead, "/api/v1/certs/{id}", ctx.CertExistsHandler)

		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/test-key?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// TestSaveCertChainHandler tests saving certificate chains
func TestSaveCertChainHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test/chain?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.SaveCertChainHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/certs/{id}/chain", ctx.SaveCertChainHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-key/chain", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/certs/{id}/chain", ctx.SaveCertChainHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-key/chain?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/certs/{id}/chain", ctx.SaveCertChainHandler)

		body := `{"cert_chain_pem": []}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-key/chain?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("saves certificate chain successfully", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		ks.SetKey("test-key", key)
		certPEM := generateTestCertificatePEM(t, key)

		router := createRouterWithHandler(http.MethodPost, "/api/v1/certs/{id}/chain", ctx.SaveCertChainHandler)

		body := fmt.Sprintf(`{"cert_chain_pem": [%q]}`, certPEM)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-key/chain?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp SuccessResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})
}

// TestGetCertChainHandler tests getting certificate chains
func TestGetCertChainHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test/chain?backend=test", nil)
		w := httptest.NewRecorder()

		ctx.GetCertChainHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}/chain", ctx.GetCertChainHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-key/chain", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}/chain", ctx.GetCertChainHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-key/chain?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns certificate chain when found", func(t *testing.T) {
		ks := setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()

		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		cert := generateTestCertificate(t, key)
		ks.SetCertChain("test-key", []*x509.Certificate{cert})

		router := createRouterWithHandler(http.MethodGet, "/api/v1/certs/{id}/chain", ctx.GetCertChainHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-key/chain?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetCertChainResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-key", resp.KeyID)
		assert.Len(t, resp.CertChainPEM, 1)
	})
}

// TestGetTLSCertificateHandler tests getting TLS certificates
func TestGetTLSCertificateHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/test?backend=test", nil)
		w := httptest.NewRecorder()

		ctx.GetTLSCertificateHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/test-key", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/test-key?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("returns error for non-existent key", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodGet, "/api/v1/tls/{id}", ctx.GetTLSCertificateHandler)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/nonexistent?backend=test-backend", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestGetImportParametersHandler tests getting import parameters
func TestGetImportParametersHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "INVALID!", "key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "../../../etc/passwd", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "test-key", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "test-key", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"backend": "nonexistent", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.GetImportParametersHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestWrapKeyHandler tests key wrapping
func TestWrapKeyHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_material", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"wrapping_public_key_pem": "test", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing wrapping_public_key_pem", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_material": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_material": "dGVzdA==", "wrapping_public_key_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid wrapping public key PEM", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_material": "dGVzdA==", "wrapping_public_key_pem": "invalid-pem", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.WrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestUnwrapKeyHandler tests key unwrapping
func TestUnwrapKeyHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing wrapped_key", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"wrapping_public_key_pem": "test", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing wrapping_public_key_pem", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"wrapped_key": "dGVzdA==", "wrapping_public_key_pem": "test"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid wrapping public key PEM", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"wrapped_key": "dGVzdA==", "wrapping_public_key_pem": "invalid-pem", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.UnwrapKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestImportKeyHandler tests key importing
func TestImportKeyHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"key_id": "test", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid backend name", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "INVALID!", "key_id": "test", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "../../../etc/passwd", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "test-key", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing wrapped_key", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "test-key", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"backend": "test", "key_id": "test-key", "key_type": "rsa", "wrapped_key": "dGVzdA=="}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"backend": "nonexistent", "key_id": "test-key", "key_type": "rsa", "wrapped_key": "dGVzdA==", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.ImportKeyHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestExportKeyHandler tests key exporting
func TestExportKeyHandler(t *testing.T) {
	t.Run("returns error for missing key_id via URL param", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test/export?backend=test", strings.NewReader(`{}`))
		w := httptest.NewRecorder()

		ctx.ExportKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=test-backend", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=test-backend", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export", ctx.ExportKeyHandler)

		body := `{"algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=nonexistent", strings.NewReader(body))
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestCopyKeyHandler tests key copying between backends
func TestCopyKeyHandler(t *testing.T) {
	t.Run("returns error for invalid JSON", func(t *testing.T) {
		ctx := newTestHandlerContext()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader("invalid"))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing source_backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_key_id": "test", "dest_backend": "dest", "dest_key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing source_key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_backend": "src", "dest_backend": "dest", "dest_key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing dest_backend", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_backend": "src", "source_key_id": "test", "dest_key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing dest_key_id", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_backend": "src", "source_key_id": "test", "dest_backend": "dest", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing key_type", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_backend": "src", "source_key_id": "test", "dest_backend": "dest", "dest_key_id": "test", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for missing algorithm", func(t *testing.T) {
		ctx := newTestHandlerContext()
		body := `{"source_backend": "src", "source_key_id": "test", "dest_backend": "dest", "dest_key_id": "test", "key_type": "rsa"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("returns error for non-existent source backend", func(t *testing.T) {
		setupTestService(t, "test-backend")
		ctx := newTestHandlerContext()
		body := `{"source_backend": "nonexistent", "source_key_id": "test", "dest_backend": "test-backend", "dest_key_id": "test", "key_type": "rsa", "algorithm": "RSA-OAEP"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", strings.NewReader(body))
		w := httptest.NewRecorder()

		ctx.CopyKeyHandler(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestBuildKeyAttributes tests building key attributes from request parameters
func TestBuildKeyAttributes(t *testing.T) {
	t.Run("builds RSA attributes", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "rsa", 4096, "", "", 0)
		assert.Equal(t, "test-key", attrs.CN)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.RSAAttributes)
		assert.Equal(t, 4096, attrs.RSAAttributes.KeySize)
	})

	t.Run("builds RSA attributes with default key size", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "rsa", 0, "", "", 0)
		assert.NotNil(t, attrs.RSAAttributes)
		assert.Equal(t, types.RSAKeySize2048, attrs.RSAAttributes.KeySize)
	})

	t.Run("builds ECDSA attributes", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "ecdsa", 0, "P384", "", 0)
		assert.Equal(t, "test-key", attrs.CN)
		assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
		assert.NotNil(t, attrs.ECCAttributes)
	})

	t.Run("builds ECDSA attributes with default curve", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "ecdsa", 0, "", "", 0)
		assert.NotNil(t, attrs.ECCAttributes)
	})

	t.Run("builds Ed25519 attributes", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "ed25519", 0, "", "", 0)
		assert.Equal(t, x509.Ed25519, attrs.KeyAlgorithm)
	})

	t.Run("builds symmetric attributes", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "symmetric", 0, "", "", 256)
		assert.Equal(t, types.KeyTypeSecret, attrs.KeyType)
		assert.Equal(t, types.SymmetricAES256GCM, attrs.SymmetricAlgorithm)
	})

	t.Run("builds symmetric attributes with different sizes", func(t *testing.T) {
		tests := []struct {
			size     int
			expected types.SymmetricAlgorithm
		}{
			{128, types.SymmetricAES128GCM},
			{192, types.SymmetricAES192GCM},
			{256, types.SymmetricAES256GCM},
			{0, types.SymmetricAES256GCM},   // default
			{512, types.SymmetricAES256GCM}, // invalid, defaults to 256
		}

		for _, tc := range tests {
			attrs := buildKeyAttributes("test-key", "symmetric", 0, "", "", tc.size)
			assert.Equal(t, tc.expected, attrs.SymmetricAlgorithm, "size=%d", tc.size)
		}
	})

	t.Run("sets hash algorithm", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "rsa", 0, "", "sha384", 0)
		assert.Equal(t, crypto.SHA384, attrs.Hash)
	})

	t.Run("uses default hash for empty string", func(t *testing.T) {
		attrs := buildKeyAttributes("test-key", "rsa", 0, "", "", 0)
		assert.Equal(t, crypto.SHA256, attrs.Hash)
	})
}

// TestGetPublicKey tests extracting public keys from private keys
func TestGetPublicKey(t *testing.T) {
	t.Run("extracts RSA public key", func(t *testing.T) {
		key, _ := rsa.GenerateKey(rand.Reader, 2048)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
		_, ok := pubKey.(*rsa.PublicKey)
		assert.True(t, ok)
	})

	t.Run("extracts ECDSA public key", func(t *testing.T) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
		_, ok := pubKey.(*ecdsa.PublicKey)
		assert.True(t, ok)
	})

	t.Run("extracts Ed25519 public key", func(t *testing.T) {
		_, key, _ := ed25519.GenerateKey(rand.Reader)
		pubKey := getPublicKey(key)
		assert.NotNil(t, pubKey)
		_, ok := pubKey.(ed25519.PublicKey)
		assert.True(t, ok)
	})

	t.Run("returns nil for unsupported key type", func(t *testing.T) {
		pubKey := getPublicKey("not a key")
		assert.Nil(t, pubKey)
	})
}

// TestGetAlgorithmString tests algorithm string generation
func TestGetAlgorithmString(t *testing.T) {
	t.Run("returns symmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			SymmetricAlgorithm: types.SymmetricAES256GCM,
		}
		result := getAlgorithmString(attrs)
		assert.Equal(t, string(types.SymmetricAES256GCM), result)
	})

	t.Run("returns asymmetric algorithm", func(t *testing.T) {
		attrs := &types.KeyAttributes{
			KeyAlgorithm: x509.RSA,
		}
		result := getAlgorithmString(attrs)
		assert.Equal(t, "RSA", result)
	})

	t.Run("returns empty string for unknown", func(t *testing.T) {
		attrs := &types.KeyAttributes{}
		result := getAlgorithmString(attrs)
		assert.Equal(t, "", result)
	})
}
