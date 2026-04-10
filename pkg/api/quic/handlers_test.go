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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	backendmocks "github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// testAuthenticator is a simple authenticator for testing
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

// Helper to create a test server with initialized xkms
func createTestServer(t *testing.T) (*Server, *xkmsmocks.MockKeyStore) {
	t.Helper()

	// Reset xkms state
	xkms.Reset()

	mockKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	return server, mockKS
}

// MockImportExportBackend extends MockBackend with import/export capabilities
type MockImportExportBackend struct {
	*backendmocks.MockBackend
	getImportParamsFunc func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.ImportParameters, error)
	wrapKeyFunc         func([]byte, *backend.ImportParameters) (*backend.WrappedKeyMaterial, error)
	unwrapKeyFunc       func(*backend.WrappedKeyMaterial, *backend.ImportParameters) ([]byte, error)
	importKeyFunc       func(*types.KeyAttributes, *backend.WrappedKeyMaterial) error
	exportKeyFunc       func(*types.KeyAttributes, backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error)
}

// NewMockImportExportBackend creates a mock backend that implements ImportExportBackend
func NewMockImportExportBackend() *MockImportExportBackend {
	return &MockImportExportBackend{
		MockBackend: backendmocks.NewMockBackend(),
	}
}

func (m *MockImportExportBackend) GetImportParameters(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	if m.getImportParamsFunc != nil {
		return m.getImportParamsFunc(attrs, alg)
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	expiresAt := time.Now().Add(24 * time.Hour)
	return &backend.ImportParameters{
		WrappingPublicKey: &privKey.PublicKey,
		ImportToken:       []byte("test-import-token"),
		Algorithm:         alg,
		ExpiresAt:         &expiresAt,
		KeySpec:           "RSA_2048",
	}, nil
}

func (m *MockImportExportBackend) WrapKey(keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if m.wrapKeyFunc != nil {
		return m.wrapKeyFunc(keyMaterial, params)
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("wrapped-key-material"),
		Algorithm:   params.Algorithm,
		ImportToken: params.ImportToken,
	}, nil
}

func (m *MockImportExportBackend) UnwrapKey(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
	if m.unwrapKeyFunc != nil {
		return m.unwrapKeyFunc(wrapped, params)
	}
	return []byte("unwrapped-key-material"), nil
}

func (m *MockImportExportBackend) ImportKey(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if m.importKeyFunc != nil {
		return m.importKeyFunc(attrs, wrapped)
	}
	return nil
}

func (m *MockImportExportBackend) ExportKey(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	if m.exportKeyFunc != nil {
		return m.exportKeyFunc(attrs, alg)
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("exported-wrapped-key"),
		Algorithm:   alg,
		ImportToken: []byte("export-token"),
	}, nil
}

// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
func (m *MockImportExportBackend) ExportKeyMaterial(attrs *types.KeyAttributes) ([]byte, error) {
	return nil, fmt.Errorf("not supported for asymmetric keys")
}

// Verify interface compliance
var _ backend.ImportExportBackend = (*MockImportExportBackend)(nil)

// MockKeyStoreWithImportExport wraps MockKeyStore to use a backend with import/export support
type MockKeyStoreWithImportExport struct {
	*xkmsmocks.MockKeyStore
	importExportBackend *MockImportExportBackend
}

func NewMockKeyStoreWithImportExport() *MockKeyStoreWithImportExport {
	mock := &MockKeyStoreWithImportExport{
		MockKeyStore:        xkmsmocks.NewMockKeyStore(),
		importExportBackend: NewMockImportExportBackend(),
	}
	return mock
}

func (m *MockKeyStoreWithImportExport) KeyProvider() types.KeyProvider {
	return m.importExportBackend
}

// Tests for handleHealth
func TestHandleHealth(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET returns healthy status", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp HealthResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "healthy", resp.Status)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/health", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for handleListBackends
func TestHandleListBackends(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET returns backends list", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListBackendsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Backends)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for handleBackendOperations
func TestHandleBackendOperations(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET specific backend returns info", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp BackendInfo
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "software", resp.ID)
	})

	t.Run("GET non-existent backend returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/backends/software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for handleKeys (list and generate)
func TestHandleKeys(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET lists keys", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListKeysResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotNil(t, resp.Keys)
	})

	t.Run("POST generates RSA key", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:     "test-rsa-key",
			Backend:   "software",
			KeyType:   "rsa",
			KeySize:   2048,
			Algorithm: "rsa",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp KeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-rsa-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)

		// Verify key was generated
		assert.Contains(t, mockKS.GenerateRSACalls, "test-rsa-key")
	})

	t.Run("POST generates ECDSA key", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:     "test-ecdsa-key",
			Backend:   "software",
			KeyType:   "ecdsa",
			Curve:     "P-256",
			Algorithm: "ecdsa",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp KeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-ecdsa-key", resp.KeyID)

		// Verify key was generated
		assert.Contains(t, mockKS.GenerateECDSACalls, "test-ecdsa-key")
	})

	t.Run("POST generates Ed25519 key", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:     "test-ed25519-key",
			Backend:   "software",
			KeyType:   "ed25519",
			Algorithm: "ed25519",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp KeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-ed25519-key", resp.KeyID)
	})

	t.Run("POST with missing key_id returns error", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			Backend: "software",
			KeyType: "rsa",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "key_id is required")
	})

	t.Run("POST with missing backend returns error", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:   "test-key",
			KeyType: "rsa",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)

		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "backend is required")
	})

	t.Run("POST with invalid JSON returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", strings.NewReader("{invalid json}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with unsupported algorithm returns error", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:     "test-key",
			Backend:   "software",
			Algorithm: "unknown",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("DELETE method not allowed on /keys endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for key operations
func TestHandleKeyOperations(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate a key for testing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("test-key", privKey)

	t.Run("GET retrieves key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp KeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-key", resp.KeyID)
		assert.NotEmpty(t, resp.PublicKeyPEM)
	})

	t.Run("GET non-existent key returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/nonexistent?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("DELETE removes key", func(t *testing.T) {
		// Set up a key to delete
		delKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		mockKS.SetKey("delete-me", delKey)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/delete-me?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DeleteResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Success)
	})

	t.Run("DELETE non-existent key returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/nonexistent?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Tests for signing
func TestHandleSign(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate a key for signing
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("signing-key", privKey)

	// Update the mock to return proper key attributes
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "signing-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
			},
		}, nil
	}

	t.Run("POST signs data", func(t *testing.T) {
		reqBody := SignRequest{
			Data: []byte("test data to sign"),
			Hash: "SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/signing-key/sign?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SignResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotNil(t, resp.Signature)
	})

	t.Run("POST with invalid hash returns error", func(t *testing.T) {
		reqBody := SignRequest{
			Data: []byte("test data to sign"),
			Hash: "INVALID",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/signing-key/sign?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with non-existent key returns 404", func(t *testing.T) {
		reqBody := SignRequest{
			Data: []byte("test data"),
			Hash: "SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/sign?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/signing-key/sign?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for verification
func TestHandleVerify(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate a key for verification
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("verify-key", privKey)

	// Update the mock to return proper key attributes
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "verify-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
			},
		}, nil
	}

	// Create a valid signature
	message := []byte("test message")
	hash := crypto.SHA256
	hasher := hash.New()
	hasher.Write(message)
	digest := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privKey, hash, digest)
	require.NoError(t, err)

	t.Run("POST verifies valid signature", func(t *testing.T) {
		reqBody := VerifyRequest{
			Data:      message,
			Signature: signature,
			Hash:      "SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/verify-key/verify?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.True(t, resp.Valid)
	})

	t.Run("POST with invalid signature returns valid=false", func(t *testing.T) {
		reqBody := VerifyRequest{
			Data:      message,
			Signature: []byte("invalid signature"),
			Hash:      "SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/verify-key/verify?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Valid)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/verify-key/verify?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for key rotation
func TestHandleRotateKey(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate a key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("rotate-key", privKey)

	// Update the mock to return proper key attributes
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "rotate-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
			},
		}, nil
	}

	t.Run("POST rotates key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-key/rotate?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp KeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "rotate-key", resp.KeyID)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/rotate-key/rotate?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for certificate operations
func TestHandleCerts(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET lists certificates", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ListCertsResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotNil(t, resp.KeyIDs)
	})

	t.Run("POST saves certificate", func(t *testing.T) {
		// Create a self-signed certificate for testing
		privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
		}
		certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
		require.NoError(t, err)

		certPEM := "-----BEGIN CERTIFICATE-----\n" +
			base64.StdEncoding.EncodeToString(certBytes) +
			"\n-----END CERTIFICATE-----"

		reqBody := CertRequest{
			KeyID:   "test-cert",
			CertPEM: certPEM,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("POST with missing key_id returns error", func(t *testing.T) {
		reqBody := CertRequest{
			CertPEM: "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with invalid PEM returns error", func(t *testing.T) {
		reqBody := CertRequest{
			KeyID:   "test-cert",
			CertPEM: "invalid pem",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("DELETE method not allowed on /certs endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Tests for sendJSON and sendError
func TestSendJSONAndError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("sendJSON sets correct content type", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, "application/json", w.Header().Get("Content-Type"))
	})
}

// Tests for unknown operations
func TestHandleKeyOperations_UnknownOperation(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate a key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("test-key", privKey)

	t.Run("unknown operation returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unknown", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Tests for certificate operations
func TestHandleCertOperations(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Create a test certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	mockKS.SetCert("test-cert", cert)

	t.Run("GET retrieves certificate", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CertResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-cert", resp.KeyID)
		assert.Contains(t, resp.CertificatePEM, "CERTIFICATE")
	})

	t.Run("GET non-existent cert returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("DELETE removes certificate", func(t *testing.T) {
		// Create another cert to delete
		mockKS.SetCert("delete-cert", cert)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/delete-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("HEAD checks certificate exists", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/test-cert", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("HEAD returns 404 for non-existent cert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodHead, "/api/v1/certs/nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// Tests for certificate chain operations
func TestHandleCertChainOperations(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Create test certificates
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)
	mockKS.SetCertChain("test-chain", []*x509.Certificate{cert})

	t.Run("GET retrieves certificate chain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-chain/chain", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp CertChainResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "test-chain", resp.KeyID)
		assert.Len(t, resp.ChainPEMs, 1)
	})

	t.Run("POST saves certificate chain", func(t *testing.T) {
		certPEM := "-----BEGIN CERTIFICATE-----\n" +
			base64.StdEncoding.EncodeToString(certBytes) +
			"\n-----END CERTIFICATE-----"

		reqBody := CertChainRequest{
			ChainPEMs: []string{certPEM},
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/new-chain/chain", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("POST with empty chain returns error", func(t *testing.T) {
		reqBody := CertChainRequest{
			ChainPEMs: []string{},
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-chain/chain", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// Test asymmetric encryption
func TestHandleAsymmetricEncrypt(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Pre-generate an RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("rsa-key", privKey)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "rsa-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
			},
		}, nil
	}

	t.Run("POST encrypts data asymmetrically", func(t *testing.T) {
		reqBody := AsymmetricEncryptRequest{
			Plaintext: []byte("test data to encrypt"),
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-key/asymmetric-encrypt?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp EncryptResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.Ciphertext)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/rsa-key/asymmetric-encrypt?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// Test empty key ID in path
func TestHandleKeyOperations_EmptyKeyID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Note: With standard http mux, /api/v1/keys/ without key ID
	// will be handled by handleKeys, not handleKeyOperations
	// Testing the actual behavior here
	t.Run("empty path after keys returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// The handler will try to process this as a key operation
		// with empty key ID, which should return an error
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// Test invalid curve for ECDSA
func TestHandleGenerateKey_InvalidCurve(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("POST with invalid curve returns error", func(t *testing.T) {
		reqBody := GenerateKeyRequest{
			KeyID:     "test-ecdsa-key",
			Backend:   "software",
			KeyType:   "ecdsa",
			Curve:     "invalid-curve",
			Algorithm: "ecdsa",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// Test backend not found
func TestHandleOperations_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("list keys with invalid backend returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=nonexistent", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}
