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

package quic

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/backend"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	keychainmocks "github.com/jeremyhahn/go-keychain/pkg/keychain/mocks"
	"github.com/jeremyhahn/go-keychain/pkg/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleKeyVersioning tests all key versioning handlers (currently stubs returning Not Implemented)
func TestHandleKeyVersioning(t *testing.T) {
	server, _ := createTestServer(t)
	defer keychain.Reset()

	t.Run("handleListKeyVersions GET returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/versions?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		// Error now contains the full message for SDK client compatibility
		assert.Contains(t, resp.Error, "key versioning is not yet supported")
		assert.Contains(t, resp.Message, "key versioning is not yet supported")
	})

	t.Run("handleListKeyVersions POST method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/versions?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("handleEnableKeyVersion POST returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/versions/enable?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "Not Implemented", resp.Error)
	})

	t.Run("handleEnableKeyVersion GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/versions/enable?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("handleDisableKeyVersion POST returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/versions/disable?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "Not Implemented", resp.Error)
	})

	t.Run("handleDisableKeyVersion GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/versions/disable?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("handleEnableAllKeyVersions POST returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/versions/enable-all?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "Not Implemented", resp.Error)
	})

	t.Run("handleEnableAllKeyVersions GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/versions/enable-all?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("handleDisableAllKeyVersions POST returns not implemented", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/versions/disable-all?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, "Not Implemented", resp.Error)
	})

	t.Run("handleDisableAllKeyVersions GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/versions/disable-all?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

// TestHandleUnwrapKeyWithImportExport tests the unwrap key handler using import/export backend
func TestHandleUnwrapKeyWithImportExport(t *testing.T) {
	server, mockKS := createTestServerWithImportExport(t)
	defer keychain.Reset()

	// Generate a test RSA key for wrapping
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	t.Run("POST unwraps key successfully", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA-OAEP-SHA256",
			ImportToken:          []byte("import-token"),
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp UnwrapKeyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Equal(t, []byte("unwrapped-key-material"), resp.KeyMaterial)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/unwrap?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON returns error", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", strings.NewReader("{invalid}"))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with missing wrapped_key returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "wrapped_key is required")
	})

	t.Run("POST with missing wrapping_public_key_pem returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey: []byte("wrapped-key-data"),
			Algorithm:  "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "wrapping_public_key_pem is required")
	})

	t.Run("POST with missing algorithm returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "algorithm is required")
	})

	t.Run("POST with invalid PEM returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: "not-valid-pem",
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "invalid wrapping public key PEM")
	})

	t.Run("POST with invalid public key DER returns error", func(t *testing.T) {
		invalidPEM := "-----BEGIN PUBLIC KEY-----\naW52YWxpZC1kZXItZGF0YQ==\n-----END PUBLIC KEY-----"
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: invalidPEM,
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to parse public key")
	})

	t.Run("POST with non-existent backend returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=nonexistent", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	// Test unwrap error
	t.Run("POST when unwrap fails returns error", func(t *testing.T) {
		mockKS.importExportBackend.unwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
			return nil, assert.AnError
		}
		defer func() {
			mockKS.importExportBackend.unwrapKeyFunc = nil
		}()

		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to unwrap key")
	})
}

// TestHandleUnwrapKeyNonImportExportBackend tests unwrap with backend that doesn't support import/export
func TestHandleUnwrapKeyNonImportExportBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer keychain.Reset()

	// Generate a test RSA key for wrapping
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&wrappingKey.PublicKey)
	require.NoError(t, err)

	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	}))

	t.Run("POST with non-import-export backend returns error", func(t *testing.T) {
		reqBody := UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-key-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "backend does not support import/export operations")
	})
}

// TestSetupFrostRoutesStubCoverageVersion tests the FROST routes stub
func TestSetupFrostRoutesStubCoverageVersion(t *testing.T) {
	server, _ := createTestServer(t)
	defer keychain.Reset()

	// The setupFrostRoutes stub should be called during NewServer
	// We verify by ensuring the server was created successfully
	assert.NotNil(t, server)

	// Test that FROST endpoints return 404 since they're not implemented
	t.Run("FROST endpoint returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/frost/keygen", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		// FROST routes are not registered, so expect 404
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestHandleDecryptEdgeCasesVersion tests decrypt handler edge cases
func TestHandleDecryptEdgeCasesVersion(t *testing.T) {
	keychain.Reset()
	mockKS := keychainmocks.NewMockKeyStore()

	// Generate a real RSA key
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("rsa-key", rsaKey)

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

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer keychain.Reset()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("decrypt with asymmetric key and invalid ciphertext returns error", func(t *testing.T) {
		reqBody := DecryptRequest{
			Ciphertext: []byte("invalid-ciphertext"),
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rsa-key/decrypt?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to decrypt")
	})
}

// TestHandleVerifyEdgeCasesVersion tests verify handler edge cases
func TestHandleVerifyEdgeCasesVersion(t *testing.T) {
	keychain.Reset()
	mockKS := keychainmocks.NewMockKeyStore()

	// Generate ECDSA key
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mockKS.SetKey("ecdsa-key", ecdsaKey)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "ecdsa-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.ECDSA,
			},
		}, nil
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer keychain.Reset()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("verify with ECDSA and string signature converts and verifies", func(t *testing.T) {
		reqBody := VerifyRequest{
			Data:      []byte("test data"),
			Signature: "base64-encoded-invalid-sig", // string type signature
			Hash:      "SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ecdsa-key/verify?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		var resp VerifyResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Valid)
	})
}

// TestHandleSaveCertChainInvalidPEMVersion tests saving cert chain with invalid PEM
func TestHandleSaveCertChainInvalidPEMVersion(t *testing.T) {
	server, _ := createTestServer(t)
	defer keychain.Reset()

	t.Run("POST with invalid PEM in chain returns error", func(t *testing.T) {
		reqBody := CertChainRequest{
			ChainPEMs: []string{"not-a-valid-pem"},
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-cert/chain", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with invalid cert DER in chain returns error", func(t *testing.T) {
		invalidCertPEM := "-----BEGIN CERTIFICATE-----\naW52YWxpZC1jZXJ0LWRhdGE=\n-----END CERTIFICATE-----"
		reqBody := CertChainRequest{
			ChainPEMs: []string{invalidCertPEM},
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/test-cert/chain", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// TestHandleTLSCertificateKeyErrorVersion tests TLS certificate handler when key retrieval fails
func TestHandleTLSCertificateKeyErrorVersion(t *testing.T) {
	keychain.Reset()
	mockKS := keychainmocks.NewMockKeyStore()

	// Create a valid certificate
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "test-tls-cert",
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(365 * 24 * time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(certBytes)
	require.NoError(t, err)

	mockKS.SetCert("tls-test-cert", cert)
	mockKS.SetKey("tls-test-cert", privKey)

	// Make GetTLSCertificate fail
	mockKS.GetTLSCertificateFunc = func(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
		return tls.Certificate{}, assert.AnError
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer keychain.Reset()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// When GetTLSCertificate fails, the handler returns 404 (not found)
	t.Run("GET TLS certificate when GetTLSCertificate fails returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/tls-test-cert?backend=software", nil)
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

// TestHandleGetImportParametersEdgeCasesVersion tests import parameters handler edge cases
func TestHandleGetImportParametersEdgeCasesVersion(t *testing.T) {
	server, mockKS := createTestServerWithImportExport(t)
	defer keychain.Reset()

	t.Run("POST when GetImportParameters fails", func(t *testing.T) {
		mockKS.importExportBackend.getImportParamsFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
			return nil, assert.AnError
		}
		defer func() {
			mockKS.importExportBackend.getImportParamsFunc = nil
		}()

		reqBody := GetImportParametersRequest{
			Algorithm: "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import-parameters?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

// TestHandleAsymmetricEncryptEdgeCasesVersion tests asymmetric encryption edge cases
func TestHandleAsymmetricEncryptEdgeCasesVersion(t *testing.T) {
	keychain.Reset()
	mockKS := keychainmocks.NewMockKeyStore()

	// Generate ECDSA key (doesn't support RSA-OAEP encryption)
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	mockKS.SetKey("ecdsa-key", ecdsaKey)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "ecdsa-key",
				KeyType:      types.KeyTypeTLS,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.ECDSA,
			},
		}, nil
	}

	err = keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer keychain.Reset()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	t.Run("asymmetric encrypt with non-RSA key fails", func(t *testing.T) {
		reqBody := AsymmetricEncryptRequest{
			Plaintext: []byte("test data"),
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ecdsa-key/asymmetric-encrypt?backend=software", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "RSA")
	})
}

// TestHandleCopyKeyEdgeCasesVersion tests copy key handler edge cases
func TestHandleCopyKeyEdgeCasesVersion(t *testing.T) {
	server, mockKS := createTestServerWithImportExport(t)
	defer keychain.Reset()

	// Need to set up a mock key in the keystore so that the key is found first
	t.Run("POST copy key when export fails", func(t *testing.T) {
		// Set up mock to return a key when listing
		mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
			return []*types.KeyAttributes{
				{
					CN:           "source-key",
					KeyType:      types.KeyTypeTLS,
					StoreType:    types.StoreSoftware,
					KeyAlgorithm: x509.RSA,
				},
			}, nil
		}
		defer func() {
			mockKS.ListKeysFunc = nil
		}()

		// Now make export fail
		mockKS.importExportBackend.exportKeyFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
			return nil, assert.AnError
		}
		defer func() {
			mockKS.importExportBackend.exportKeyFunc = nil
		}()

		reqBody := CopyKeyRequest{
			SourceKeyID:   "source-key",
			DestKeyID:     "target-key",
			SourceBackend: "software",
			DestBackend:   "software",
			Algorithm:     "RSA-OAEP-SHA256",
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "failed to export key")
	})

	t.Run("POST copy key missing algorithm returns 400", func(t *testing.T) {
		reqBody := CopyKeyRequest{
			SourceKeyID:   "source-key",
			DestKeyID:     "target-key",
			SourceBackend: "software",
			DestBackend:   "software",
			// Missing algorithm
		}

		body, _ := json.Marshal(reqBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code)
		var resp ErrorResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.Contains(t, resp.Message, "algorithm is required")
	})
}

// TestServerStopWithoutStartVersion tests server stop when not started
func TestServerStopWithoutStartVersion(t *testing.T) {
	keychain.Reset()
	mockKS := keychainmocks.NewMockKeyStore()

	err := keychain.Initialize(&keychain.ServiceConfig{
		Backends: map[string]keychain.KeyStore{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)
	defer keychain.Reset()

	cfg := &Config{
		Addr:          "localhost:18445",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	// Stop without starting - should handle gracefully
	err = server.Stop()
	assert.NoError(t, err)
}
