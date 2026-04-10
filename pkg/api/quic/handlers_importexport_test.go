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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHandleEncrypt(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/encrypt?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("hello")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST with invalid JSON body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/encrypt?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent key", func(t *testing.T) {
		body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("hello")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/encrypt?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})
}

func TestHandleDecrypt(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/decrypt?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON body", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("data")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/decrypt?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST without backend searches backends", func(t *testing.T) {
		body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("data")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/decrypt", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})
}

func TestHandleGetImportParameters(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed for per-key endpoint", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/import-parameters?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with nonexistent backend per-key endpoint", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import-parameters?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST with invalid backend per-key endpoint", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import-parameters?backend=invalid-type", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// invalid-type doesn't parse to a known StoreType
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST global endpoint missing backend", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{KeyID: "k", KeyType: "rsa", Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint missing key_id", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Backend: "software", KeyType: "rsa", Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint missing key_type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Backend: "software", KeyID: "k", Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint missing algorithm", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Backend: "software", KeyID: "k", KeyType: "rsa"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "nonexistent",
			KeyID:     "k",
			KeyType:   "rsa",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST global endpoint valid request for RSA key", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "test-key",
			KeyType:   "rsa",
			Algorithm: "RSA_OAEP_SHA256",
			KeySize:   2048,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// Software backend doesn't support import/export
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint ECDSA key type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "test-key",
			KeyType:   "ecdsa",
			Algorithm: "RSA_OAEP_SHA256",
			Curve:     "P-256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint Ed25519 key type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "test-key",
			KeyType:   "ed25519",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint AES key type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:    "software",
			KeyID:      "test-key",
			KeyType:    "aes",
			Algorithm:  "RSA_OAEP_SHA256",
			AESKeySize: 256,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST global endpoint invalid ECDSA curve", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "test-key",
			KeyType:   "ecdsa",
			Algorithm: "RSA_OAEP_SHA256",
			Curve:     "invalid-curve",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleWrapKey(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/wrap?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(WrapKeyRequest{KeyMaterial: []byte("key")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST with invalid PEM", func(t *testing.T) {
		body, _ := json.Marshal(WrapKeyRequest{
			KeyMaterial:        []byte("key"),
			WrappingPublicKeyPEM: "not-a-pem",
			Algorithm:          "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// Software doesn't support import/export, so we get 400
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleUnwrapKey(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/unwrap?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST missing wrapped_key", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:           "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST missing wrapping_public_key_pem", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey: []byte("data"),
			Algorithm:  "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST missing algorithm", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("data"),
			WrappingPublicKeyPEM: pubKeyPEM,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST with invalid PEM", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("data"),
			WrappingPublicKeyPEM: "not-a-pem",
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// Software doesn't support import/export
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleImportKey(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/import?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(ImportKeyRequest{WrappedKey: []byte("key")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST software backend doesnt support import", func(t *testing.T) {
		body, _ := json.Marshal(ImportKeyRequest{WrappedKey: []byte("key"), Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleExportKey(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/test-key/export?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("POST with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=software", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with nonexistent backend", func(t *testing.T) {
		body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/export?backend=nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("POST nonexistent key", func(t *testing.T) {
		body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/export?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})
}

func TestHandleTLSCertificate(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET nonexistent cert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/nonexistent-cert", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("GET with invalid backend", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/my-cert?backend=invalid-backend-type", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("GET empty cert ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/tls/", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/tls/my-cert", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleKeyOperationsUnknown(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("unknown operation returns 404", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unknown-op", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("key operations with empty key ID", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		// empty key ID after trim goes to handleKeys (list)
		assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	})

	t.Run("key operations no-op DELETE", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/nonexistent-key", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusBadRequest, http.StatusNotFound}, w.Code)
	})

	t.Run("key operations PATCH not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPatch, "/api/v1/keys/test-key", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}

func TestHandleCopyKeyMissingFields(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	missingFieldTests := []struct {
		name string
		req  CopyKeyRequest
	}{
		{"missing source_key_id", CopyKeyRequest{SourceBackend: "s", DestBackend: "d", DestKeyID: "k", Algorithm: "a"}},
		{"missing dest_backend", CopyKeyRequest{SourceBackend: "s", SourceKeyID: "k", DestKeyID: "k", Algorithm: "a"}},
		{"missing dest_key_id", CopyKeyRequest{SourceBackend: "s", SourceKeyID: "k", DestBackend: "d", Algorithm: "a"}},
		{"missing algorithm", CopyKeyRequest{SourceBackend: "s", SourceKeyID: "k", DestBackend: "d", DestKeyID: "k"}},
	}

	for _, tt := range missingFieldTests {
		t.Run(tt.name, func(t *testing.T) {
			body, _ := json.Marshal(tt.req)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

func TestHandleAsymmetricEncryptViaRoute(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Generate an RSA key
	genBody := GenerateKeyRequest{
		KeyID:     "asym-enc-key",
		Backend:   "software",
		KeyType:   "rsa",
		KeySize:   2048,
		Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	_ = mockKS

	t.Run("POST encrypts data", func(t *testing.T) {
		body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello world")})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/asym-enc-key/asymmetric-encrypt?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("GET method not allowed", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/asym-enc-key/asymmetric-encrypt?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
	})
}
