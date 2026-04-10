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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createImportExportTestServer creates a server with MockKeyStoreWithImportExport
func createImportExportTestServer(t *testing.T) (*Server, *MockKeyStoreWithImportExport) {
	t.Helper()
	xkms.Reset()

	mockKS := NewMockKeyStoreWithImportExport()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": mockKS,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	cfg := &Config{
		Addr: "localhost:8444",
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)
	return server, mockKS
}

func TestHandleWrapKeyWithImportExportBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	t.Run("POST wraps key successfully", func(t *testing.T) {
		body, _ := json.Marshal(WrapKeyRequest{
			KeyMaterial:          []byte("my-secret-key"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST with invalid PEM", func(t *testing.T) {
		body, _ := json.Marshal(WrapKeyRequest{
			KeyMaterial:          []byte("key"),
			WrappingPublicKeyPEM: "not-a-pem",
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with malformed public key", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")})
		body, _ := json.Marshal(WrapKeyRequest{
			KeyMaterial:          []byte("key"),
			WrappingPublicKeyPEM: string(invalidPEM),
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/wrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleUnwrapKeyWithImportExportBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubKeyBytes, _ := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	t.Run("POST unwraps key successfully", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-data"),
			WrappingPublicKeyPEM: pubKeyPEM,
			Algorithm:            "RSA_OAEP_SHA256",
			ImportToken:          []byte("token"),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST with invalid PEM unwrap", func(t *testing.T) {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("data"),
			WrappingPublicKeyPEM: "not-pem",
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("POST with malformed public key", func(t *testing.T) {
		invalidPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("invalid")})
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("data"),
			WrappingPublicKeyPEM: string(invalidPEM),
			Algorithm:            "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestHandleImportKeyWithImportExportBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	t.Run("POST imports key successfully", func(t *testing.T) {
		body, _ := json.Marshal(ImportKeyRequest{
			WrappedKey:  []byte("wrapped-key"),
			Algorithm:   "RSA_OAEP_SHA256",
			ImportToken: []byte("token"),
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleExportKeyWithImportExportBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	// Generate a key first
	// Generate via HTTP handler
	genBody := GenerateKeyRequest{KeyID: "export-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa"}
	genBodyJSON, _ := json.Marshal(genBody)
	genReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(genBodyJSON))
	genW := httptest.NewRecorder()
	server.handler.ServeHTTP(genW, genReq)
	require.Equal(t, http.StatusCreated, genW.Code)

	t.Run("POST exports key", func(t *testing.T) {
		body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/export-key/export?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST export nonexistent key", func(t *testing.T) {
		body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent/export?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandleGetImportParametersWithIEBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	t.Run("POST per-key import parameters", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP_SHA256"})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/import-parameters?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)

		var resp GetImportParametersResponse
		err := json.NewDecoder(w.Body).Decode(&resp)
		require.NoError(t, err)
		assert.NotEmpty(t, resp.WrappingPublicKeyPEM)
		assert.NotEmpty(t, resp.Algorithm)
	})

	t.Run("POST global import-params with RSA", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-rsa",
			KeyType:   "rsa",
			Algorithm: "RSA_OAEP_SHA256",
			KeySize:   2048,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with ECDSA", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-ec",
			KeyType:   "ecdsa",
			Algorithm: "RSA_OAEP_SHA256",
			Curve:     "P-256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with Ed25519", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-ed",
			KeyType:   "ed25519",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with AES 128", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:    "software",
			KeyID:      "import-aes128",
			KeyType:    "aes",
			Algorithm:  "RSA_OAEP_SHA256",
			AESKeySize: 128,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with AES 192", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:    "software",
			KeyID:      "import-aes192",
			KeyType:    "symmetric",
			Algorithm:  "RSA_OAEP_SHA256",
			AESKeySize: 192,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with signing type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-signing",
			KeyType:   "signing",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with encryption type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-encryption",
			KeyType:   "encryption",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST global import-params with unknown type", func(t *testing.T) {
		body, _ := json.Marshal(GetImportParametersRequest{
			Backend:   "software",
			KeyID:     "import-other",
			KeyType:   "unknown",
			Algorithm: "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleCopyKeyWithIEBackend(t *testing.T) {
	server, _ := createImportExportTestServer(t)
	defer xkms.Reset()

	// Generate a source key
	// Generate source key via HTTP handler
	genBody := GenerateKeyRequest{KeyID: "source-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa"}
	genBodyJSON, _ := json.Marshal(genBody)
	genReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(genBodyJSON))
	genW := httptest.NewRecorder()
	server.handler.ServeHTTP(genW, genReq)
	require.Equal(t, http.StatusCreated, genW.Code)

	t.Run("POST copies key successfully", func(t *testing.T) {
		body, _ := json.Marshal(CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "source-key",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("POST nonexistent source key", func(t *testing.T) {
		body, _ := json.Marshal(CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   "nonexistent",
			DestBackend:   "software",
			DestKeyID:     "dest-key",
			Algorithm:     "RSA_OAEP_SHA256",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandleEncryptDecryptRSA(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Generate an RSA key
	genBody := GenerateKeyRequest{
		KeyID: "enc-dec-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	_ = mockKS

	t.Run("asymmetric encrypt then decrypt", func(t *testing.T) {
		// Encrypt
		encBody, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello")})
		encReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/enc-dec-key/asymmetric-encrypt?backend=software", bytes.NewReader(encBody))
		encW := httptest.NewRecorder()
		server.handler.ServeHTTP(encW, encReq)
		require.Equal(t, http.StatusOK, encW.Code)

		var encResp EncryptResponse
		err := json.NewDecoder(encW.Body).Decode(&encResp)
		require.NoError(t, err)

		// Decrypt
		decBody, _ := json.Marshal(DecryptRequest{
			Ciphertext: encResp.Ciphertext,
		})
		decReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/enc-dec-key/decrypt?backend=software", bytes.NewReader(decBody))
		decW := httptest.NewRecorder()
		server.handler.ServeHTTP(decW, decReq)
		assert.Equal(t, http.StatusOK, decW.Code)

		var decResp DecryptResponse
		err = json.NewDecoder(decW.Body).Decode(&decResp)
		require.NoError(t, err)
		assert.Equal(t, []byte("hello"), decResp.Plaintext)
	})

	t.Run("asymmetric encrypt with ECDSA key fails", func(t *testing.T) {
		// Generate ECDSA key
		genBody := GenerateKeyRequest{
			KeyID: "ecdsa-enc-key", Backend: "software", KeyType: "ecdsa", Curve: "P-256", Algorithm: "ecdsa",
		}
		body, _ := json.Marshal(genBody)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		require.Equal(t, http.StatusCreated, w.Code)

		encBody, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello")})
		encReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/ecdsa-enc-key/asymmetric-encrypt?backend=software", bytes.NewReader(encBody))
		encW := httptest.NewRecorder()
		server.handler.ServeHTTP(encW, encReq)
		assert.Equal(t, http.StatusBadRequest, encW.Code)
	})
}

func TestHandleCertExtended(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Create a test certificate
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-cert"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	certPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))

	t.Run("save and list certs", func(t *testing.T) {
		body, _ := json.Marshal(CertRequest{
			KeyID:   "test-cert",
			CertPEM: certPEM,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)

		// List certs
		req = httptest.NewRequest(http.MethodGet, "/api/v1/certs", nil)
		w = httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("certExists checks", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/test-cert/exists", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Contains(t, []int{http.StatusOK, http.StatusNotFound}, w.Code)
	})

	t.Run("deleteCert", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/certs/test-cert", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("save cert chain", func(t *testing.T) {
		body, _ := json.Marshal(CertChainRequest{
			
			ChainPEMs: []string{certPEM},
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/chain-cert/chain", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("get cert chain", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/chain-cert/chain", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleSignVerifyExtended(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Generate a key
	genBody := GenerateKeyRequest{
		KeyID: "sign-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	t.Run("sign and verify", func(t *testing.T) {
		data := []byte("data to sign")
		signBody, _ := json.Marshal(SignRequest{
			Data: data,
			Hash: "SHA256",
		})
		signReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sign-key/sign?backend=software", bytes.NewReader(signBody))
		signW := httptest.NewRecorder()
		server.handler.ServeHTTP(signW, signReq)
		require.Equal(t, http.StatusOK, signW.Code)

		var signResp SignResponse
		err := json.NewDecoder(signW.Body).Decode(&signResp)
		require.NoError(t, err)
		assert.NotEmpty(t, signResp.Signature)

		// Verify
		verifyBody, _ := json.Marshal(VerifyRequest{
			Data: data,
			Signature: signResp.Signature.(string),
			Hash: "SHA256",
		})
		verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sign-key/verify?backend=software", bytes.NewReader(verifyBody))
		verifyW := httptest.NewRecorder()
		server.handler.ServeHTTP(verifyW, verifyReq)
		assert.Equal(t, http.StatusOK, verifyW.Code)

		var verifyResp VerifyResponse
		err = json.NewDecoder(verifyW.Body).Decode(&verifyResp)
		require.NoError(t, err)
		assert.True(t, verifyResp.Valid)
	})

	t.Run("verify with invalid signature", func(t *testing.T) {
		verifyBody, _ := json.Marshal(VerifyRequest{
			Data: []byte("data"),
			Signature: []byte("bad-sig"),
			Hash: "SHA256",
		})
		verifyReq := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sign-key/verify?backend=software", bytes.NewReader(verifyBody))
		verifyW := httptest.NewRecorder()
		server.handler.ServeHTTP(verifyW, verifyReq)
		assert.Equal(t, http.StatusOK, verifyW.Code)

		var resp VerifyResponse
		err := json.NewDecoder(verifyW.Body).Decode(&resp)
		require.NoError(t, err)
		assert.False(t, resp.Valid)
	})
}

func TestHandleRotateKeyExtended(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	genBody := GenerateKeyRequest{
		KeyID: "rotate-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	t.Run("rotate key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/rotate-key/rotate?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("rotate nonexistent key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/nonexistent-key/rotate?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})
}

func TestHandleGenerateKeyTypes(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("generate Ed25519 key", func(t *testing.T) {
		body, _ := json.Marshal(GenerateKeyRequest{
			KeyID: "ed25519-key", Backend: "software", KeyType: "ed25519", Algorithm: "ed25519",
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("generate key with invalid backend", func(t *testing.T) {
		body, _ := json.Marshal(GenerateKeyRequest{
			KeyID: "bad-backend-key", Backend: "nonexistent", KeyType: "rsa", KeySize: 2048,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("generate key with invalid JSON", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader([]byte(`{bad`)))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("generate key missing key_id", func(t *testing.T) {
		body, _ := json.Marshal(GenerateKeyRequest{Backend: "software", KeyType: "rsa", KeySize: 2048})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

func TestExtractPublicKey(t *testing.T) {
	t.Run("extracts from RSA private key", func(t *testing.T) {
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		pub, err := extractPublicKey(privKey)
		require.NoError(t, err)
		_, ok := pub.(*rsa.PublicKey)
		assert.True(t, ok)
	})

	t.Run("extracts from ECDSA private key", func(t *testing.T) {
		privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		pub, err := extractPublicKey(privKey)
		require.NoError(t, err)
		_, ok := pub.(*ecdsa.PublicKey)
		assert.True(t, ok)
	})

	t.Run("fails with RSA public key directly", func(t *testing.T) {
		privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		_, err := extractPublicKey(&privKey.PublicKey)
		require.Error(t, err)
	})

	t.Run("fails with unsupported type", func(t *testing.T) {
		_, err := extractPublicKey("not a key")
		require.Error(t, err)
	})
}

func TestHandleGetKey(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Generate a key
	genBody := GenerateKeyRequest{
		KeyID: "get-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)

	t.Run("GET retrieves key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/get-key?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleDeleteKey(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Generate a key
	genBody := GenerateKeyRequest{
		KeyID: "del-key", Backend: "software", KeyType: "rsa", KeySize: 2048, Algorithm: "rsa",
	}
	body, _ := json.Marshal(genBody)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	require.Equal(t, http.StatusCreated, w.Code)
	_ = mockKS

	t.Run("DELETE key", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodDelete, "/api/v1/keys/del-key?backend=software", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

func TestHandleListKeysNoBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	t.Run("GET list keys without backend uses default", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)
		assert.Equal(t, http.StatusOK, w.Code)
	})
}

// Verify interface compliance for MockKeyStoreWithImportExport
func TestMockKeyStoreWithImportExportCompliance(t *testing.T) {
	mock := NewMockKeyStoreWithImportExport()
	assert.NotNil(t, mock.KeyProvider())
}

func TestNewMockImportExportBackendDefaults(t *testing.T) {
	m := NewMockImportExportBackend()

	t.Run("ExportKeyMaterial returns error", func(t *testing.T) {
		_, err := m.ExportKeyMaterial(nil)
		require.Error(t, err)
	})
}
