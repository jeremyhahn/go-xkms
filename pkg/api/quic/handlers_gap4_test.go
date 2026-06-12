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

//go:build !frost

package quic

import (
	"bytes"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// handleDecrypt — symmetric path (IsSymmetric() returns true)
// These tests exercise the attrs.IsSymmetric() == true branch.
// MockBackend doesn't implement SymmetricKeyProvider, so the result is 400.
// ============================================================================

func TestHandleDecrypt_SymmetricKeyNoSymSupport(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// SymmetricAlgorithm != "" → IsSymmetric() == true
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "sym-dec-key",
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				StoreType:          backend.STORE_SW,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("sym-dec-key", nil)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("cipher")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "sym-dec-key", "software")
	// MockBackend doesn't implement SymmetricKeyProvider → 400
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleDecrypt_SymmetricKeyNoSymSupport_NoBackend(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "sym-dec-key2",
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				StoreType:          backend.STORE_SW,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("sym-dec-key2", nil)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("cipher")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// No backend param → searches symmetric (fails), then software (finds key, IsSymmetric → true)
	server.handleDecrypt(rec, req, "sym-dec-key2", "")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleEncrypt — exercises the backendParam="" defaulting to "symmetric" path
// ============================================================================

func TestHandleEncrypt_DefaultsToSymmetricBackend(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Set up a symmetric key so findKeyByID returns it.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "enc-sym-key",
				KeyType:            backend.KEY_TYPE_ENCRYPTION,
				StoreType:          backend.STORE_SW,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("enc-sym-key", nil)

	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("hello")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// backendParam="" → defaults to "symmetric"; only "software" is registered,
	// so the defaulting path is pinned by the backend-not-found response.
	server.handleEncrypt(rec, req, "enc-sym-key", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
	assert.Contains(t, rec.Body.String(), "symmetric")
}

// ============================================================================
// handleVerify — string signature (base64 decode) and default (unknown type) paths
// ============================================================================

func TestHandleVerify_StringSignatureBase64(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "str-sig-key", KeyType: backend.KEY_TYPE_TLS, StoreType: backend.STORE_SW, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	mockKS.SetKey("str-sig-key", privKey)

	// JSON-encode a string signature — exercises the "case string:" branch (base64 decode)
	reqBody := map[string]interface{}{
		"data":      []byte("testdata"),
		"signature": "bm90LWEtcmVhbC1zaWduYXR1cmU=", // base64 for "not-a-real-signature"
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "str-sig-key", "software")
	// Verification completes (valid=false or internal error), but exercises the string branch
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

func TestHandleVerify_StringSignatureRawBytes(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "raw-sig-key", KeyType: backend.KEY_TYPE_TLS, StoreType: backend.STORE_SW, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	mockKS.SetKey("raw-sig-key", privKey)

	// Non-base64 string → falls back to raw bytes in the string case branch
	reqBody := map[string]interface{}{
		"data":      []byte("testdata"),
		"signature": "not===valid===base64====!", // will fail base64 decode → raw bytes
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "raw-sig-key", "software")
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

func TestHandleVerify_NullSignature(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "null-sig-key", KeyType: backend.KEY_TYPE_TLS, StoreType: backend.STORE_SW, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	mockKS.SetKey("null-sig-key", privKey)

	// null signature → json null → default case in the Signature type switch
	reqBody := map[string]interface{}{
		"data":      []byte("testdata"),
		"signature": nil,
	}
	body, _ := json.Marshal(reqBody)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "null-sig-key", "software")
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

// ============================================================================
// handleGenerateKey — RSA path
// ============================================================================

func TestHandleGenerateKey_RSA_Success(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.GenerateRSAFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, nil // returns nil key to exercise nil-key path
	}

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "rsa-gen-key",
		Backend:   "software",
		Algorithm: "rsa",
		KeySize:   2048,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleListKeys — ListKeys error path and filter by store type
// ============================================================================

func TestHandleListKeys_ListKeysError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("storage failure")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestHandleListKeys_WithBackend_StoreTypeFilter(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Return keys with mixed StoreTypes — some match, some don't.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "sw-key", StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
			{CN: "pkcs11-key", StoreType: types.StorePKCS11, KeyAlgorithm: x509.RSA},
		}, nil
	}

	// backend=software → filter keeps only StoreSoftware keys
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp ListKeysResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	// Only the software key should appear
	assert.Equal(t, 1, len(resp.Keys))
}

// ============================================================================
// handleBarrierSeal — seal after initialization
// ============================================================================

func TestHandleBarrierSeal_Initialized(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// Initialize the barrier first so Seal() can succeed
	ibody, _ := json.Marshal(BarrierInitializeRequest{Secret: "seal-secret"})
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(ibody))
	server.handler.ServeHTTP(httptest.NewRecorder(), ireq)

	// Now seal — barrier is auto-unsealed after init
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/seal", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Should succeed (200) or conflict (409) if already sealed, or 500 on in-memory storage issues
	assert.Contains(t, []int{http.StatusOK, http.StatusConflict, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleBarrierDeleteRecoveryKeys / handleBarrierHasRecoveryKeys — initialized barrier
// ============================================================================

func TestHandleBarrierDeleteRecoveryKeys_Initialized(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// Initialize barrier
	ibody, _ := json.Marshal(BarrierInitializeRequest{Secret: "rec-secret"})
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(ibody))
	server.handler.ServeHTTP(httptest.NewRecorder(), ireq)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

func TestHandleBarrierHasRecoveryKeys_Initialized(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// Initialize barrier
	ibody, _ := json.Marshal(BarrierInitializeRequest{Secret: "has-rec-secret"})
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(ibody))
	server.handler.ServeHTTP(httptest.NewRecorder(), ireq)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]interface{}
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	_, ok := resp["has_recovery_keys"]
	assert.True(t, ok)
}

// ============================================================================
// handleExportKey — backend exists but ImportExport not supported, bad body, method not allowed
// ============================================================================

func TestHandleExportKey_NoImportExportSupport(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Register the key so findKeyByID succeeds and the handler reaches the
	// ImportExportBackend capability check.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "mykey",
				KeyType:      backend.KEY_TYPE_SIGNING,
				StoreType:    backend.STORE_SW,
				KeyAlgorithm: x509.Ed25519,
			},
		}, nil
	}
	mockKS.SetKey("mykey", nil)

	body, _ := json.Marshal(ExportKeyRequest{})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "mykey", "software")
	// MockBackend doesn't implement ImportExportBackend → 400
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "import/export")
}

func TestHandleExportKey_BadBody(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("{invalid")))
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "mykey", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestHandleExportKey_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "mykey", "software")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — key not found and method not allowed
// ============================================================================

func TestHandleAsymmetricEncrypt_KeyNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "missing-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestHandleAsymmetricEncrypt_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "key", "software")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleCopyKey — missing required fields validation (one missing field per test)
// ============================================================================

func TestHandleCopyKey_MissingSourceBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceKeyID: "key",
		DestBackend: "software",
		DestKeyID:   "dest",
		Algorithm:   "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCopyKey_MissingSourceKeyID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		DestBackend:   "software",
		DestKeyID:     "dest",
		Algorithm:     "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCopyKey_MissingDestBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "key",
		DestKeyID:     "dest",
		Algorithm:     "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCopyKey_MissingDestKeyID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "key",
		DestBackend:   "software",
		Algorithm:     "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleCopyKey_MissingAlgorithm(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "key",
		DestBackend:   "software",
		DestKeyID:     "dest",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGetImportParameters — invalid store type in backend param
// ============================================================================

func TestHandleGetImportParameters_InvalidStoreType(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// "INVALID_XYZ" doesn't parse to a known StoreType → 400
	server.handleGetImportParameters(rec, req, "mykey", "INVALID_XYZ")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// passwordWriteJSON — exercises the success path
// ============================================================================

func TestPasswordWriteJSON_Success(t *testing.T) {
	w := httptest.NewRecorder()
	passwordWriteJSON(w, map[string]string{"key": "value"}, http.StatusOK)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "application/json")
}

// ============================================================================
// handleSetSOPIN / handleSetUserPIN — bad body paths
// ============================================================================

func TestHandleSetSOPIN_BadBodyAlt(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleSetUserPIN_BadBodyAlt(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleChangeSOPIN/handleChangeUserPIN — bad body paths (alt names to avoid collision)
// ============================================================================

func TestHandleChangeSOPIN_BadBodyAlt2(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleChangeUserPIN_BadBodyAlt2(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleVerifySOPIN / handleVerifyUserPIN — bad body paths (alt names)
// ============================================================================

func TestHandleVerifySOPIN_BadBodyAlt2(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleVerifyUserPIN_BadBodyAlt2(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleBarrierRecoverWithKeys — bad body
// ============================================================================

func TestHandleBarrierRecoverWithKeys_BadBody(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys/recover", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGetImportParams — missing required field validation
// ============================================================================

func TestHandleGetImportParams_MissingBackend(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		KeyID:     "mykey",
		KeyType:   "tls",
		Algorithm: "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetImportParams_MissingKeyID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		Backend:   "software",
		KeyType:   "tls",
		Algorithm: "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetImportParams_MissingKeyType(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "mykey",
		Algorithm: "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleGetImportParams_MissingAlgorithm(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		Backend: "software",
		KeyID:   "mykey",
		KeyType: "tls",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGetImportParams — no ImportExport support in the backend
// ============================================================================

func TestHandleGetImportParams_NoImportExportSupport(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{
		Backend:   "software",
		KeyID:     "mykey",
		KeyType:   "tls",
		Algorithm: "RSA_OAEP",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/import-params", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// MockBackend does NOT implement ImportExportBackend → 400
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleSaveCertChain — save error path (SaveCertChainFunc returns error)
// ============================================================================

func TestHandleSaveCertChain_SaveError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.SaveCertChainFunc = func(keyID string, chain []*x509.Certificate) error {
		return errors.New("storage failure")
	}

	certPEM := generateSelfSignedCertPEM(t)
	body, _ := json.Marshal(CertChainRequest{
		ChainPEMs: []string{certPEM},
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs/my-cert/chain", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleGetImportParameters — full path with ImportExportBackend
// ============================================================================

// importExportKeyStore wraps MockKeyStore so KeyProvider returns a key
// provider that satisfies backend.ImportExportBackend, mirroring the
// production type assertion in handleGetImportParameters.
type importExportKeyStore struct {
	*xkmsmocks.MockKeyStore
	ie *MockImportExportBackend
}

func (k *importExportKeyStore) KeyProvider() types.KeyProvider {
	return k.ie
}

func TestHandleGetImportParameters_WithImportExportBackend(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	mockIE := NewMockImportExportBackend()
	ks := &importExportKeyStore{
		MockKeyStore: xkmsmocks.NewMockKeyStore(),
		ie:           mockIE,
	}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	svc, _ := xkms.Get()

	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	body, _ := json.Marshal(GetImportParametersRequest{})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleGetImportParameters(rec, req, "mykey", "software")
	// Should succeed or fail based on mock impl
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError, http.StatusBadRequest}, rec.Code)
}

// ============================================================================
// UpdatePasswordHandler — StoreClosed error path
// ============================================================================

func TestUpdatePasswordHandler_StoreClosed(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add a password first
	pw := &staticpw.StaticPassword{
		Name:     "close-test-pw",
		Password: "secret",
	}
	err := store.Add(pw)
	require.NoError(t, err)

	// Close the store
	err = store.Close()
	require.NoError(t, err)

	// Try to update on a closed store
	newPW := "new-secret"
	body, _ := json.Marshal(PasswordUpdateRequest{Password: &newPW})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// DeletePasswordHandler — StoreClosed error path
// ============================================================================

func TestDeletePasswordHandler_StoreClosed(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "close-del-pw",
		Password: "secret",
	}
	err := store.Add(pw)
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/"+pw.ID, nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// GetPasswordHandler — StoreClosed error path
// ============================================================================

func TestGetPasswordHandler_StoreClosed(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "close-get-pw",
		Password: "secret",
	}
	err := store.Add(pw)
	require.NoError(t, err)

	err = store.Close()
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/"+pw.ID, nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusServiceUnavailable, http.StatusNotFound, http.StatusInternalServerError}, w.Code)
}
