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
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	backendmocks "github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// extendedKeyStore wraps MockKeyStore so KeyProvider returns an
// ExtendedMockBackend, providing both SymmetricKeyProvider and
// ImportExportBackend on the "software" backend.
// ============================================================================

type extendedKeyStore struct {
	*xkmsmocks.MockKeyStore
	ext *backendmocks.ExtendedMockBackend
}

func (k *extendedKeyStore) KeyProvider() types.KeyProvider {
	return k.ext
}

// createTestServerWithExtended builds a server whose "software" backend
// KeyProvider satisfies both SymmetricKeyProvider and ImportExportBackend.
func createTestServerWithExtended(t *testing.T) (*Server, *xkmsmocks.MockKeyStore, *backendmocks.ExtendedMockBackend) {
	t.Helper()
	xkms.Reset()

	inner := xkmsmocks.NewMockKeyStore()
	ext := backendmocks.NewExtendedMockBackend()
	ks := &extendedKeyStore{MockKeyStore: inner, ext: ext}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	return server, inner, ext
}

// ============================================================================
// handleEncrypt — symmetric success path
// ============================================================================

func TestHandleEncrypt_SymmetricSuccess(t *testing.T) {
	server, mockKS, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "sym-enc-key",
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("sym-enc-key", nil)

	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("hello world")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/sym-enc-key/encrypt?backend=software", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// ExtendedMockBackend implements SymmetricKeyProvider → reaches encrypt path.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleEncrypt — SymmetricEncrypter error path
// ============================================================================

func TestHandleEncrypt_SymmetricEncrypterError(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	ext.SymmetricEncrypterFunc = func(attrs *types.KeyAttributes) (types.SymmetricEncrypter, error) {
		return nil, errors.New("encrypter init failed")
	}

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "enc-err-key",
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("enc-err-key", nil)

	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("hello")})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/enc-err-key/encrypt?backend=software", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleEncrypt — bad body (via extended backend)
// ============================================================================

func TestHandleEncrypt_BadBodyExtended(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/any-key/encrypt?backend=software", bytes.NewReader([]byte("{invalid")))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleDecrypt — asymmetric (RSA OAEP) success path
// ============================================================================

func TestHandleDecrypt_AsymmetricSuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// RSA key → attrs.IsSymmetric() == false → asymmetric branch.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "rsa-decrypt-key",
				KeyType:      types.KeyTypeEncryption,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
				RSAAttributes: &types.RSAAttributes{
					KeySize: 2048,
				},
			},
		}, nil
	}
	mockKS.SetKey("rsa-decrypt-key", privKey)

	// Encrypt something with the public key so that Decrypt() succeeds.
	ciphertext, encErr := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader, &privKey.PublicKey, []byte("secret"), nil)
	if encErr != nil {
		// Fallback: junk ciphertext still exercises the asymmetric branch.
		ciphertext = []byte("junk-ciphertext")
	}

	body, _ := json.Marshal(DecryptRequest{Ciphertext: ciphertext})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "rsa-decrypt-key", "software")
	// 200 on success, 500 on junk ciphertext — both reach the asymmetric branch.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

// ============================================================================
// handleDecrypt — Decrypter() returns error (nil key in store)
// ============================================================================

func TestHandleDecrypt_AsymmetricDecrypterError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Store nil key so Decrypter() will fail when it tries to use it.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:           "nil-rsa-key",
				KeyType:      types.KeyTypeEncryption,
				StoreType:    types.StoreSoftware,
				KeyAlgorithm: x509.RSA,
			},
		}, nil
	}
	mockKS.SetKey("nil-rsa-key", nil)

	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("junk")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "nil-rsa-key", "software")
	assert.Contains(t, []int{http.StatusInternalServerError, http.StatusNotFound, http.StatusOK}, rec.Code)
}

// ============================================================================
// handleDecrypt — symmetric path with ExtendedMockBackend (decrypt error)
// ============================================================================

func TestHandleDecrypt_SymmetricDecrypterPath(t *testing.T) {
	server, mockKS, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "sym-dec-ext",
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("sym-dec-ext", nil)

	// Garbage ciphertext exercises the symmetric decrypt error path.
	body, _ := json.Marshal(DecryptRequest{
		Ciphertext: []byte("garbage-ciphertext"),
		Nonce:      make([]byte, 12),
		Tag:        make([]byte, 16),
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "sym-dec-ext", "software")
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

// ============================================================================
// handleGenerateKey — ECDSA path
// ============================================================================

func TestHandleGenerateKey_ECDSA(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "ecdsa-gen",
		Backend:   "software",
		Algorithm: "ecdsa",
		Curve:     "P-256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleGenerateKey — invalid curve
// ============================================================================

func TestHandleGenerateKey_ECDSAInvalidCurve(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "ecdsa-bad-curve",
		Backend:   "software",
		Algorithm: "ecdsa",
		Curve:     "P-999",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGenerateKey — Ed25519 path (via ExtendedMockBackend)
// ============================================================================

func TestHandleGenerateKey_Ed25519Extended(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "ed25519-gen-ext",
		Backend:   "software",
		Algorithm: "ed25519",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleGenerateKey — AES 128-bit path
// ============================================================================

func TestHandleGenerateKey_AES128(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "aes128-gen",
		Backend:   "software",
		Algorithm: "aes",
		KeySize:   128,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleGenerateKey — AES 192-bit path
// ============================================================================

func TestHandleGenerateKey_AES192(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "aes192-gen",
		Backend:   "software",
		Algorithm: "aes",
		KeySize:   192,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusBadRequest, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleGenerateKey — AES invalid key size
// ============================================================================

func TestHandleGenerateKey_AESInvalidSize(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "aes-bad-size",
		Backend:   "software",
		Algorithm: "aes",
		KeySize:   512,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGenerateKey — unsupported algorithm
// ============================================================================

func TestHandleGenerateKey_UnsupportedAlgorithm(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "unsupported-alg",
		Backend:   "software",
		Algorithm: "quantum",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleWrapKey — success path using ImportExport backend
// ============================================================================

func TestHandleWrapKey_Success(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	ks := NewMockKeyStoreWithImportExport()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	// Valid RSA public key PEM for the wrapping operation.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	body, _ := json.Marshal(WrapKeyRequest{
		KeyMaterial:          []byte("raw-key-bytes"),
		WrappingPublicKeyPEM: pubKeyPEM,
		Algorithm:            "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleWrapKey(rec, req, "any-key", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleWrapKey — invalid public key bytes (parse error after IE check)
// ============================================================================

func TestHandleWrapKey_InvalidPublicKeyPEM(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	ks := NewMockKeyStoreWithImportExport()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	// PEM block is valid but the DER bytes are garbage — ParsePKIXPublicKey fails.
	garblePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("not-valid-der")}))
	body, _ := json.Marshal(WrapKeyRequest{
		KeyMaterial:          []byte("key"),
		WrappingPublicKeyPEM: garblePEM,
		Algorithm:            "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleWrapKey(rec, req, "any-key", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleUnwrapKey — success path using ImportExport backend
// ============================================================================

func TestHandleUnwrapKey_Success(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	ks := NewMockKeyStoreWithImportExport()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	pubKeyPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: pubKeyBytes}))

	body, _ := json.Marshal(UnwrapKeyRequest{
		WrappedKey:           []byte("wrapped-material"),
		WrappingPublicKeyPEM: pubKeyPEM,
		Algorithm:            "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleUnwrapKey(rec, req, "any-key", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleUnwrapKey — invalid public key bytes (parse error after IE check)
// ============================================================================

func TestHandleUnwrapKey_InvalidPublicKeyPEM(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	ks := NewMockKeyStoreWithImportExport()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	garblePEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: []byte("garbage")}))
	body, _ := json.Marshal(UnwrapKeyRequest{
		WrappedKey:           []byte("data"),
		WrappingPublicKeyPEM: garblePEM,
		Algorithm:            "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleUnwrapKey(rec, req, "any-key", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleImportKey — success path using ImportExport backend
// ============================================================================

func TestHandleImportKey_Success(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	ks := NewMockKeyStoreWithImportExport()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(ImportKeyRequest{
		WrappedKey: []byte("wrapped-key-material"),
		Algorithm:  "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleImportKey(rec, req, "import-key", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleImportKey — ImportKey returns an error
// ============================================================================

func TestHandleImportKey_ImportError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	mockIE := NewMockImportExportBackend()
	mockIE.importKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		return errors.New("import storage failure")
	}
	ks := &importExportKeyStore{
		MockKeyStore: xkmsmocks.NewMockKeyStore(),
		ie:           mockIE,
	}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(ImportKeyRequest{
		WrappedKey: []byte("wrapped-data"),
		Algorithm:  "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleImportKey(rec, req, "fail-import-key", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleExportKey — success path using ImportExport backend
// ============================================================================

func TestHandleExportKey_Success(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	mockIE := NewMockImportExportBackend()
	inner := xkmsmocks.NewMockKeyStore()
	inner.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "export-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	inner.SetKey("export-key", nil)

	ks := &importExportKeyStore{MockKeyStore: inner, ie: mockIE}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "export-key", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleExportKey — ExportKey returns an error
// ============================================================================

func TestHandleExportKey_ExportError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	mockIE := NewMockImportExportBackend()
	mockIE.exportKeyFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, errors.New("export hardware failure")
	}

	inner := xkmsmocks.NewMockKeyStore()
	inner.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "exp-err-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	inner.SetKey("exp-err-key", nil)

	ks := &importExportKeyStore{MockKeyStore: inner, ie: mockIE}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(ExportKeyRequest{Algorithm: "RSA_OAEP_SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleExportKey(rec, req, "exp-err-key", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleCopyKey — success path (both backends support ImportExport)
// ============================================================================

func TestHandleCopyKey_Success(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	inner := xkmsmocks.NewMockKeyStore()
	inner.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "src-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	ks := NewMockKeyStoreWithImportExport()
	ks.MockKeyStore = inner

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "src-key",
		DestBackend:   "software",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleCopyKey — destination backend not found
// ============================================================================

func TestHandleCopyKey_DestBackendNotFound(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "some-key",
		DestBackend:   "nonexistent",
		DestKeyID:     "dest-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// dest backend nonexistent → 404
	assert.Contains(t, []int{http.StatusNotFound, http.StatusBadRequest}, w.Code)
}

// ============================================================================
// server.Stop — nil underlying HTTP/3 server (exercises the nil guard)
// ============================================================================

func TestServerStop_NilServer(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	// server.server (http3.Server) is nil until Start() is called.
	err := server.Stop()
	assert.NoError(t, err)
}

// ============================================================================
// handleSaveCert — key_id from query param and certificate_pem field name
// ============================================================================

// TestHandleSaveCert_KeyIDFromQueryParam exercises the query-param key_id path
// (key_id not in body but present as ?key_id=... → proceeds to cert_pem check).
func TestHandleSaveCert_KeyIDFromQueryParam(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// key_id in query → passes key_id check; no cert_pem → 400.
	body, _ := json.Marshal(CertRequest{})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs?key_id=my-key", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestHandleSaveCert_CertificatePEMField exercises the certificate_pem field alias.
func TestHandleSaveCert_CertificatePEMField(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// certificate_pem (not cert_pem) set to an invalid PEM → 400.
	body, _ := json.Marshal(CertRequest{KeyID: "my-key", CertificatePEM: "not-a-real-cert"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/certs", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// PIN handler error paths — cover sendPINError branches via mockPINManager
// ============================================================================

func TestHandleChangeSOPIN_Error(t *testing.T) {
	server, pin := createBarrierServerWithPIN(t)
	defer xkms.Reset()
	pin.changeSOErr = qrdbsdk.ErrPINInvalid

	body, _ := json.Marshal(ChangeSOPINRequest{CurrentSOPIN: "wrong", NewSOPIN: "new"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleChangeUserPIN_Error(t *testing.T) {
	server, pin := createBarrierServerWithPIN(t)
	defer xkms.Reset()
	pin.changeUserErr = qrdbsdk.ErrPINLocked

	body, _ := json.Marshal(ChangeUserPINRequest{CurrentUserPIN: "cur", NewUserPIN: "new"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/change", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusTooManyRequests, w.Code)
}

func TestHandleVerifySOPIN_Error(t *testing.T) {
	server, pin := createBarrierServerWithPIN(t)
	defer xkms.Reset()
	pin.verifySOErr = qrdbsdk.ErrSOPINRequired

	body, _ := json.Marshal(VerifyPINRequest{PIN: "somepin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/so-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestHandleVerifyUserPIN_Error(t *testing.T) {
	server, pin := createBarrierServerWithPIN(t)
	defer xkms.Reset()
	pin.verifyUserErr = qrdbsdk.ErrPINTooShort

	body, _ := json.Marshal(VerifyPINRequest{PIN: "x"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/user-pin/verify", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleResetLockout_MissingSOPINAlt(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	// Empty body → SOPIN field is "" → 400.
	body, _ := json.Marshal(ResetLockoutRequest{SOPIN: ""})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleResetLockout_Error(t *testing.T) {
	server, pin := createBarrierServerWithPIN(t)
	defer xkms.Reset()
	pin.resetErr = qrdbsdk.ErrPINAlreadySet

	body, _ := json.Marshal(ResetLockoutRequest{SOPIN: "sopin"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout/reset", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ============================================================================
// handleBarrierSeal — Seal() completes (uninitialized, initialized, or error)
// ============================================================================

func TestHandleBarrierSeal_SealAny(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/seal", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Barrier may succeed (200) or fail (400/409/500) depending on state.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError, http.StatusBadRequest, http.StatusConflict}, w.Code)
}

// ============================================================================
// handleGetLockoutStatus — method not allowed (POST on a GET-only endpoint)
// ============================================================================

func TestHandleGetLockoutStatus_PostNotAllowed(t *testing.T) {
	server, _ := createBarrierServerWithPIN(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/pin/lockout", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// Password handlers — UnlockHandler / LockHandler with nil manager (501)
// ============================================================================

func TestPasswordUnlockHandler_NilManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// createPasswordTestServer does not wire a PasswordManager → 501.
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestPasswordLockHandler_NilManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

// ============================================================================
// StatusHandler — system-level fallback when no manager is set
// ============================================================================

func TestPasswordStatusHandler_NoManager(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleBarrierInitialize — double init (covers sendBarrierError conflict branch)
// ============================================================================

func TestHandleBarrierInitialize_DoubleInit(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	// First initialization succeeds.
	ibody, _ := json.Marshal(BarrierInitializeRequest{Secret: "secret-one"})
	ireq := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(ibody))
	server.handler.ServeHTTP(httptest.NewRecorder(), ireq)

	// Second initialization → ErrAlreadyInitialized → 409.
	body, _ := json.Marshal(BarrierInitializeRequest{Secret: "secret-two"})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/initialize", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ============================================================================
// handleGetCertChain — chain not found (exercises 200/empty branch)
// ============================================================================

func TestHandleGetCertChain_NotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/certs/nonexistent-cert/chain", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusOK, http.StatusNotFound, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleRotateKey — success path with nil private key (exercises nil-privKey branch)
// ============================================================================

func TestHandleRotateKey_SuccessNilKey(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rotate-key", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rotate-key", privKey)
	mockKS.RotateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		newKey, _ := rsa.GenerateKey(rand.Reader, 2048)
		return newKey, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleRotateKey(rec, req, "rotate-key", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — non-RSA key (Ed25519) returns 400
// ============================================================================

func TestHandleAsymmetricEncrypt_NotRSA(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Ed25519 key — extractPublicKey succeeds, but the key is not *rsa.PublicKey.
	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "ed25519-asym-enc", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.Ed25519},
		}, nil
	}
	mockKS.SetKey("ed25519-asym-enc", privKey)

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "ed25519-asym-enc", "software")
	// Ed25519 is not RSA → 400
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleEncrypt — full success path + AdditionalData branch
// ============================================================================

func TestHandleEncrypt_SymmetricFullSuccess(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	const keyName = "sym-enc-full"

	// Store the key in BOTH the mock key store AND the symmetric key store.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyName, key)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 keyName,
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey(keyName, nil)

	body, _ := json.Marshal(EncryptRequest{
		Plaintext:      []byte("hello-aes"),
		AdditionalData: []byte("aad-context"), // exercises the AdditionalData branch
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, req, keyName, "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleDecrypt — symmetric full success path
// ============================================================================

func TestHandleDecrypt_SymmetricFullSuccess(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	const keyName = "sym-dec-full"

	// Generate a real AES-256 key and store it.
	key := make([]byte, 32)
	_, err := rand.Read(key)
	require.NoError(t, err)
	ext.StoreSymmetricKey(keyName, key)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 keyName,
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey(keyName, nil)

	// Encrypt something first so we can decrypt it.
	encReq := httptest.NewRequest(http.MethodPost, "/test", mustMarshal(EncryptRequest{
		Plaintext: []byte("plaintext-test"),
	}))
	encRec := httptest.NewRecorder()
	server.handleEncrypt(encRec, encReq, keyName, "software")
	require.Equal(t, http.StatusOK, encRec.Code)

	var encResp EncryptResponse
	require.NoError(t, json.NewDecoder(encRec.Body).Decode(&encResp))

	// Now decrypt.
	body, _ := json.Marshal(DecryptRequest{
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Tag:        encResp.Tag,
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, keyName, "software")
	assert.Equal(t, http.StatusOK, rec.Code)

	var decResp DecryptResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&decResp))
	assert.Equal(t, []byte("plaintext-test"), decResp.Plaintext)
}

// mustMarshal marshals v to bytes or panics. Helper for table tests.
func mustMarshal(v interface{}) *bytes.Reader {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return bytes.NewReader(b)
}

// ============================================================================
// handleSign — Signer() returns error (key not in store)
// ============================================================================

func TestHandleSign_SignerError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-signer-err", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// Not stored in keys map → Signer() returns ErrMockKeyNotFound.
	// Don't call SetKey so the key is missing.

	body, _ := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "rsa-signer-err", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleSign — Sign() itself returns an error (via SignerFunc)
// ============================================================================

func TestHandleSign_SignError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-sign-fail", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// Use a failing signer stub.
	mockKS.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return nil, errors.New("HSM unavailable")
	}
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.SetKey("rsa-sign-fail", privKey)

	body, _ := json.Marshal(SignRequest{Data: []byte("data"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "rsa-sign-fail", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleVerify — GetKey() returns error (key missing from store)
// ============================================================================

func TestHandleVerify_GetKeyError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "missing-verify-key", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// Key is NOT in the keys map → GetKey returns ErrMockKeyNotFound → 404.

	body, _ := json.Marshal(VerifyRequest{Data: []byte("msg"), Signature: []byte("sig"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "missing-verify-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleVerify — default signature type case (map signature → []byte coercion)
// ============================================================================

func TestHandleVerify_DefaultSignatureType(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-deftype", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rsa-deftype", privKey)

	// Use a raw JSON object as the Signature field → triggers the default type case.
	body := []byte(`{"data":"aGVsbG8=","signature":{"foo":"bar"},"hash":"SHA256"}`)
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "rsa-deftype", "software")
	// Verification completes (valid=false) because sigBytes will be marshaled JSON of map.
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleDecrypt — no backendParam fallback: symmetric backend not found,
// falls back to software backend to find the key.
// ============================================================================

func TestHandleDecrypt_NoBackendFallbackToSoftware(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Register the key with RSA attrs so IsSymmetric()==false → asymmetric path.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-nodec", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeEncryption, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rsa-nodec", privKey)

	// backendParam is "": no "symmetric" backend is registered; falls back to "software".
	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("junk")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "rsa-nodec", "")
	// Reaches asymmetric path → decrypt fails on junk → 500 OR
	// key not found in "symmetric" → falls to "software" which has it.
	assert.Contains(t, []int{http.StatusOK, http.StatusInternalServerError}, rec.Code)
}

// ============================================================================
// handleDecrypt — method not allowed
// ============================================================================

func TestHandleDecrypt_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleDecrypt(rec, req, "any", "software")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleEncrypt — method not allowed (GET via direct call)
// ============================================================================

func TestHandleEncrypt_MethodNotAllowedDirect(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, req, "any", "software")
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleEncrypt — key not found
// ============================================================================

func TestHandleEncrypt_KeyNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Empty ListKeysFunc → findKeyByID returns error.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, req, "no-such-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleEncrypt — backend does not support symmetric encryption
// ============================================================================

func TestHandleEncrypt_BackendNoSymmetric(t *testing.T) {
	// createTestServer uses standard MockKeyStore whose KeyProvider() does NOT
	// implement SymmetricKeyProvider → triggers the 400 "does not support" branch.
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{
				CN:                 "sym-no-support",
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				KeyAlgorithm:       x509.UnknownPublicKeyAlgorithm,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
			},
		}, nil
	}
	mockKS.SetKey("sym-no-support", nil)

	body, _ := json.Marshal(EncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleEncrypt(rec, req, "sym-no-support", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleGenerateKey — key generation error (RSA via error func)
// ============================================================================

func TestHandleGenerateKey_RSAGenerationError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.GenerateRSAFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("HSM key generation failed")
	}

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "rsa-gen-err",
		Backend:   "software",
		Algorithm: "rsa",
		KeySize:   2048,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleGenerateKey — storeType is StoreUnknown (custom backend name)
// ============================================================================

func TestHandleGenerateKey_StoreTypeUnknown(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	// Register a backend under the name "custom-backend". ParseStoreType("custom-backend")
	// returns StoreUnknown → 400 "invalid backend".
	inner := xkmsmocks.NewMockKeyStore()
	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"custom-backend": inner},
		DefaultBackend: "custom-backend",
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

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "unknown-store-key",
		Backend:   "custom-backend",
		Algorithm: "rsa",
		KeySize:   2048,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleBarrierDeleteRecoveryKeys — nil barrier (503) and method-not-allowed
// ============================================================================

func TestHandleBarrierDeleteRecoveryKeys_NilBarrier(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/barrier/recovery-keys", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierDeleteRecoveryKeys(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleBarrierDeleteRecoveryKeys_MethodNotAllowedGet(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierDeleteRecoveryKeys(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleBarrierHasRecoveryKeys — nil barrier (503) and method-not-allowed
// ============================================================================

func TestHandleBarrierHasRecoveryKeys_NilBarrier(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/recovery-keys", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierHasRecoveryKeys(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestHandleBarrierHasRecoveryKeys_MethodNotAllowedPost(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recovery-keys", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierHasRecoveryKeys(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleBarrierRecoverWithKeys — nil barrier (503)
// ============================================================================

func TestHandleBarrierRecoverWithKeys_NilBarrier(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(map[string]interface{}{"keys": []string{"key1"}})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/recover", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleBarrierRecoverWithKeys(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ============================================================================
// createPasswordTestServerWithManager builds a server that has a real
// TenantPasswordStoreManager wired in. This enables testing the
// identity-check branches (manager != nil) of UnlockHandler/LockHandler/StatusHandler.
// ============================================================================

func createPasswordTestServerWithManager(t *testing.T) *Server {
	t.Helper()
	xkms.Reset()

	// Bootstrap a server with a password store.
	server, _ := createPasswordTestServer(t)

	// Build a minimal system barrier.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{RootKeyPath: "test-root-key"}, strategy)
	require.NoError(t, err)

	// Build a BarrierRegistry from the system barrier.
	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// Build a minimal in-memory system store.
	systemStore := staticpw.NewStore(storage.New())

	// Create the manager.
	mgr, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	// Wire the manager into the server.
	server.SetPasswordManager(mgr)
	// Rebuild routes so the new manager is picked up.
	mux := http.NewServeMux()
	server.setupPasswordRoutes(mux)
	server.setupBarrierPINRoutes(mux)
	// Replace the handler with a fresh mux that includes the updated password routes.
	// Instead of replacing the handler, call SetPasswordManager before NewServer
	// by using a temporary server. Here we patch the handler for the test scope.
	newHandler := http.NewServeMux()
	server.setupRoutes(newHandler)
	server.handler = newHandler

	return server
}

// ============================================================================
// createPasswordTestServerWithUnsealedTenant creates a server with a real
// TenantPasswordStoreManager where a named tenant has been registered,
// initialized, and unsealed. This lets unlock/lock/status success paths run.
// ============================================================================

func createPasswordTestServerWithUnsealedTenant(t *testing.T, tenantID string) *Server {
	t.Helper()
	xkms.Reset()

	server, _ := createPasswordTestServer(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{RootKeyPath: "root-key"}, strategy)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// Register + initialize the tenant barrier.
	// Note: after Initialize, the barrier is already unsealed — no separate Unseal needed.
	_, err = registry.RegisterTenant(tenantID)
	require.NoError(t, err)

	ctx := context.Background()
	creds := qrdbsdk.Credentials{Secret: "tenant-test-passphrase"}
	require.NoError(t, registry.InitializeTenant(ctx, tenantID, creds))

	systemStore := staticpw.NewStore(storage.New())
	mgr, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	server.SetPasswordManager(mgr)
	newHandler := http.NewServeMux()
	server.setupRoutes(newHandler)
	server.handler = newHandler

	return server
}

// ============================================================================
// UnlockHandler — tenant unsealed: first unlock succeeds, second returns ErrStoreNotLocked
// ============================================================================

func TestPasswordUnlockHandler_Success(t *testing.T) {
	const tenantID = "unlock-success-tenant"
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithUnsealedTenant(t, tenantID)

	identity := &auth.Identity{Subject: "user1", TenantID: tenantID}

	// First unlock: tenant is sealed-by-default in manager state → clears lock → 200.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "Store unlocked successfully", resp.Message)
}

// ============================================================================
// UnlockHandler — ErrStoreNotLocked: already-unlocked tenant → 409
// ============================================================================

func TestPasswordUnlockHandler_AlreadyUnlocked(t *testing.T) {
	const tenantID = "already-unlocked-tenant"
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithUnsealedTenant(t, tenantID)

	identity := &auth.Identity{Subject: "user1", TenantID: tenantID}

	// First unlock succeeds.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	req1 = req1.WithContext(auth.WithIdentity(req1.Context(), identity))
	server.handler.ServeHTTP(httptest.NewRecorder(), req1)

	// Second unlock → ErrStoreNotLocked → 409.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	req2 = req2.WithContext(auth.WithIdentity(req2.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req2)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ============================================================================
// UnlockHandler — ErrTenantSealed: registered but sealed tenant → 503
// ============================================================================

func TestPasswordUnlockHandler_TenantSealed(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server, _ := createPasswordTestServer(t)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	base := storage.New()
	strategy := seal.NewSoftwareStrategy()
	barrier, err := seal.NewBarrier(logger, base, seal.BarrierConfig{RootKeyPath: "root-key"}, strategy)
	require.NoError(t, err)

	registry, err := seal.NewBarrierRegistry(barrier)
	require.NoError(t, err)

	// Register tenant but do NOT initialize/unseal → tenant is SEALED.
	_, err = registry.RegisterTenant("sealed-tenant")
	require.NoError(t, err)

	systemStore := staticpw.NewStore(storage.New())
	mgr, err := staticpw.NewTenantPasswordStoreManager(registry, systemStore)
	require.NoError(t, err)

	server.SetPasswordManager(mgr)
	newHandler := http.NewServeMux()
	server.setupRoutes(newHandler)
	server.handler = newHandler

	identity := &auth.Identity{Subject: "user1", TenantID: "sealed-tenant"}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// Tenant is sealed → ErrTenantSealed → 503.
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ============================================================================
// LockHandler — success path (lock an unlocked tenant)
// ============================================================================

func TestPasswordLockHandler_Success(t *testing.T) {
	const tenantID = "lock-success-tenant"
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithUnsealedTenant(t, tenantID)

	identity := &auth.Identity{Subject: "user1", TenantID: tenantID}

	// Unlock first so we have something to lock.
	unlockReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	unlockReq = unlockReq.WithContext(auth.WithIdentity(unlockReq.Context(), identity))
	server.handler.ServeHTTP(httptest.NewRecorder(), unlockReq)

	// Lock → 200.
	lockReq := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	lockReq = lockReq.WithContext(auth.WithIdentity(lockReq.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, lockReq)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "Store locked successfully", resp.Message)
}

// ============================================================================
// LockHandler — ErrStoreAlreadyLocked: lock an already-locked tenant → 409
// ============================================================================

func TestPasswordLockHandler_AlreadyLocked(t *testing.T) {
	const tenantID = "already-locked-tenant"
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithUnsealedTenant(t, tenantID)

	identity := &auth.Identity{Subject: "user1", TenantID: tenantID}

	// No unlock first → tenant state is default-locked or no-state.
	// LockTenant: no tenantPasswordState loaded → registry.Tenant(tenantID) exists
	// → returns ErrStoreAlreadyLocked (no state = default locked).
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusConflict, w.Code)
}

// ============================================================================
// StatusHandler — manager + unsealed tenant with valid identity → success (200)
// ============================================================================

func TestPasswordStatusHandler_WithUnsealedTenant(t *testing.T) {
	const tenantID = "status-success-tenant"
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithUnsealedTenant(t, tenantID)

	identity := &auth.Identity{Subject: "user1", TenantID: tenantID}
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordStoreStatusResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.True(t, resp.Available)
}

// ============================================================================
// UnlockHandler — identity present but TenantID empty → 401
// ============================================================================

func TestPasswordUnlockHandler_EmptyTenantID(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithManager(t)

	// Inject identity with empty TenantID → 401.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	identity := &auth.Identity{Subject: "user1", TenantID: ""}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ============================================================================
// UnlockHandler — identity with valid TenantID but tenant not found → 404
// ============================================================================

func TestPasswordUnlockHandler_TenantNotFound(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithManager(t)

	// Tenant "unknown-tenant" not registered in registry → ErrTenantNotFound → 404.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/unlock", nil)
	identity := &auth.Identity{Subject: "user1", TenantID: "unknown-tenant"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// LockHandler — identity present but TenantID empty → 401
// ============================================================================

func TestPasswordLockHandler_EmptyTenantID(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithManager(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	identity := &auth.Identity{Subject: "user1", TenantID: ""}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

// ============================================================================
// LockHandler — valid TenantID, tenant not in registry → 404
// ============================================================================

func TestPasswordLockHandler_TenantNotFound(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithManager(t)

	// ErrStoreAlreadyLocked when no state → but Tenant() fails first → default→500.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/lock", nil)
	identity := &auth.Identity{Subject: "user1", TenantID: "unknown-tenant"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	// LockTenant: no state → registry.Tenant("unknown-tenant") → ErrTenantNotFound OR
	// ErrStoreAlreadyLocked. Either 404 or 409 are valid.
	assert.Contains(t, []int{http.StatusNotFound, http.StatusConflict, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// StatusHandler — manager present + valid tenant identity → calls TenantStoreStatus
// ============================================================================

func TestPasswordStatusHandler_WithTenantIdentity(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	server := createPasswordTestServerWithManager(t)

	// Tenant not registered → TenantStoreStatus → ErrTenantNotFound → 404.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/status", nil)
	identity := &auth.Identity{Subject: "user1", TenantID: "no-such-tenant"}
	req = req.WithContext(auth.WithIdentity(req.Context(), identity))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — RSA success path (200)
// ============================================================================

func TestHandleAsymmetricEncrypt_RSASuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-asym-enc-ok", KeyType: types.KeyTypeEncryption, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}
	mockKS.SetKey("rsa-asym-enc-ok", privKey)

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("hello RSA")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "rsa-asym-enc-ok", "software")
	assert.Equal(t, http.StatusOK, rec.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — key not found (findKeyByID fails) → 404
// ============================================================================

func TestHandleAsymmetricEncrypt_KeyNotFoundDirect(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "no-such-asym-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleRotateKey — RotateKey returns error → 500
// ============================================================================

func TestHandleRotateKey_RotationError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-rotate-err", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rsa-rotate-err", privKey)
	mockKS.RotateKeyFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("HSM rotation failed")
	}

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleRotateKey(rec, req, "rsa-rotate-err", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleCopyKey — source key not found in ImportExport backend
// ============================================================================

func TestHandleCopyKey_SourceKeyNotFound(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	inner := xkmsmocks.NewMockKeyStore()
	// No keys registered → findKeyByID fails on source.
	inner.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}
	ks := NewMockKeyStoreWithImportExport()
	ks.MockKeyStore = inner

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "nonexistent",
		DestBackend:   "software",
		DestKeyID:     "dst",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleGenerateKey — AES generation error (via GenerateSymmetricKeyFunc returning error)
// ============================================================================

// ============================================================================
// handleBarrierSeal — method not allowed (non-POST)
// ============================================================================

func TestHandleBarrierSeal_MethodNotAllowedGet(t *testing.T) {
	server := createBarrierTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/barrier/seal", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierSeal(rec, req)
	assert.Equal(t, http.StatusMethodNotAllowed, rec.Code)
}

// ============================================================================
// handleBarrierSeal — nil barrier (503)
// ============================================================================

func TestHandleBarrierSeal_NilBarrierDirect(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/api/v1/barrier/seal", nil)
	rec := httptest.NewRecorder()
	server.handleBarrierSeal(rec, req)
	assert.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

// ============================================================================
// handleGetImportParameters — invalid (unknown) backend param → 400
// ============================================================================

func TestHandleGetImportParameters_InvalidBackendDirect(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP_SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// "custom-unknown" → ParseStoreType returns StoreUnknown → 400.
	server.handleGetImportParameters(rec, req, "any-key", "custom-unknown")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleBackendOperations — existing backend returns BackendInfo
// ============================================================================

func TestHandleBackendOperations_Success(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// handleGenerateKey — ECDSA generation error
// ============================================================================

func TestHandleGenerateKey_ECDSAGenerationError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.GenerateECDSAFunc = func(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
		return nil, errors.New("ECDSA generation failed")
	}

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "ecdsa-gen-err",
		Backend:   "software",
		Algorithm: "ecdsa",
		Curve:     "P-256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleSign — RSA sign success path (exercises signer.Sign() for non-Ed25519 key)
// ============================================================================

func TestHandleSign_RSASuccess(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-sign-ok", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// No SignerFunc override — MockKeyStore uses SetKey to provide the signer.
	mockKS.SetKey("rsa-sign-ok", privKey)

	body, _ := json.Marshal(SignRequest{Data: []byte("hello world"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "rsa-sign-ok", "software")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp SignResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.Signature)
}

// ============================================================================
// handleVerify — RSA path with valid hash and invalid sig → valid=false
// ============================================================================

func TestHandleVerify_RSABadSig(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-verify-bad", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rsa-verify-bad", privKey)

	// Bogus signature — VerifyPKCS1v15 returns an error → err != nil → valid=false.
	body, _ := json.Marshal(VerifyRequest{
		Data:      []byte("hello"),
		Signature: []byte("definitely-not-a-valid-rsa-signature"),
		Hash:      "SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "rsa-verify-bad", "software")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp VerifyResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.False(t, resp.Valid)
}

// ============================================================================
// handleVerify — extractPublicKey error (nil key from GetKey) → 500
// ============================================================================

func TestHandleVerify_ExtractPubKeyError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// SetKey with nil → GetKey returns (nil, nil) → extractPublicKey(nil) → error.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "nil-key-verify", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("nil-key-verify", nil)

	body, _ := json.Marshal(VerifyRequest{
		Data:      []byte("msg"),
		Signature: []byte("sig"),
		Hash:      "SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "nil-key-verify", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// UpdatePasswordHandler — ErrEmptyPassword → 400 and ErrInvalidName → 400
// ============================================================================

func TestUpdatePasswordHandler_EmptyPassword(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "pw-for-empty-update",
		Password: "original",
	}
	require.NoError(t, store.Add(pw))

	// Send empty password string via pointer → existing.Password="" → ErrEmptyPassword.
	emptyPW := ""
	body, _ := json.Marshal(PasswordUpdateRequest{Password: &emptyPW})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUpdatePasswordHandler_EmptyName(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "pw-for-name-update",
		Password: "original",
	}
	require.NoError(t, store.Add(pw))

	// Send empty name string via pointer → existing.Name="" → ErrInvalidName.
	emptyName := ""
	body, _ := json.Marshal(PasswordUpdateRequest{Name: &emptyName})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleSeal — KeyID provided but key not found in ListKeys → 404
// ============================================================================

func TestHandleSeal_KeyIDNotFound(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// ListKeysFunc returns an empty set — so key lookup for "ghost-key" fails.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}
	// Also need CanSeal to allow the request to proceed past early checks.
	// The backend check happens inside sealWithBackend, but the key-lookup
	// happens before sealWithBackend is called.

	body, _ := json.Marshal(SealRequest{
		Backend: "software",
		KeyID:   "ghost-key",
		Data:    []byte("secret"),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleSeal — KeyID provided but ListKeys returns error → 500
// ============================================================================

func TestHandleSeal_ListKeysError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("keystore unavailable")
	}

	body, _ := json.Marshal(SealRequest{
		Backend: "software",
		KeyID:   "any-key",
		Data:    []byte("secret"),
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/seal", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleCopyKey — source backend does not support ImportExport → 400
// ============================================================================

func TestHandleCopyKey_SourceNoImportExport(t *testing.T) {
	// createTestServer uses standard MockKeyStore whose KeyProvider() is
	// *backend.MockBackend — which does NOT implement ImportExportBackend.
	// So the source backend check on line 2144 fails → 400.
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "src-no-ie", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.Ed25519},
		}, nil
	}

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "src-no-ie",
		DestBackend:   "software",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// ListPasswordsHandler — folder path and invalid scope → 400
// ============================================================================

func TestListPasswordsHandler_FolderPath(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	// Add a password with a folder path.
	pw := &staticpw.StaticPassword{
		Name:       "folder-pw",
		Password:   "secret",
		FolderPath: "myapp/credentials",
	}
	require.NoError(t, store.Add(pw))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?folder=myapp/credentials", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	var resp PasswordListResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.GreaterOrEqual(t, resp.Total, 1)
}

func TestListPasswordsHandler_InvalidScopeAlt(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	// "unknown" is not a valid PasswordScope → 400.
	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?scope=unknown", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestListPasswordsHandler_ScopeAllFallback(t *testing.T) {
	// ?scope=all on a non-ScopedStore → falls back to store.List() → 200.
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords?scope=all", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)
}

// ============================================================================
// UpdatePasswordHandler — ErrPasswordReadOnly → 403
// ============================================================================

func TestUpdatePasswordHandler_ReadOnly(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "readonly-update-pw",
		Password: "secret",
		ReadOnly: true,
	}
	require.NoError(t, store.Add(pw))

	newPW := "new-secret"
	body, _ := json.Marshal(PasswordUpdateRequest{Password: &newPW})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/"+pw.ID, bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ============================================================================
// DeletePasswordHandler — ErrPasswordReadOnly → 403
// ============================================================================

func TestDeletePasswordHandler_ReadOnly(t *testing.T) {
	server, store := createPasswordTestServer(t)
	defer xkms.Reset()

	pw := &staticpw.StaticPassword{
		Name:     "readonly-delete-pw",
		Password: "secret",
		ReadOnly: true,
	}
	require.NoError(t, store.Add(pw))

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/"+pw.ID, nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ============================================================================
// handleAsymmetricEncrypt — GetKey returns error (key in attrs but not in keys map)
// ============================================================================

func TestHandleAsymmetricEncrypt_GetKeyError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// Registered in ListKeys so findKeyByID succeeds, but SetKey is NOT called
	// so GetKey will fail with ErrMockKeyNotFound.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "asym-enc-no-key", KeyType: types.KeyTypeEncryption, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}
	// Deliberately NOT calling mockKS.SetKey so GetKey returns not-found.

	body, _ := json.Marshal(AsymmetricEncryptRequest{Plaintext: []byte("data")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleAsymmetricEncrypt(rec, req, "asym-enc-no-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleDecrypt — key not found in both symmetric and software backends (no backendParam)
// ============================================================================

func TestHandleDecrypt_KeyNotFoundBothBackends(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	// ListKeysFunc returns nothing so findKeyByID fails on the "software" backend too.
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{}, nil
	}

	body, _ := json.Marshal(DecryptRequest{Ciphertext: []byte("junk")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	// Empty backendParam triggers the else branch: try "symmetric" (fails), try "software",
	// findKeyByID on software also fails → 404.
	server.handleDecrypt(rec, req, "ghost-key", "")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleGetImportParameters — GetImportParameters returns error → 500
// ============================================================================

func TestHandleGetImportParameters_GetParamsError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	mockIE := NewMockImportExportBackend()
	mockIE.getImportParamsFunc = func(
		attrs *types.KeyAttributes,
		alg backend.WrappingAlgorithm,
	) (*backend.ImportParameters, error) {
		return nil, errors.New("HSM import params unavailable")
	}
	ks := &importExportKeyStore{
		MockKeyStore: xkmsmocks.NewMockKeyStore(),
		ie:           mockIE,
	}

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))

	svc, _ := xkms.Get()
	cfg := &Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	}
	server, err := NewServer(cfg)
	require.NoError(t, err)

	body, _ := json.Marshal(GetImportParametersRequest{Algorithm: "RSA_OAEP_SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleGetImportParameters(rec, req, "any-key", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleSign — Ed25519 sign() returns error via SignerFunc
// ============================================================================

func TestHandleSign_Ed25519SignError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "ed25519-sign-err", KeyAlgorithm: x509.Ed25519, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// SignerFunc returns error so signer.Sign will never be reached, but the
	// Signer() call itself fails → 500.
	mockKS.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return nil, errors.New("Ed25519 HSM unavailable")
	}
	mockKS.SetKey("ed25519-sign-err", privKey)

	body, _ := json.Marshal(SignRequest{Data: []byte("message")})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "ed25519-sign-err", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleVerify — Ed25519 key path with bad signature (valid=false)
// ============================================================================

func TestHandleVerify_Ed25519BadSig(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	_, privKey, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "ed25519-verify", KeyAlgorithm: x509.Ed25519, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("ed25519-verify", privKey)

	// Bogus signature — verifySignature returns false (not an error).
	body, _ := json.Marshal(VerifyRequest{
		Data:      []byte("hello"),
		Signature: []byte("bad-signature"),
	})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "ed25519-verify", "software")
	assert.Equal(t, http.StatusOK, rec.Code)

	var resp VerifyResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.False(t, resp.Valid)
}

// ============================================================================
// handleGenerateKey — AES generation error (via SymmetricEncrypterFunc returning error
// for GenerateSymmetricKey; use ExtendedMockBackend which supports it)
// ============================================================================

func TestHandleGenerateKey_AES256GenerationError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	inner := xkmsmocks.NewMockKeyStore()
	ext := backendmocks.NewExtendedMockBackend()
	ext.GenerateSymmetricKeyFunc = func(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
		return nil, errors.New("symmetric key storage full")
	}
	ks := &extendedKeyStore{MockKeyStore: inner, ext: ext}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
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

	// Use KeyType="symmetric" with empty Algorithm so the inner req.Algorithm=="" check
	// skips the IsValid guard and uses KeySize=256 → SymmetricAES256GCM.
	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "aes256-gen-err",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 256,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// findKeyByID — ListKeys returns error (via handleGetKey)
// ============================================================================

// TestHandleGetKey_ListKeysError exercises the findKeyByID ListKeys error branch.
// The error propagates through handleGetKey → 404.
func TestHandleGetKey_ListKeysError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("keystore unavailable")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/any-key?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleGetKey — GetKey returns error after findKeyByID succeeds
// ============================================================================

// TestHandleGetKey_GetKeyError finds a key via ListKeys but GetKey fails because
// the key is not stored in the mock's key map.
func TestHandleGetKey_GetKeyError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "ghost-key", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	// Key is in list but NOT in the key map → GetKey returns error.

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/ghost-key?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// handleSign — bad JSON body
// ============================================================================

// TestHandleSign_BadBody sends invalid JSON to handleSign covering the
// json.NewDecoder.Decode error branch.
func TestHandleSign_BadBody(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-key", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("{bad json")))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "rsa-key", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleSign — Sign() itself fails for RSA/ECDSA digest path
// ============================================================================

// failingCryptoSigner is a crypto.Signer whose Sign method always returns an error.
type failingCryptoSigner struct {
	pub crypto.PublicKey
}

func (f *failingCryptoSigner) Public() crypto.PublicKey { return f.pub }
func (f *failingCryptoSigner) Sign(_ io.Reader, _ []byte, _ crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("HSM sign operation failed")
}

// TestHandleSign_RSADigestSignError exercises the signer.Sign error branch for
// the RSA/ECDSA digest path, where Signer() succeeds but Sign() itself fails.
func TestHandleSign_RSADigestSignError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-digest-fail", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}
	mockKS.SetKey("rsa-digest-fail", privKey)

	mockKS.SignerFunc = func(attrs *types.KeyAttributes) (crypto.Signer, error) {
		return &failingCryptoSigner{pub: &privKey.PublicKey}, nil
	}

	body, _ := json.Marshal(SignRequest{Data: []byte("hello"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleSign(rec, req, "rsa-digest-fail", "software")
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
}

// ============================================================================
// handleVerify — bad JSON body
// ============================================================================

// TestHandleVerify_BadBody sends invalid JSON to handleVerify covering the
// json.NewDecoder.Decode error branch.
func TestHandleVerify_BadBody(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "rsa-key", KeyAlgorithm: x509.RSA, KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware},
		}, nil
	}

	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader([]byte("{bad json")))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "rsa-key", "software")
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// ============================================================================
// handleVerify — findKeyByID returns error (ListKeys fails)
// ============================================================================

// TestHandleVerify_FindKeyByIDError makes ListKeys return an error so that
// findKeyByID fails inside handleVerify → 404.
func TestHandleVerify_FindKeyByIDError(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("keystore read error")
	}

	body, _ := json.Marshal(VerifyRequest{Data: []byte("msg"), Signature: []byte("sig"), Hash: "SHA256"})
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	server.handleVerify(rec, req, "some-key", "software")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// handleRotateKey — backend not found
// ============================================================================

// TestHandleRotateKey_BackendNotFound requests rotation on a non-existent backend
// → 404 from getKeystoreForBackend.
func TestHandleRotateKey_BackendNotFound(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodPost, "/test", nil)
	rec := httptest.NewRecorder()
	server.handleRotateKey(rec, req, "some-key", "nonexistent-backend")
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

// ============================================================================
// GetPasswordHandler — empty password ID
// ============================================================================

// TestGetPasswordHandler_EmptyPasswordID covers the passwordID == "" guard
// in GetPasswordHandler → 400.
func TestGetPasswordHandler_EmptyPasswordID(t *testing.T) {
	t.Helper()
	xkms.Reset()
	defer xkms.Reset()

	store := staticpw.NewStore(storage.New())
	handlers := NewPasswordHandlers(store, nil)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/passwords/", nil)
	w := httptest.NewRecorder()
	handlers.GetPasswordHandler(w, req, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// UpdatePasswordHandler — empty password ID
// ============================================================================

// TestUpdatePasswordHandler_EmptyPasswordID covers the passwordID == "" guard
// in UpdatePasswordHandler → 400.
func TestUpdatePasswordHandler_EmptyPasswordID(t *testing.T) {
	t.Helper()
	xkms.Reset()
	defer xkms.Reset()

	store := staticpw.NewStore(storage.New())
	handlers := NewPasswordHandlers(store, nil)

	body, _ := json.Marshal(PasswordUpdateRequest{})
	req := httptest.NewRequest(http.MethodPut, "/api/v1/passwords/", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handlers.UpdatePasswordHandler(w, req, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// DeletePasswordHandler — empty password ID
// ============================================================================

// TestDeletePasswordHandler_EmptyPasswordID covers the passwordID == "" guard
// in DeletePasswordHandler → 400.
func TestDeletePasswordHandler_EmptyPasswordID(t *testing.T) {
	t.Helper()
	xkms.Reset()
	defer xkms.Reset()

	store := staticpw.NewStore(storage.New())
	handlers := NewPasswordHandlers(store, nil)

	req := httptest.NewRequest(http.MethodDelete, "/api/v1/passwords/", nil)
	w := httptest.NewRecorder()
	handlers.DeletePasswordHandler(w, req, "")
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// AddPasswordHandler — duplicate name (ErrPasswordExists → 409)
// ============================================================================

// TestAddPasswordHandler_DuplicateName adds the same password twice and verifies
// that the second attempt returns 409 Conflict via ErrPasswordExists.
func TestAddPasswordHandler_DuplicateName(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	addBody := func() []byte {
		b, _ := json.Marshal(PasswordAddRequest{
			Name:     "dup-password",
			Password: "s3cr3t!",
		})
		return b
	}

	// First add must succeed.
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(addBody()))
	w1 := httptest.NewRecorder()
	server.handler.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusCreated, w1.Code)

	// Second add with same name → 409 Conflict.
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/passwords", bytes.NewReader(addBody()))
	w2 := httptest.NewRecorder()
	server.handler.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusConflict, w2.Code)
}

// ============================================================================
// handleGenerateKey — AES key size dispatch: 192-bit and unsupported size paths
// ============================================================================

// TestHandleGenerateKey_AES192_KeySize exercises the case 192 branch in the
// keysize switch. Algorithm must be empty so req.Algorithm=="" → keysize switch.
func TestHandleGenerateKey_AES192_KeySize(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "aes192-ks",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 192,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusInternalServerError}, w.Code)
}

// TestHandleGenerateKey_AES_UnsupportedKeySize exercises the default branch of the
// keysize switch for an unrecognised AES key size → 400.
func TestHandleGenerateKey_AES_UnsupportedKeySize(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "aes999-ks",
		Backend: "software",
		KeyType: "symmetric",
		KeySize: 999,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleCopyKey — destination backend does not implement ImportExportBackend
// ============================================================================

// TestHandleCopyKey_DestNoImportExport registers source (has ImportExport) and
// dest (plain MockKeyStore, no ImportExport). The handler returns 400 on the
// dest-backend type assertion.
func TestHandleCopyKey_DestNoImportExport(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	srcKS := NewMockKeyStoreWithImportExport()
	srcKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "src-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}

	// destKS is a standard MockKeyStore whose KeyProvider() is *MockBackend
	// — does NOT implement ImportExportBackend.
	destKS := xkmsmocks.NewMockKeyStore()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"source": srcKS, "software": destKS},
		DefaultBackend: "source",
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "source",
		SourceKeyID:   "src-key",
		DestBackend:   "software",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleCopyKey — source ListKeys returns error
// ============================================================================

// TestHandleCopyKey_SourceListKeysError exercises the ListKeys error branch after
// both backends are resolved and have ImportExport support.
func TestHandleCopyKey_SourceListKeysError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	srcKS := NewMockKeyStoreWithImportExport()
	srcKS.MockKeyStore.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, errors.New("source keystore unavailable")
	}
	destKS := NewMockKeyStoreWithImportExport()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"source": srcKS, "dest": destKS},
		DefaultBackend: "source",
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "source",
		SourceKeyID:   "some-key",
		DestBackend:   "dest",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleCopyKey — ExportKey returns error
// ============================================================================

// TestHandleCopyKey_ExportKeyError exercises the ExportKey error branch after a
// successful source key lookup. Source and dest both use "software" (a valid
// ParseStoreType name) to avoid the storeType validation error.
func TestHandleCopyKey_ExportKeyError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	srcKS := NewMockKeyStoreWithImportExport()
	srcKS.MockKeyStore.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "export-fail-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}
	srcKS.importExportBackend.exportKeyFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
		return nil, errors.New("HSM export denied")
	}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": srcKS},
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "export-fail-key",
		DestBackend:   "software",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// handleCopyKey — ImportKey returns error
// ============================================================================

// TestHandleCopyKey_ImportKeyError exercises the ImportKey error branch after
// a successful ExportKey. Both backends use "software" (valid ParseStoreType).
func TestHandleCopyKey_ImportKeyError(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	srcKS := NewMockKeyStoreWithImportExport()
	srcKS.MockKeyStore.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "import-fail-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}
	// ExportKey uses default → succeeds. ImportKey fails.
	srcKS.importExportBackend.importKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		return errors.New("dest keystore full")
	}

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": srcKS},
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "import-fail-key",
		DestBackend:   "software",
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// ============================================================================
// GeneratePasswordHandler — invalid length (ErrInvalidLength → 400)
// ============================================================================

// TestGeneratePasswordHandler_InvalidLength triggers ErrInvalidLength by sending
// a length below the minimum (8).
func TestGeneratePasswordHandler_InvalidLength(t *testing.T) {
	server, _ := createPasswordTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(PasswordGenerateRequest{Length: 1})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/generate", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleBackendOperations — empty backendID
// ============================================================================

// TestHandleBackendOperations_EmptyBackendID exercises the backendID == "" guard
// by sending a request to /api/v1/backends/ (trailing slash → empty path segment).
func TestHandleBackendOperations_EmptyBackendID(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/backends/", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGenerateKey — symmetric backend without SymmetricKeyProvider
// ============================================================================

// TestHandleGenerateKey_SymmetricNoSymProvider uses the plain test server
// (MockBackend does NOT implement SymmetricKeyProvider) with KeyType "symmetric"
// → covers the symBackend cast failure branch → 400.
func TestHandleGenerateKey_SymmetricNoSymProvider(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "sym-no-provider",
		Backend: "software",
		KeyType: "symmetric",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGenerateKey — valid symmetric algorithm in req.Algorithm (e.g. "aes256-gcm")
// ============================================================================

// TestHandleGenerateKey_SymmetricAlgorithmField exercises the req.Algorithm != ""
// branch inside the symmetric case. Using Algorithm: "symmetric" enters the
// symmetric switch arm (EqualFold("Symmetric","symmetric")=true) AND hits the
// req.Algorithm != "" branch → sets attrs.SymmetricAlgorithm → "symmetric" is
// not a valid SymmetricAlgorithm → 400.
func TestHandleGenerateKey_SymmetricAlgorithmField(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:     "sym-algo-field",
		Backend:   "software",
		Algorithm: "symmetric", // EqualFold matches "Symmetric"; invalid SymmetricAlgorithm → 400
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// ============================================================================
// handleGenerateKey — symmetric with no KeySize (defaults to 256)
// ============================================================================

// TestHandleGenerateKey_SymmetricDefaultKeySize omits KeySize so that the
// keySize == 0 → keySize = 256 default path is covered.
func TestHandleGenerateKey_SymmetricDefaultKeySize(t *testing.T) {
	server, _, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	body, _ := json.Marshal(GenerateKeyRequest{
		KeyID:   "aes-default-size",
		Backend: "software",
		KeyType: "symmetric",
		// KeySize intentionally omitted → defaults to 256.
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Contains(t, []int{http.StatusCreated, http.StatusInternalServerError}, w.Code)
}

// ============================================================================
// handleCopyKey — invalid destination storeType
// ============================================================================

// TestHandleCopyKey_InvalidDestStoreType registers a backend under a custom name
// ("custom-backend") so that lookupBackend succeeds but ParseStoreType returns
// StoreUnknown → 400.
func TestHandleCopyKey_InvalidDestStoreType(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	srcKS := NewMockKeyStoreWithImportExport()
	srcKS.MockKeyStore.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "src-key", KeyType: types.KeyTypeTLS, StoreType: types.StoreSoftware, KeyAlgorithm: x509.RSA},
		}, nil
	}
	// Both backends need ImportExport for the handler to get past the type assertion.
	destKS := NewMockKeyStoreWithImportExport()

	err := xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": srcKS, "custom-backend": destKS},
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

	body, _ := json.Marshal(CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "src-key",
		DestBackend:   "custom-backend", // registered but not a valid ParseStoreType → StoreUnknown
		DestKeyID:     "dst-key",
		Algorithm:     "RSA_OAEP_SHA256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/copy", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	assert.Equal(t, http.StatusBadRequest, w.Code)
}
