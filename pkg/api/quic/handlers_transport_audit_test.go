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
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// createServerWithNamedBackend registers a single backend under an arbitrary
// registration name, reporting an arbitrary store type. The two are
// deliberately different: a backend's configuration name and its store type are
// independent, and conflating them is the defect these tests pin.
func createServerWithNamedBackend(t *testing.T, name string, storeType types.BackendType) (*Server, *xkmsmocks.MockKeyStore) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	mockKS := xkmsmocks.NewMockKeyStore()
	mockKS.BackendMock.TypeFunc = func() types.BackendType { return storeType }

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{name: mockKS},
		DefaultBackend: name,
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{
		Addr:          "localhost:8444",
		Authenticator: auth.NewNoOpAuthenticator(),
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	})
	require.NoError(t, err)
	return server, mockKS
}

// TestHandleListKeys_FiltersByStoreTypeNotBackendName is the regression test
// for a list that always came back empty.
//
// The handler resolved the backend by name and then filtered its own keys by
// comparing KeyAttributes.StoreType against the *name* the backend happened to
// be registered under. Those are different values: a pkcs11 backend configured
// as "prod-hsm" matched nothing, so every key it held was dropped and the
// endpoint reported an empty keyring for a populated HSM.
func TestHandleListKeys_FiltersByStoreTypeNotBackendName(t *testing.T) {
	server, mockKS := createServerWithNamedBackend(t, "prod-hsm", types.BackendTypePKCS11)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "hsm-key-1", StoreType: types.StorePKCS11},
			{CN: "hsm-key-2", StoreType: types.StorePKCS11},
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=prod-hsm", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 2, "a backend not named after its store type must still list its keys")

	ids := []string{resp.Keys[0].KeyID, resp.Keys[1].KeyID}
	assert.ElementsMatch(t, []string{"hsm-key-1", "hsm-key-2"}, ids)
}

// TestHandleListKeys_StillDropsForeignStoreTypes is the bad-input companion:
// widening the filter must not turn it off. A key attributed to a different
// store type than the resolved backend's is still not that backend's key.
func TestHandleListKeys_StillDropsForeignStoreTypes(t *testing.T) {
	server, mockKS := createServerWithNamedBackend(t, "prod-hsm", types.BackendTypePKCS11)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "hsm-key", StoreType: types.StorePKCS11},
			{CN: "software-key", StoreType: types.StoreSoftware},
			{CN: "tpm-key", StoreType: types.StoreTPM2},
		}, nil
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys?backend=prod-hsm", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp ListKeysResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	require.Len(t, resp.Keys, 1)
	assert.Equal(t, "hsm-key", resp.Keys[0].KeyID)
}

// TestHandleUnwrapKey_WrappingPublicKeyIsOptional is the regression test for a
// mandatory field the operation does not consume.
//
// Unwrapping uses the private half of the wrapping key pair, which lives in the
// backend; the public half is an input to the wrap, not to its reverse. The
// service layer's UnwrapKey does not populate
// backend.ImportParameters.WrappingPublicKey at all, so requiring the field
// here rejected, with 400, requests the service accepts.
func TestHandleUnwrapKey_WrappingPublicKeyIsOptional(t *testing.T) {
	server, mockKS := createImportExportTestServer(t)
	defer xkms.Reset()

	var seen *backend.ImportParameters
	mockKS.importExportBackend.unwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
		seen = params
		return []byte("unwrapped-key-material"), nil
	}

	body, _ := json.Marshal(UnwrapKeyRequest{
		WrappedKey: []byte("wrapped-bytes"),
		Algorithm:  "RSAES_OAEP_SHA_256",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var resp UnwrapKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, []byte("unwrapped-key-material"), resp.KeyMaterial)

	require.NotNil(t, seen)
	assert.Nil(t, seen.WrappingPublicKey,
		"an unsupplied wrapping public key must reach the backend as absent, not as a zero value")
}

// TestHandleUnwrapKey_MalformedWrappingPublicKeyStillRefused is the bad-input
// companion: optional is not the same as ignored. A value that is supplied but
// cannot be parsed is refused rather than forwarded or silently dropped.
func TestHandleUnwrapKey_MalformedWrappingPublicKeyStillRefused(t *testing.T) {
	server, mockKS := createImportExportTestServer(t)
	defer xkms.Reset()

	called := false
	mockKS.importExportBackend.unwrapKeyFunc = func(wrapped *backend.WrappedKeyMaterial, params *backend.ImportParameters) ([]byte, error) {
		called = true
		return []byte("unwrapped-key-material"), nil
	}

	for _, badPEM := range []string{"not-a-pem", "-----BEGIN PUBLIC KEY-----\nZm9v\n-----END PUBLIC KEY-----\n"} {
		body, _ := json.Marshal(UnwrapKeyRequest{
			WrappedKey:           []byte("wrapped-bytes"),
			Algorithm:            "RSAES_OAEP_SHA_256",
			WrappingPublicKeyPEM: badPEM,
		})
		req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
		w := httptest.NewRecorder()
		server.handler.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Code, "PEM %q must be refused", badPEM)
	}
	assert.False(t, called, "a malformed wrapping key must not reach the backend")

	// A well-formed key is still forwarded.
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	require.NoError(t, err)
	goodPEM := string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))

	body, _ := json.Marshal(UnwrapKeyRequest{
		WrappedKey:           []byte("wrapped-bytes"),
		Algorithm:            "RSAES_OAEP_SHA_256",
		WrappingPublicKeyPEM: goodPEM,
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/test-key/unwrap?backend=software", bytes.NewReader(body))
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.True(t, called)
}

// TestHandleGenerateKey_SymmetricCipherNames pins the algorithm vocabulary this
// transport accepts for a symmetric key.
//
// It used to match the literal "symmetric" and nothing else, and then copy
// req.Algorithm verbatim into KeyAttributes.SymmetricAlgorithm -- so the
// spellings the service layer accepts ("aes-256-gcm", "chacha20-poly1305") were
// refused as unsupported algorithms, and the one spelling that did reach the
// branch failed its own IsValid check.
func TestHandleGenerateKey_SymmetricCipherNames(t *testing.T) {
	cases := []struct {
		algorithm string
		keySize   int
		expect    types.SymmetricAlgorithm
	}{
		{"aes-256-gcm", 0, types.SymmetricAES256GCM},
		{"aes256-gcm", 0, types.SymmetricAES256GCM},
		{"AES-128-GCM", 0, types.SymmetricAES128GCM},
		{"aes-192-gcm", 0, types.SymmetricAES192GCM},
		{"chacha20-poly1305", 0, types.SymmetricChaCha20Poly1305},
		{"xchacha20-poly1305", 0, types.SymmetricXChaCha20Poly1305},
		// The bare names carry no cipher, so the key size selects one.
		{"symmetric", 128, types.SymmetricAES128GCM},
		{"secret", 0, types.SymmetricAES256GCM},
	}

	for _, tc := range cases {
		t.Run(tc.algorithm, func(t *testing.T) {
			server, _, ext := createTestServerWithExtended(t)
			defer xkms.Reset()

			var generated *types.KeyAttributes
			ext.GenerateSymmetricKeyFunc = func(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
				generated = attrs
				return nil, nil
			}

			body, _ := json.Marshal(GenerateKeyRequest{
				KeyID:     "sym-" + tc.algorithm,
				Backend:   "software",
				Algorithm: tc.algorithm,
				KeySize:   tc.keySize,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)

			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())
			require.NotNil(t, generated)
			assert.Equal(t, tc.expect, generated.SymmetricAlgorithm)
			assert.Equal(t, types.KeyTypeSecret, generated.KeyType)
		})
	}
}

// TestHandleGenerateKey_UnknownAlgorithmStillRefused is the bad-input
// companion: widening the symmetric vocabulary must not turn the switch into a
// catch-all that accepts any string.
func TestHandleGenerateKey_UnknownAlgorithmStillRefused(t *testing.T) {
	for _, algorithm := range []string{"aes-512-gcm", "chacha", "rot13", "aes"} {
		t.Run(algorithm, func(t *testing.T) {
			server, _, ext := createTestServerWithExtended(t)
			defer xkms.Reset()

			called := false
			ext.GenerateSymmetricKeyFunc = func(attrs *types.KeyAttributes) (types.SymmetricKey, error) {
				called = true
				return nil, nil
			}

			body, _ := json.Marshal(GenerateKeyRequest{
				KeyID:     "bad-" + algorithm,
				Backend:   "software",
				Algorithm: algorithm,
			})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/keys", bytes.NewReader(body))
			w := httptest.NewRecorder()
			server.handler.ServeHTTP(w, req)

			assert.Equal(t, http.StatusBadRequest, w.Code)
			assert.False(t, called, "no key may be created for an algorithm nobody recognizes")
		})
	}
}
