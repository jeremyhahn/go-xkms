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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	backendmocks "github.com/jeremyhahn/go-xkms/pkg/backend/mocks"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================================
// capableKeyOpProvider is a types.KeyProvider that additionally implements
// types.AttestingKeyProvider and types.KeyAgreementProvider. It exists so the
// success-path tests below can prove a request actually reached a
// hardware-capable backend through the xkms service layer, rather than
// short-circuiting inside the transport handler.
// ============================================================================

type capableKeyOpProvider struct {
	*backendmocks.MockBackend

	attestResult interface{}
	attestErr    error
	attestNonce  []byte

	derivedKey     []byte
	deriveErr      error
	lastPeerPubKey []byte
	lastKDFParams  *types.KDFParams
}

func newCapableKeyOpProvider() *capableKeyOpProvider {
	return &capableKeyOpProvider{
		MockBackend: backendmocks.NewMockBackend(),
		derivedKey:  []byte("ecdh-derived-key-material"),
	}
}

// AttestKey implements types.AttestingKeyProvider.
func (p *capableKeyOpProvider) AttestKey(_ context.Context, _ *types.KeyAttributes, nonce []byte) (interface{}, error) {
	p.attestNonce = nonce
	if p.attestErr != nil {
		return nil, p.attestErr
	}
	return p.attestResult, nil
}

// DeriveKeyECDH implements types.KeyAgreementProvider.
func (p *capableKeyOpProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, peerPublicKey []byte, params *types.KDFParams) ([]byte, error) {
	p.lastPeerPubKey = peerPublicKey
	p.lastKDFParams = params
	if p.deriveErr != nil {
		return nil, p.deriveErr
	}
	return p.derivedKey, nil
}

// SupportedCurves implements types.KeyAgreementProvider.
func (p *capableKeyOpProvider) SupportedCurves() []string { return []string{"P-256"} }

var (
	_ types.AttestingKeyProvider = (*capableKeyOpProvider)(nil)
	_ types.KeyAgreementProvider = (*capableKeyOpProvider)(nil)
)

// createTestServerWithHardwareBackend registers a "hardware" backend backed
// by capableKeyOpProvider (attestation + ECDH capable) alongside the
// capability-free "software" default, so tests can exercise both the success
// path and the capability-boundary path against real routing.
func createTestServerWithHardwareBackend(t *testing.T) (*Server, *capableKeyOpProvider) {
	t.Helper()
	xkms.Reset()

	software := xkmsmocks.NewMockKeyStore()

	provider := newCapableKeyOpProvider()
	hardware, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": software,
			"hardware": hardware,
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

	return server, provider
}

// keyOpTestCert generates a self-signed certificate for use in attestation
// certificate chains.
func keyOpTestCert(t *testing.T) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "attesting-key"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

func postJSON(t *testing.T, server *Server, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reader *bytes.Reader
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(data)
	} else {
		reader = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(http.MethodPost, path, reader)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)
	return w
}

// ============================================================================
// AttestKey — POST /api/v1/attest
// ============================================================================

func TestHandleAttestKey_Success(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	cert := keyOpTestCert(t)
	provider.attestResult = &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestationData:    []byte("TPM2_Certify"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "idevid"}}, nil
	}

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware",
		KeyID:   "idevid",
		Nonce:   []byte("challenge"),
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.AttestKeyResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "tpm2", resp.Format)
	assert.Equal(t, "tpm2", resp.Backend)
	assert.Equal(t, []byte("TPM2_Certify"), resp.AttestationData)
	assert.Equal(t, []byte("sig"), resp.Signature)
	assert.Equal(t, x509.ECDSAWithSHA256.String(), resp.SignatureAlgorithm)
	require.Len(t, resp.CertificateChain, 1)
	assert.Equal(t, cert.Raw, resp.CertificateChain[0])
	assert.Equal(t, []byte("challenge"), provider.attestNonce)
}

func TestHandleAttestKey_BackendLacksCapability(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "idevid",
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleAttestKey_ValidationError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// Backend is required and is missing.
	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		KeyID: "idevid",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleAttestKey_AuthorizationDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "idevid",
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "get", rbac.lastAction)
}

// ============================================================================
// DeriveKeyECDH — POST /api/v1/keys/derive-ecdh
// ============================================================================

func TestHandleDeriveKeyECDH_Success(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	provider.derivedKey = []byte("derived-symmetric-key")
	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA}}, nil
	}

	w := postJSON(t, server, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hardware",
		PeerPublicKey: []byte("peer-public-key-bytes"),
		KeyLength:     32,
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.DeriveKeyECDHResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, []byte("derived-symmetric-key"), resp.DerivedKey)
	assert.Equal(t, []byte("peer-public-key-bytes"), provider.lastPeerPubKey)
	require.NotNil(t, provider.lastKDFParams)
	assert.Equal(t, 32, provider.lastKDFParams.KeyLength)
}

func TestHandleDeriveKeyECDH_BackendLacksCapability(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "some-key",
		Backend:       "software",
		PeerPublicKey: []byte("peer"),
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleDeriveKeyECDH_ValidationError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// key_id is required and is missing.
	w := postJSON(t, server, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		Backend:       "software",
		PeerPublicKey: []byte("peer"),
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleDeriveKeyECDH_AuthorizationDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "some-key",
		Backend:       "software",
		PeerPublicKey: []byte("peer"),
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "derive", rbac.lastAction)
}

// ============================================================================
// WrapKeyByID — POST /api/v1/keys/wrap-by-id
// ============================================================================

// TestHandleWrapKeyByID_Success proves a wrap over this transport produces a
// real RSA-OAEP ciphertext under the caller's own designated wrapping key.
//
// The oracle is rsa.DecryptOAEP with the KEK's private half: it must recover
// exactly the target key's material. The response used to be asserted equal to
// that material in the clear, which the identity "wrap" of the old import
// ceremony satisfied -- a test that a real wrap would have failed.
//
// The algorithm name is the canonical suite name published in this API's
// documentation. Sending it used to fail outright with "unsupported wrap
// algorithm: RSAES_OAEP_SHA_256", because the name was passed straight into a
// dispatcher that only understood the lowercase PKCS#11 mechanism vocabulary.
func TestHandleWrapKeyByID_Success(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	kekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	targetMaterial := []byte("0123456789abcdef0123456789abcdef")
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "target-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true},
			{CN: "kek", KeyAlgorithm: x509.RSA},
		}, nil
	}

	// The fixture gets its own copy: the service wipes the exported plaintext
	// with secure.Wipe once it has wrapped it, and every production backend
	// hands out a defensive copy rather than its stored slice. Storing the
	// test's own array here would have it zeroed mid-call, so the assertions
	// below would compare the recovered key against thirty-two zero bytes.
	storedMaterial := make([]byte, len(targetMaterial))
	copy(storedMaterial, targetMaterial)
	ext.StoreSymmetricKey("target-key", storedMaterial)
	mockKS.SetKey("kek", kekPriv)

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.WrapKeyByIDResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)
	assert.NotEqual(t, targetMaterial, resp.WrappedKey, "the key must be wrapped, not returned in the clear")

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, kekPriv, resp.WrappedKey, nil)
	require.NoError(t, err)
	assert.Equal(t, targetMaterial, recovered)
}

// TestHandleWrapKeyByID_UnsupportedAlgorithm proves an algorithm name from
// neither accepted vocabulary is refused rather than mapped onto a default.
func TestHandleWrapKeyByID_UnsupportedAlgorithm(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	kekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "target-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true},
			{CN: "kek", KeyAlgorithm: x509.RSA},
		}, nil
	}
	ext.StoreSymmetricKey("target-key", []byte("0123456789abcdef0123456789abcdef"))
	mockKS.SetKey("kek", kekPriv)

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA3_256",
	})

	// An unrecognized algorithm is a bad request field, so it is reported as
	// 400 with the offending name echoed back rather than silently mapped
	// onto a supported default.
	//
	// The example used to be RSAES_OAEP_SHA_512, which is now a supported
	// algorithm: the PKCS#11 module encodes the caller's OAEP digest into the
	// algorithm name, so SHA-384 and SHA-512 became selectable. A test for
	// unsupported input has to name something actually unsupported, or it
	// stops testing the rejection path the moment the vocabulary grows.
	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), "RSAES_OAEP_SHA3_256")
}

func TestHandleWrapKeyByID_BackendLacksCapability(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleWrapKeyByID_ValidationError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// wrapping_key_id is required and is missing.
	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleWrapKeyByID_AuthorizationDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "wrap", rbac.lastAction)
}

// TestHandleWrapKeyByID_RoutingNotSwallowedByKeyOperations proves the
// dedicated "/api/v1/keys/wrap-by-id" mux pattern is reached directly and is
// not swallowed by handleKeyOperations treating "wrap-by-id" as a key ID
// (which, for a POST with no matching sub-operation, would return 405
// without ever calling the authorizer).
func TestHandleWrapKeyByID_RoutingNotSwallowedByKeyOperations(t *testing.T) {
	rbac := &recordingRBAC{deny: false}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "operator@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	require.NotNil(t, rbac.lastIdentity, "authorize was never called: request was not routed to handleWrapKeyByID")
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "wrap", rbac.lastAction)
	assert.NotEqual(t, http.StatusMethodNotAllowed, w.Code)
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

// ============================================================================
// UnwrapKeyByID — POST /api/v1/keys/unwrap-by-id
// ============================================================================

// TestHandleUnwrapKeyByID_Success proves an unwrap over this transport
// decrypts with the caller's own designated unwrapping key and imports the
// recovered material into the target backend.
//
// WrappedKey is a genuine RSA-OAEP ciphertext built here, independently of the
// server, so a handler that unwrapped with anything other than the named key
// could not produce the right plaintext. The oracle is the material that
// actually reached the target backend's import ceremony: it must decrypt back
// to the plaintext that was wrapped.
func TestHandleUnwrapKeyByID_Success(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	kekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// The target backend's import ceremony wraps under a key it generates.
	// Pin that key here, and make the ceremony perform a real OAEP wrap, so
	// the blob that reaches ImportKey can be opened and checked.
	importPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	ext.GetImportParametersFunc = func(attrs *types.KeyAttributes, alg backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
		return &backend.ImportParameters{
			WrappingPublicKey: &importPriv.PublicKey,
			Algorithm:         alg,
			ImportToken:       []byte("test-import-token"),
		}, nil
	}
	ext.WrapKeyFunc = func(material []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
		pub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("import parameters carry no RSA wrapping key")
		}
		blob, wrapErr := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, material, nil)
		if wrapErr != nil {
			return nil, wrapErr
		}
		return &backend.WrappedKeyMaterial{
			WrappedKey:  blob,
			Algorithm:   params.Algorithm,
			ImportToken: params.ImportToken,
		}, nil
	}

	var importedBlob []byte
	ext.ImportKeyFunc = func(attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
		importedBlob = wrapped.WrappedKey
		return nil
	}

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "kek", KeyAlgorithm: x509.RSA}}, nil
	}
	mockKS.SetKey("kek", kekPriv)

	plaintext := []byte("0123456789abcdef0123456789abcdef")
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &kekPriv.PublicKey, plaintext, nil)
	require.NoError(t, err)

	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapped,
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.UnwrapKeyByIDResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, "new-key", resp.KeyID)
	assert.Equal(t, "software", resp.Backend)
	assert.True(t, resp.Success)
	require.NotEmpty(t, ext.ImportKeyCalls)
	require.NotNil(t, importedBlob, "unwrapped material must reach the target backend's import ceremony")
	assert.NotEqual(t, plaintext, importedBlob, "the material must be re-wrapped for import, not imported in the clear")

	recovered, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, importPriv, importedBlob, nil)
	require.NoError(t, err)
	assert.Equal(t, plaintext, recovered,
		"the imported material must be exactly the key the caller wrapped")
}

// TestHandleUnwrapKeyByID_WrongUnwrappingKey proves the unwrap really is
// performed with the named key: a ciphertext produced under a different RSA
// key must fail rather than yield some other plaintext.
func TestHandleUnwrapKeyByID_WrongUnwrappingKey(t *testing.T) {
	server, mockKS, _ := createTestServerWithExtended(t)
	defer xkms.Reset()

	kekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "kek", KeyAlgorithm: x509.RSA}}, nil
	}
	mockKS.SetKey("kek", kekPriv)

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, &otherPriv.PublicKey, []byte("secret"), nil)
	require.NoError(t, err)

	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           wrapped,
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Contains(t, w.Body.String(), "unwrap")
}

func TestHandleUnwrapKeyByID_BackendLacksCapability(t *testing.T) {
	server, mockKS := createTestServer(t)
	defer xkms.Reset()

	kekPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "kek", KeyAlgorithm: x509.RSA}}, nil
	}
	mockKS.SetKey("kek", kekPriv)

	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-material"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	// The plain MockKeyStore's KeyProvider is not an ImportExportBackend, so
	// the target cannot accept an import. That boundary is reported before any
	// decryption is attempted.
	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleUnwrapKeyByID_ValidationError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// wrapped_key is required and is missing.
	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES_KEY_WRAP",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleUnwrapKeyByID_AuthorizationDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-material"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES_KEY_WRAP",
		TargetKeyID:          "new-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	assert.Equal(t, http.StatusForbidden, w.Code)
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "unwrap", rbac.lastAction)
}

// ============================================================================
// ExportKeyMaterial — POST /api/v1/keys/{keyID}/export-material
// ============================================================================

func TestHandleExportKeyMaterial_Success(t *testing.T) {
	server, mockKS, ext := createTestServerWithExtended(t)
	defer xkms.Reset()

	material := []byte("0123456789abcdef0123456789abcdef")
	mockKS.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{
			{CN: "sym-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true},
		}, nil
	}
	ext.StoreSymmetricKey("sym-key", material)

	w := postJSON(t, server, "/api/v1/keys/sym-key/export-material?backend=software", nil)

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.ExportKeyMaterialResponse
	require.NoError(t, json.NewDecoder(w.Body).Decode(&resp))
	assert.Equal(t, material, resp.KeyMaterial)
	assert.Equal(t, string(types.SymmetricAES256GCM), resp.KeyType)
	assert.Equal(t, types.SymmetricAES256GCM.KeySize(), resp.KeySize)
}

func TestHandleExportKeyMaterial_BackendLacksCapability(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/sym-key/export-material?backend=software", nil)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestHandleExportKeyMaterial_ValidationError(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	// No backend query parameter supplied.
	w := postJSON(t, server, "/api/v1/keys/sym-key/export-material", nil)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestHandleExportKeyMaterial_AuthorizationDenied(t *testing.T) {
	rbac := &recordingRBAC{deny: true}
	logger := &mockAuditLogger{}
	identity := &auth.Identity{Subject: "viewer@example.com"}
	server, _ := createAuthzTestServer(t, auth.NewAuthorizer(rbac), logger, identity)
	defer xkms.Reset()

	w := postJSON(t, server, "/api/v1/keys/sym-key/export-material?backend=software", nil)

	assert.Equal(t, http.StatusForbidden, w.Code)
	require.NotNil(t, rbac.lastIdentity)
	assert.Equal(t, "keys", rbac.lastResource)
	assert.Equal(t, "export", rbac.lastAction)
}

// ============================================================================
// Method-not-allowed guards
// ============================================================================

func TestHandleAttestKey_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/attest", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleDeriveKeyECDH_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/derive-ecdh", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleWrapKeyByID_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/wrap-by-id", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleUnwrapKeyByID_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/unwrap-by-id", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

func TestHandleExportKeyMaterial_MethodNotAllowed(t *testing.T) {
	server, _ := createTestServer(t)
	defer xkms.Reset()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys/sym-key/export-material?backend=software", nil)
	w := httptest.NewRecorder()
	server.handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusMethodNotAllowed, w.Code)
}

// ============================================================================
// Nil xkmsService guards (NewServer refuses a nil XKMSService, so these use
// createNilSvcServer from handlers_gap_test.go to bypass that validation and
// exercise the handler-level guard directly).
// ============================================================================

func TestHandleAttestKey_NilService(t *testing.T) {
	server := createNilSvcServer(t)

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "k",
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleDeriveKeyECDH_NilService(t *testing.T) {
	server := createNilSvcServer(t)

	w := postJSON(t, server, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "k",
		Backend:       "software",
		PeerPublicKey: []byte("p"),
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleWrapKeyByID_NilService(t *testing.T) {
	server := createNilSvcServer(t)

	w := postJSON(t, server, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleUnwrapKeyByID_NilService(t *testing.T) {
	server := createNilSvcServer(t)

	w := postJSON(t, server, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("w"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "AES_KEY_WRAP",
		TargetKeyID:          "new",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestHandleExportKeyMaterial_NilService(t *testing.T) {
	server := createNilSvcServer(t)

	w := postJSON(t, server, "/api/v1/keys/sym-key/export-material", nil)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

// ============================================================================
// sendKeyOpError additional branch coverage: role-lookup (404) and an
// unmapped sentinel falling through to the internal (500) default.
// ============================================================================

func TestHandleAttestKey_KeyNotFound(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return nil, nil
	}

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware",
		KeyID:   "missing",
	})

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestHandleAttestKey_BackendFailureIsInternal(t *testing.T) {
	server, provider := createTestServerWithHardwareBackend(t)
	defer xkms.Reset()

	provider.attestErr = errors.New("TPM_RC_POLICY_FAIL")
	provider.ListKeysFunc = func() ([]*types.KeyAttributes, error) {
		return []*types.KeyAttributes{{CN: "idevid"}}, nil
	}

	w := postJSON(t, server, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware",
		KeyID:   "idevid",
	})

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
