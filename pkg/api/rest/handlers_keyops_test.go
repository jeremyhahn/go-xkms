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
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// capableKeyProvider carries every hardware capability the key operation
// handlers depend on (backend.ImportExportBackend, types.AttestingKeyProvider,
// types.KeyAgreementProvider). Only a provider that implements the capability
// interfaces can distinguish "the handler reached a real backend through the
// xkms service layer" from "the handler short-circuited", which is what these
// tests exist to prove.
// ===========================================================================

type capableKeyProvider struct {
	keys map[string]*types.KeyAttributes

	// wrappingKey is a stable RSA key returned by GetKey and Decrypter.
	// C_WrapKey/C_UnwrapKey resolve the caller's designated wrapping key
	// through those seams and perform real RSA-OAEP, so a provider minting a
	// fresh ECDSA key per call could neither satisfy the algorithm nor
	// round-trip.
	wrappingKey *rsa.PrivateKey

	exportedMaterial []byte
	exportErr        error
	unwrapped        []byte
	imported         map[string]*backend.WrappedKeyMaterial

	attestation interface{}
	attestErr   error

	derivedKey []byte
	deriveErr  error
}

func newCapableKeyProvider() *capableKeyProvider {
	return &capableKeyProvider{
		keys:             make(map[string]*types.KeyAttributes),
		imported:         make(map[string]*backend.WrappedKeyMaterial),
		exportedMaterial: []byte("raw-symmetric-key-material-32b!!"),
		unwrapped:        []byte("recovered-key-material"),
		derivedKey:       []byte("ecdh-derived-key"),
	}
}

func (p *capableKeyProvider) addKey(attrs *types.KeyAttributes) { p.keys[attrs.CN] = attrs }

func (p *capableKeyProvider) Type() types.BackendType { return "capable" }

func (p *capableKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true, Export: true}
}

func (p *capableKeyProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

func (p *capableKeyProvider) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if _, ok := p.keys[attrs.CN]; !ok {
		return nil, errors.New("key not found")
	}
	return p.rsaWrappingKey()
}

// rsaWrappingKey lazily creates and returns the provider's stable RSA key.
func (p *capableKeyProvider) rsaWrappingKey() (*rsa.PrivateKey, error) {
	if p.wrappingKey == nil {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		p.wrappingKey = key
	}
	return p.wrappingKey, nil
}

func (p *capableKeyProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	delete(p.keys, attrs.CN)
	return nil
}

func (p *capableKeyProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}

func (p *capableKeyProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}

func (p *capableKeyProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.rsaWrappingKey()
}

func (p *capableKeyProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }

func (p *capableKeyProvider) Close() error { return nil }

// backend.ImportExportBackend

func (p *capableKeyProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{Algorithm: algorithm, ImportToken: []byte("token")}, nil
}

func (p *capableKeyProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{
		WrappedKey: append([]byte("wrapped:"), keyMaterial...),
		Algorithm:  params.Algorithm,
	}, nil
}

func (p *capableKeyProvider) UnwrapKey(_ context.Context, _ *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return p.unwrapped, nil
}

func (p *capableKeyProvider) ImportKey(_ context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	p.imported[attrs.CN] = wrapped
	return nil
}

func (p *capableKeyProvider) ExportKey(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported"), Algorithm: algorithm}, nil
}

func (p *capableKeyProvider) ExportKeyTo(_ context.Context, _ *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("exported"),
		Algorithm:   dstParams.Algorithm,
		ImportToken: dstParams.ImportToken,
	}, nil
}

func (p *capableKeyProvider) ExportKeyMaterial(_ context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if p.exportErr != nil {
		return nil, p.exportErr
	}
	// Material is derived from the resolved attributes when they name a
	// tenant, so a test can tell which tenant's key the service actually
	// reached rather than merely that some key was reached.
	material := p.exportedMaterial
	if attrs != nil && attrs.TenantID != "" {
		material = []byte("key-material-for-" + attrs.TenantID)
	}
	// Return a copy, as a real backend does: the wrap-by-id handler zeroizes
	// the plaintext material after wrapping, and it must not reach back into
	// the provider's own buffer (or this fixture's expected value).
	out := make([]byte, len(material))
	copy(out, material)
	return out, nil
}

// types.AttestingKeyProvider

func (p *capableKeyProvider) AttestKey(_ context.Context, _ *types.KeyAttributes, _ []byte) (interface{}, error) {
	if p.attestErr != nil {
		return nil, p.attestErr
	}
	return p.attestation, nil
}

// types.KeyAgreementProvider

func (p *capableKeyProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, _ []byte, _ *types.KDFParams) ([]byte, error) {
	if p.deriveErr != nil {
		return nil, p.deriveErr
	}
	return p.derivedKey, nil
}

func (p *capableKeyProvider) SupportedCurves() []string { return []string{"P-256"} }

var (
	_ backend.ImportExportBackend = (*capableKeyProvider)(nil)
	_ types.AttestingKeyProvider  = (*capableKeyProvider)(nil)
	_ types.KeyAgreementProvider  = (*capableKeyProvider)(nil)
)

// bareKeyProvider carries no hardware capability at all, so it proves the
// capability-boundary (501) path of every handler under test.
type bareKeyProvider struct {
	keys map[string]*types.KeyAttributes
}

func newBareKeyProvider() types.KeyProvider {
	return &bareKeyProvider{keys: make(map[string]*types.KeyAttributes)}
}

func (p *bareKeyProvider) Type() types.BackendType          { return "bare" }
func (p *bareKeyProvider) Capabilities() types.Capabilities { return types.Capabilities{Keys: true} }
func (p *bareKeyProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.keys[attrs.CN] = attrs
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}
func (p *bareKeyProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("key not found")
}
func (p *bareKeyProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareKeyProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	attrs := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		attrs = append(attrs, a)
	}
	return attrs, nil
}
func (p *bareKeyProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("not supported")
}
func (p *bareKeyProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("not supported")
}
func (p *bareKeyProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *bareKeyProvider) Close() error                                              { return nil }

// setupKeyOpsHandlerContext wires a real *xkms.XKMSService with two backends:
// "hardware" (capableKeyProvider, exercises the success paths) and "software"
// (bareKeyProvider, exercises the capability-boundary/501 paths), then
// injects the service into a fresh HandlerContext exactly as production
// wiring does via HandlerContext.SetXKMSService.
func setupKeyOpsHandlerContext(t *testing.T) (*HandlerContext, *capableKeyProvider) {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	provider := newCapableKeyProvider()
	hardware, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	software, err := xkms.New(&xkms.BackendConfig{Backend: newBareKeyProvider(), CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"hardware": hardware, "software": software},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	h := NewHandlerContext("1.0.0")
	h.SetXKMSService(svc)
	return h, provider
}

func keyOpsTestCert(t *testing.T) *x509.Certificate {
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

func doJSONRequest(t *testing.T, handler http.HandlerFunc, method, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}
	req := httptest.NewRequest(method, path, reqBody)
	w := httptest.NewRecorder()
	handler(w, req)
	return w
}

// ===========================================================================
// AttestKeyHandler
// ===========================================================================

func TestAttestKeyHandler_Success(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	cert := keyOpsTestCert(t)
	provider.attestation = &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   []*x509.Certificate{cert},
		AttestationData:    []byte("TPM2_Certify"),
		Signature:          []byte("sig"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
	provider.addKey(&types.KeyAttributes{CN: "idevid", KeyAlgorithm: x509.ECDSA})

	w := doJSONRequest(t, h.AttestKeyHandler, http.MethodPost, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware",
		KeyID:   "idevid",
		Nonce:   []byte("challenge"),
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.AttestKeyResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, "tpm2", resp.Format)
	assert.Equal(t, "tpm2", resp.Backend)
	assert.Equal(t, []byte("TPM2_Certify"), resp.AttestationData)
	assert.Equal(t, []byte("sig"), resp.Signature)
	require.Len(t, resp.CertificateChain, 1)
	assert.Equal(t, cert.Raw, resp.CertificateChain[0])
}

func TestAttestKeyHandler_BackendLacksCapability(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.AttestKeyHandler, http.MethodPost, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "software",
		KeyID:   "idevid",
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestAttestKeyHandler_ValidationError(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.AttestKeyHandler, http.MethodPost, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware",
		// KeyID intentionally omitted.
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestKeyHandler_NotInitialized(t *testing.T) {
	h := NewHandlerContext("1.0.0")

	w := doJSONRequest(t, h.AttestKeyHandler, http.MethodPost, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware", KeyID: "idevid",
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestAttestKeyHandler_InvalidJSON(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/attest", bytes.NewBufferString("{not json"))
	w := httptest.NewRecorder()
	h.AttestKeyHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestAttestKeyHandler_RBACDenied(t *testing.T) {
	requireRBACDenied(t, http.MethodPost, "/api/v1/attest", &transport.AttestKeyRequest{
		Backend: "hardware", KeyID: "idevid",
	})
}

// ===========================================================================
// DeriveKeyECDHHandler
// ===========================================================================

func TestDeriveKeyECDHHandler_Success(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.addKey(&types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})

	w := doJSONRequest(t, h.DeriveKeyECDHHandler, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hardware",
		PeerPublicKey: []byte("peer"),
		KDFAlgorithm:  "HKDF",
		KDFHash:       "SHA-256",
		KeyLength:     32,
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.DeriveKeyECDHResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, provider.derivedKey, resp.DerivedKey)
}

func TestDeriveKeyECDHHandler_BackendLacksCapability(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.DeriveKeyECDHHandler, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "some-key",
		Backend:       "software",
		PeerPublicKey: []byte("peer"),
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestDeriveKeyECDHHandler_ValidationError(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.DeriveKeyECDHHandler, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:   "ecdh-key",
		Backend: "hardware",
		// PeerPublicKey intentionally omitted.
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestDeriveKeyECDHHandler_KeyLengthExceedsMaximum proves an oversized
// key_length surfaces as 400 Bad Request rather than the 500 Internal Server
// Error every DeriveKeyECDH backend's own KDF validation failure fell to
// before this fix wrapped it as request validation (go-xkms#1259).
func TestDeriveKeyECDHHandler_KeyLengthExceedsMaximum(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.DeriveKeyECDHHandler, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hardware",
		PeerPublicKey: []byte("peer"),
		KeyLength:     types.MaxDerivedKeyLength + 1,
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeriveKeyECDHHandler_NotInitialized(t *testing.T) {
	h := NewHandlerContext("1.0.0")

	w := doJSONRequest(t, h.DeriveKeyECDHHandler, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID: "ecdh-key", Backend: "hardware", PeerPublicKey: []byte("peer"),
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestDeriveKeyECDHHandler_InvalidJSON(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/derive-ecdh", bytes.NewBufferString("{not json"))
	w := httptest.NewRecorder()
	h.DeriveKeyECDHHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestDeriveKeyECDHHandler_RBACDenied(t *testing.T) {
	requireRBACDenied(t, http.MethodPost, "/api/v1/keys/derive-ecdh", &transport.DeriveKeyECDHRequest{
		KeyID: "ecdh-key", Backend: "hardware", PeerPublicKey: []byte("peer"),
	})
}

// ===========================================================================
// ExportKeyMaterialHandler
// ===========================================================================

func TestExportKeyMaterialHandler_Success(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.addKey(&types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export-material", h.ExportKeyMaterialHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/aes-key/export-material?backend=hardware", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.ExportKeyMaterialResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.Equal(t, provider.exportedMaterial, resp.KeyMaterial)
	assert.Equal(t, string(types.SymmetricAES256GCM), resp.KeyType)
	assert.NotZero(t, resp.KeySize)
}

func TestExportKeyMaterialHandler_BackendLacksCapability(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export-material", h.ExportKeyMaterialHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/aes-key/export-material?backend=software", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestExportKeyMaterialHandler_MissingBackend(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export-material", h.ExportKeyMaterialHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/aes-key/export-material", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), ErrMissingBackend.Error())
}

func TestExportKeyMaterialHandler_MissingKeyID(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys//export-material?backend=hardware", nil)
	w := httptest.NewRecorder()
	h.ExportKeyMaterialHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
	assert.Contains(t, w.Body.String(), ErrMissingKeyID.Error())
}

func TestExportKeyMaterialHandler_NotInitialized(t *testing.T) {
	h := NewHandlerContext("1.0.0")

	router := createRouterWithHandler(http.MethodPost, "/api/v1/keys/{id}/export-material", h.ExportKeyMaterialHandler)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/aes-key/export-material?backend=hardware", nil)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestExportKeyMaterialHandler_RBACDenied(t *testing.T) {
	requireRBACDenied(t, http.MethodPost, "/api/v1/keys/aes-key/export-material?backend=hardware", nil)
}

// ===========================================================================
// WrapKeyByIDHandler
// ===========================================================================

func TestWrapKeyByIDHandler_Success(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.addKey(&types.KeyAttributes{
		CN: "target-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true,
	})
	provider.addKey(&types.KeyAttributes{CN: "kek"})

	w := doJSONRequest(t, h.WrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "hardware",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "hardware",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.WrapKeyByIDResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	// A real RSA-OAEP wrap, not the import ceremony's canned marker.
	assert.Len(t, resp.WrappedKey, 256, "RSA-2048 OAEP output is one modulus block")
	assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)

	wrappingKey, keyErr := provider.rsaWrappingKey()
	require.NoError(t, keyErr)
	recovered, decErr := wrappingKey.Decrypt(rand.Reader, resp.WrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, decErr, "the blob must decrypt under the designated wrapping key")
	assert.Equal(t, provider.exportedMaterial, recovered)
}

func TestWrapKeyByIDHandler_BackendLacksCapability(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.WrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestWrapKeyByIDHandler_ValidationError(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.WrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		// WrappingKeyID intentionally omitted.
		WrappingKeyBackend: "hardware",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "hardware",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWrapKeyByIDHandler_NotInitialized(t *testing.T) {
	h := NewHandlerContext("1.0.0")

	w := doJSONRequest(t, h.WrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID: "kek", WrappingKeyBackend: "hardware",
		TargetKeyID: "target-key", TargetKeyBackend: "hardware",
		Algorithm: "RSAES_OAEP_SHA_256",
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestWrapKeyByIDHandler_InvalidJSON(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/wrap-by-id", bytes.NewBufferString("{not json"))
	w := httptest.NewRecorder()
	h.WrapKeyByIDHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestWrapKeyByIDHandler_RBACDenied(t *testing.T) {
	requireRBACDenied(t, http.MethodPost, "/api/v1/keys/wrap-by-id", &transport.WrapKeyByIDRequest{
		WrappingKeyID: "kek", WrappingKeyBackend: "hardware",
		TargetKeyID: "target-key", TargetKeyBackend: "hardware",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
}

// ===========================================================================
// UnwrapKeyByIDHandler
// ===========================================================================

func TestUnwrapKeyByIDHandler_Success(t *testing.T) {
	h, provider := setupKeyOpsHandlerContext(t)
	provider.addKey(&types.KeyAttributes{CN: "kek"})

	// A genuine RSA-OAEP blob under the designated unwrapping key. The literal
	// "wrapped-blob" only worked while the service routed through the import
	// ceremony and never actually decrypted.
	wrappingKey, keyErr := provider.rsaWrappingKey()
	require.NoError(t, keyErr)
	const material = "unwrapped-key-material"
	realBlob, wrapErr := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader,
		&wrappingKey.PublicKey, []byte(material), nil)
	require.NoError(t, wrapErr)

	w := doJSONRequest(t, h.UnwrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           realBlob,
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "hardware",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "imported-key",
		TargetKeyBackend:     "hardware",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	require.Equal(t, http.StatusOK, w.Code)
	var resp transport.UnwrapKeyByIDResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyID)
	assert.Equal(t, "hardware", resp.Backend)

	imported, ok := provider.imported["imported-key"]
	require.True(t, ok, "the unwrapped key must be imported into the target backend")
	// "wrapped:" is the fake importer's own marker; the suffix is what the
	// blob genuinely decrypted to.
	assert.Equal(t, append([]byte("wrapped:"), []byte(material)...), imported.WrappedKey)
}

func TestUnwrapKeyByIDHandler_BackendLacksCapability(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.UnwrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-blob"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "software",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "imported-key",
		TargetKeyBackend:     "software",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	})

	assert.Equal(t, http.StatusNotImplemented, w.Code)
}

func TestUnwrapKeyByIDHandler_ValidationError(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	w := doJSONRequest(t, h.UnwrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		// WrappedKey intentionally omitted.
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "hardware",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "imported-key",
		TargetKeyBackend:     "hardware",
	})

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUnwrapKeyByIDHandler_NotInitialized(t *testing.T) {
	h := NewHandlerContext("1.0.0")

	w := doJSONRequest(t, h.UnwrapKeyByIDHandler, http.MethodPost, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey: []byte("wrapped-blob"), UnwrappingKeyID: "kek", UnwrappingKeyBackend: "hardware",
		Algorithm: "RSAES_OAEP_SHA_256", TargetKeyID: "imported-key", TargetKeyBackend: "hardware",
	})

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}

func TestUnwrapKeyByIDHandler_InvalidJSON(t *testing.T) {
	h, _ := setupKeyOpsHandlerContext(t)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/keys/unwrap-by-id", bytes.NewBufferString("{not json"))
	w := httptest.NewRecorder()
	h.UnwrapKeyByIDHandler(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestUnwrapKeyByIDHandler_RBACDenied(t *testing.T) {
	requireRBACDenied(t, http.MethodPost, "/api/v1/keys/unwrap-by-id", &transport.UnwrapKeyByIDRequest{
		WrappedKey: []byte("wrapped-blob"), UnwrappingKeyID: "kek", UnwrappingKeyBackend: "hardware",
		Algorithm: "RSAES_OAEP_SHA_256", TargetKeyID: "imported-key", TargetKeyBackend: "hardware",
	})
}

// ===========================================================================
// RBAC denial harness
//
// denyingRBACClient implements qrdbtransport.RBACClient and refuses every
// permission check, proving the RequirePermission decorator is actually
// attached to the new routes (as opposed to a test that calls the handler
// method directly, bypassing the router and its middleware chain).
// ===========================================================================

type denyingRBACClient struct{}

func (denyingRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, _, _ string) error {
	return errors.New("permission denied")
}

func (denyingRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("permission denied")
}

func (d denyingRBACClient) ListOwnPermissions(ctx context.Context) ([]qrdbtransport.PermissionInfo, error) {
	return d.ListPermissions(ctx, nil)
}

// requireRBACDenied builds a full REST server with RBAC enabled and a
// denying RBACClient, drives the given request through the real chi router
// (not a bare handler call), and asserts the RequirePermission decorator
// rejected it with 403 before the handler ever ran.
func requireRBACDenied(t *testing.T, method, path string, body interface{}) {
	t.Helper()

	ks := newMockKeyStore()
	cfg := &Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": ks},
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(denyingRBACClient{}),
	}

	server, err := NewServer(cfg)
	require.NoError(t, err)

	var reqBody *bytes.Buffer
	if body != nil {
		data, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewBuffer(data)
	} else {
		reqBody = bytes.NewBuffer(nil)
	}

	req := httptest.NewRequest(method, path, reqBody)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// ===========================================================================
// mapKeyOpError
//
// A direct unit test over the sentinel table, mirroring
// pkg/api/grpc/errors_keyops_test.go's TestMapKeyOpError so both transports'
// error-mapping tables stay honest independent of any one handler's
// call path.
// ===========================================================================

func TestMapKeyOpError(t *testing.T) {
	tests := []struct {
		name       string
		err        error
		wantStatus int
	}{
		{
			name:       "not leader is misdirected request",
			err:        &qrdbtransport.NotLeaderError{ShardID: 1, LeaderID: 2, LeaderAddress: "10.0.0.1:8443"},
			wantStatus: http.StatusMisdirectedRequest,
		},
		{
			name:       "role lookup keeps the participant name",
			err:        &xkms.ErrRoleLookup{Role: "target key backend", Name: "hsm", Err: xkms.ErrBackendNotFound},
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "validation reports the field verbatim",
			err:        &xkms.ErrValidation{Sentinel: xkms.ErrMissingRequiredField, Detail: "key_id is required"},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "validation without detail falls back to the sentinel",
			err:        &xkms.ErrValidation{Sentinel: xkms.ErrMissingRequiredField},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "unsupported capability",
			err:        &xkms.ErrBackendUnsupported{Sentinel: xkms.ErrOperationNotSupported, Backend: "software", Detail: "does not support attestation"},
			wantStatus: http.StatusNotImplemented,
		},
		{
			name:       "non-exportable key",
			err:        &xkms.ErrOperationWrap{Sentinel: xkms.ErrExportKeyMaterialFailed, Err: errors.New("not extractable")},
			wantStatus: http.StatusPreconditionFailed,
		},
		{
			name:       "backend not found",
			err:        xkms.ErrBackendNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "bare key not found",
			err:        xkms.ErrKeyNotFound,
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "service not initialized",
			err:        xkms.ErrNotInitialized,
			wantStatus: http.StatusServiceUnavailable,
		},
		{
			name:       "malformed backend name is a bad request",
			err:        &xkms.ErrBackendNameValidation{Err: errors.New("contains '/'")},
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "wrapped key-not-exportable cause is forbidden",
			err:        &xkms.ErrOperationWrap{Sentinel: xkms.ErrOperationFailed, Err: backend.ErrKeyNotExportable},
			wantStatus: http.StatusForbidden,
		},
		{
			name:       "wrapped existing destination key is a conflict",
			err:        &xkms.ErrKeyOperation{Operation: "import key", Err: storage.ErrAlreadyExists},
			wantStatus: http.StatusConflict,
		},
		{
			name:       "anything else is internal",
			err:        errors.New("disk on fire"),
			wantStatus: http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			mapKeyOpError(w, tt.err)
			assert.Equal(t, tt.wantStatus, w.Code)
		})
	}
}
