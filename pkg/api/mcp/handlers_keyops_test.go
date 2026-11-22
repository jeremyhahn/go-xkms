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

package mcp

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Fake capability-bearing key providers
//
// fakeIEProvider is a complete backend.ImportExportBackend implementation with
// no hardware capability. fakeAttestingProvider and fakeAgreementProvider
// embed it and add exactly one hardware capability (types.AttestingKeyProvider
// and types.KeyAgreementProvider respectively), so each success test proves
// the supported path of a single capability without the others interfering,
// and fakeIEProvider alone proves the unsupported path for every capability.
// ===========================================================================

type fakeIEProvider struct {
	keys         []*types.KeyAttributes
	wrappingKey  *rsa.PrivateKey
	material     map[string][]byte
	materialErr  error
	unwrapped    []byte
	unwrapErr    error
	importedKeys map[string]*backend.WrappedKeyMaterial
}

func newFakeIEProvider(keys ...*types.KeyAttributes) *fakeIEProvider {
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic(err)
	}
	return &fakeIEProvider{
		keys:         keys,
		wrappingKey:  wrappingKey,
		material:     make(map[string][]byte),
		importedKeys: make(map[string]*backend.WrappedKeyMaterial),
	}
}

func (p *fakeIEProvider) Type() types.BackendType { return "fake-ie" }
func (p *fakeIEProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true, Export: true}
}
func (p *fakeIEProvider) GenerateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("fake provider: generate not supported")
}

// GetKey returns the fake's RSA key. C_WrapKey resolves the wrapping key's
// public half through GetKey, so a provider that refuses it cannot exercise
// the real wrap path at all -- which is why these tests previously asserted a
// canned prefix from the import-ceremony path instead of a real wrap.
func (p *fakeIEProvider) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return p.wrappingKey, nil
}
func (p *fakeIEProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error { return nil }
func (p *fakeIEProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return p.keys, nil
}
func (p *fakeIEProvider) Signer(_ context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("fake provider: signer not supported")
}

// Decrypter returns the fake's RSA key, which satisfies crypto.Decrypter.
// C_UnwrapKey decrypts with the caller's own unwrapping key through this seam.
func (p *fakeIEProvider) Decrypter(_ context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return p.wrappingKey, nil
}
func (p *fakeIEProvider) RotateKey(_ context.Context, attrs *types.KeyAttributes) error { return nil }
func (p *fakeIEProvider) Close() error                                                  { return nil }

func (p *fakeIEProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{
		WrappingPublicKey: &p.wrappingKey.PublicKey,
		ImportToken:       []byte("fake-import-token"),
		Algorithm:         algorithm,
	}, nil
}

func (p *fakeIEProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	wrapped := append([]byte("wrapped:"), keyMaterial...)
	return &backend.WrappedKeyMaterial{WrappedKey: wrapped, Algorithm: params.Algorithm}, nil
}

func (p *fakeIEProvider) UnwrapKey(_ context.Context, _ *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	if p.unwrapErr != nil {
		return nil, p.unwrapErr
	}
	if p.unwrapped != nil {
		return p.unwrapped, nil
	}
	return []byte("unwrapped-key-material"), nil
}

func (p *fakeIEProvider) ImportKey(_ context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	p.importedKeys[attrs.CN] = wrapped
	return nil
}

func (p *fakeIEProvider) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported-material"), Algorithm: algorithm}, nil
}

func (p *fakeIEProvider) ExportKeyTo(_ context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	if dstParams == nil {
		return nil, errors.New("fake provider: destination import parameters cannot be nil")
	}
	return &backend.WrappedKeyMaterial{
		WrappedKey:  []byte("exported-material"),
		Algorithm:   dstParams.Algorithm,
		ImportToken: dstParams.ImportToken,
	}, nil
}

func (p *fakeIEProvider) ExportKeyMaterial(_ context.Context, attrs *types.KeyAttributes) ([]byte, error) {
	if p.materialErr != nil {
		return nil, p.materialErr
	}
	if m, ok := p.material[attrs.CN]; ok {
		return m, nil
	}
	return nil, errors.New("fake provider: no material configured for " + attrs.CN)
}

var _ backend.ImportExportBackend = (*fakeIEProvider)(nil)

// fakeAttestingProvider satisfies types.AttestingKeyProvider.
type fakeAttestingProvider struct {
	*fakeIEProvider
	stmt      *attestation.AttestationStatement
	attestErr error
}

func newFakeAttestingProvider(stmt *attestation.AttestationStatement, keys ...*types.KeyAttributes) *fakeAttestingProvider {
	return &fakeAttestingProvider{fakeIEProvider: newFakeIEProvider(keys...), stmt: stmt}
}

func (p *fakeAttestingProvider) AttestKey(_ context.Context, _ *types.KeyAttributes, _ []byte) (interface{}, error) {
	if p.attestErr != nil {
		return nil, p.attestErr
	}
	return p.stmt, nil
}

var _ types.AttestingKeyProvider = (*fakeAttestingProvider)(nil)

// fakeAgreementProvider satisfies types.KeyAgreementProvider.
type fakeAgreementProvider struct {
	*fakeIEProvider
	derived   []byte
	deriveErr error
}

func newFakeAgreementProvider(derived []byte, keys ...*types.KeyAttributes) *fakeAgreementProvider {
	return &fakeAgreementProvider{fakeIEProvider: newFakeIEProvider(keys...), derived: derived}
}

func (p *fakeAgreementProvider) DeriveKeyECDH(_ context.Context, _ *types.KeyAttributes, _ []byte, _ *types.KDFParams) ([]byte, error) {
	if p.deriveErr != nil {
		return nil, p.deriveErr
	}
	return p.derived, nil
}

func (p *fakeAgreementProvider) SupportedCurves() []string {
	return []string{"P-256", "P-384"}
}

var _ types.KeyAgreementProvider = (*fakeAgreementProvider)(nil)

// ===========================================================================
// Setup helper
// ===========================================================================

// newKeyOpsServer builds an MCP server backed by a "software" default backend
// (capability-free for attestation/ECDH, exactly like production software-only
// deployments) plus one additional named backend per entry in extra. It
// mirrors createTestServer/setupTestXKMS but allows registering the
// capability-bearing fakes the key-operations handlers need to exercise their
// success and capability-boundary paths.
func newKeyOpsServer(t *testing.T, extra map[string]types.KeyProvider) *Server {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)

	softBackend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	softKS, err := xkms.New(&xkms.BackendConfig{Backend: softBackend, CertStorage: storage.New()})
	require.NoError(t, err)

	backends := map[string]xkms.Backend{"software": softKS}
	for name, provider := range extra {
		ks, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
		require.NoError(t, err)
		backends[name] = ks
	}

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       backends,
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return server
}

func testAttestationStatement() *attestation.AttestationStatement {
	return &attestation.AttestationStatement{
		Format:             "tpm2",
		CertificateChain:   nil,
		AttestationData:    []byte("TPM2_Certify output"),
		Signature:          []byte("hw-signature"),
		SignatureAlgorithm: x509.ECDSAWithSHA256,
		Nonce:              []byte("challenge"),
		Backend:            "tpm2",
	}
}

// ===========================================================================
// AttestKey
// ===========================================================================

func TestHandler_AttestKey_Success(t *testing.T) {
	stmt := testAttestationStatement()
	provider := newFakeAttestingProvider(stmt, &types.KeyAttributes{CN: "idevid", KeyAlgorithm: x509.ECDSA})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"tpm2": provider})

	paramsJSON, err := json.Marshal(&transport.AttestKeyRequest{Backend: "tpm2", KeyID: "idevid", Nonce: []byte("challenge")})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.attestKey", Params: paramsJSON, ID: 1}
	result, err := server.handleAttestKey(context.Background(), req)
	require.NoError(t, err)

	resp, ok := result.(*transport.AttestKeyResponse)
	require.True(t, ok)
	assert.Equal(t, "tpm2", resp.Format)
	assert.Equal(t, "tpm2", resp.Backend)
	assert.Equal(t, stmt.AttestationData, resp.AttestationData)
	assert.Equal(t, stmt.Signature, resp.Signature)
	assert.Equal(t, []byte("challenge"), resp.Nonce)
}

func TestHandler_AttestKey_BackendLacksCapability(t *testing.T) {
	server := createTestServer(t)

	paramsJSON, err := json.Marshal(&transport.AttestKeyRequest{Backend: "software", KeyID: "whatever", Nonce: []byte("n")})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.attestKey", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandler_AttestKey_ValidationError(t *testing.T) {
	server := createTestServer(t)

	// Missing key_id is a required-field validation failure.
	paramsJSON, err := json.Marshal(&transport.AttestKeyRequest{Backend: "software"})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.attestKey", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "key_id is required")
}

// ===========================================================================
// DeriveKeyECDH
// ===========================================================================

func TestHandler_DeriveKeyECDH_Success(t *testing.T) {
	derived := []byte("derived-shared-secret-32-bytes!!")
	provider := newFakeAgreementProvider(derived, &types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"hsm": provider})

	paramsJSON, err := json.Marshal(&transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "hsm",
		PeerPublicKey: []byte("peer-public-key"),
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.deriveKeyECDH", Params: paramsJSON, ID: 1}
	result, err := server.handleDeriveKeyECDH(context.Background(), req)
	require.NoError(t, err)

	resp, ok := result.(*transport.DeriveKeyECDHResponse)
	require.True(t, ok)
	assert.Equal(t, derived, resp.DerivedKey)
}

func TestHandler_DeriveKeyECDH_BackendLacksCapability(t *testing.T) {
	provider := newFakeIEProvider(&types.KeyAttributes{CN: "ecdh-key", KeyAlgorithm: x509.ECDSA})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"no-caps": provider})

	paramsJSON, err := json.Marshal(&transport.DeriveKeyECDHRequest{
		KeyID:         "ecdh-key",
		Backend:       "no-caps",
		PeerPublicKey: []byte("peer-public-key"),
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.deriveKeyECDH", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandler_DeriveKeyECDH_ValidationError(t *testing.T) {
	server := createTestServer(t)

	// Missing peer_public_key is a required-field validation failure.
	paramsJSON, err := json.Marshal(&transport.DeriveKeyECDHRequest{KeyID: "k", Backend: "software"})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.deriveKeyECDH", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "peer_public_key is required")
}

// TestHandler_DeriveKeyECDH_KeyLengthExceedsMaximum proves an oversized
// key_length is refused before any backend or key lookup, so it surfaces as
// Invalid params on this transport too, matching REST and gRPC
// (go-xkms#1259).
func TestHandler_DeriveKeyECDH_KeyLengthExceedsMaximum(t *testing.T) {
	server := createTestServer(t)

	paramsJSON, err := json.Marshal(&transport.DeriveKeyECDHRequest{
		KeyID:         "k",
		Backend:       "software",
		PeerPublicKey: []byte("peer-public-key"),
		KeyLength:     types.MaxDerivedKeyLength + 1,
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.deriveKeyECDH", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
}

// ===========================================================================
// ExportKeyMaterial
// ===========================================================================

func TestHandler_ExportKeyMaterial_Success(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	provider := newFakeIEProvider(&types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	provider.material["aes-key"] = material
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"hsm": provider})

	paramsJSON, err := json.Marshal(&transport.ExportKeyMaterialRequest{KeyID: "aes-key", Backend: "hsm"})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKeyMaterial", Params: paramsJSON, ID: 1}
	result, err := server.handleExportKeyMaterial(context.Background(), req)
	require.NoError(t, err)

	resp, ok := result.(*transport.ExportKeyMaterialResponse)
	require.True(t, ok)
	assert.Equal(t, material, resp.KeyMaterial)
	assert.Equal(t, string(types.SymmetricAES256GCM), resp.KeyType)
	assert.Equal(t, 256, resp.KeySize)
}

func TestHandler_ExportKeyMaterial_BackendLacksCapability(t *testing.T) {
	provider := &fakeMinimalProvider{keys: []*types.KeyAttributes{{CN: "aes-key"}}}
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"no-caps": provider})

	paramsJSON, err := json.Marshal(&transport.ExportKeyMaterialRequest{KeyID: "aes-key", Backend: "no-caps"})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKeyMaterial", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandler_ExportKeyMaterial_ValidationError(t *testing.T) {
	server := createTestServer(t)

	// Missing key_id is a required-field validation failure.
	paramsJSON, err := json.Marshal(&transport.ExportKeyMaterialRequest{Backend: "software"})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKeyMaterial", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "key_id is required")
}

// TestHandler_ExportKey_And_ExportKeyMaterial_AreDistinct proves the rename in
// Part A did not swap the two handlers: xkms.exportKey must still route to the
// wrapped-envelope export (handleExportKey, ExportKeyResult with a
// WrappedKey/Algorithm/ImportToken envelope) and xkms.exportKeyMaterial must
// route to the new raw-material export (handleExportKeyMaterial,
// transport.ExportKeyMaterialResponse with plaintext KeyMaterial bytes).
func TestHandler_ExportKey_And_ExportKeyMaterial_AreDistinct(t *testing.T) {
	material := []byte("0123456789abcdef0123456789abcdef")
	provider := newFakeIEProvider(&types.KeyAttributes{
		CN:                 "aes-key",
		KeyType:            types.KeyTypeSecret,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	provider.material["aes-key"] = material
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"software": provider})

	t.Run("xkms.exportKey returns the wrapped envelope", func(t *testing.T) {
		params := ExportKeyParams{KeyID: "aes-key", Backend: "software", Algorithm: "RSAES_OAEP_SHA_256"}
		paramsJSON, err := json.Marshal(params)
		require.NoError(t, err)

		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKey", Params: paramsJSON, ID: 1}
		result, err := server.handleExportKey(context.Background(), req)
		require.NoError(t, err)

		envelope, ok := result.(ExportKeyResult)
		require.True(t, ok)
		assert.Equal(t, []byte("exported-material"), envelope.WrappedKey)
	})

	t.Run("xkms.exportKeyMaterial returns raw plaintext material", func(t *testing.T) {
		paramsJSON, err := json.Marshal(&transport.ExportKeyMaterialRequest{KeyID: "aes-key", Backend: "software"})
		require.NoError(t, err)

		req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.exportKeyMaterial", Params: paramsJSON, ID: 1}
		result, err := server.handleExportKeyMaterial(context.Background(), req)
		require.NoError(t, err)

		resp, ok := result.(*transport.ExportKeyMaterialResponse)
		require.True(t, ok)
		assert.Equal(t, material, resp.KeyMaterial)
	})
}

// ===========================================================================
// WrapKeyByID
// ===========================================================================

func TestHandler_WrapKeyByID_Success(t *testing.T) {
	target := newFakeIEProvider(&types.KeyAttributes{
		CN: "target-key", KeyType: types.KeyTypeSecret, SymmetricAlgorithm: types.SymmetricAES256GCM,
	})
	target.material["target-key"] = []byte("target-key-material")
	kek := newFakeIEProvider(&types.KeyAttributes{CN: "kek"})
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"target-be": target, "kek-be": kek})

	paramsJSON, err := json.Marshal(&transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "kek-be",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "target-be",
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.wrapKeyByID", Params: paramsJSON, ID: 1}
	result, err := server.handleWrapKeyByID(context.Background(), req)
	require.NoError(t, err)

	resp, ok := result.(*transport.WrapKeyByIDResponse)
	require.True(t, ok)
	// A real RSA-OAEP wrap, not a canned fixture prefix: assert the blob is
	// genuine ciphertext (RSA-2048 block size, not the plaintext) and that it
	// decrypts back to the target material with the wrapping key. This is what
	// the previous canned-prefix assertion could not tell you -- it passed
	// while the service routed through the import ceremony and wrapped under a
	// freshly generated ephemeral key rather than the caller's own.
	assert.Len(t, resp.WrappedKey, 256, "RSA-2048 OAEP output is one modulus block")
	assert.NotEqual(t, []byte("target-key-material"), resp.WrappedKey)
	assert.Equal(t, "RSAES_OAEP_SHA_256", resp.Algorithm)

	recovered, decErr := kek.wrappingKey.Decrypt(rand.Reader, resp.WrappedKey, &rsa.OAEPOptions{Hash: crypto.SHA256})
	require.NoError(t, decErr, "the wrapped blob must decrypt under the designated wrapping key")
	assert.Equal(t, []byte("target-key-material"), recovered)
}

func TestHandler_WrapKeyByID_BackendLacksCapability(t *testing.T) {
	provider := &fakeMinimalProvider{keys: []*types.KeyAttributes{{CN: "kek"}}}
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"no-caps": provider})

	paramsJSON, err := json.Marshal(&transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "no-caps",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "no-caps",
		Algorithm:          "AES_KEY_WRAP",
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.wrapKeyByID", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandler_WrapKeyByID_ValidationError(t *testing.T) {
	server := createTestServer(t)

	// Missing algorithm is a required-field validation failure.
	paramsJSON, err := json.Marshal(&transport.WrapKeyByIDRequest{
		WrappingKeyID:      "kek",
		WrappingKeyBackend: "software",
		TargetKeyID:        "target-key",
		TargetKeyBackend:   "software",
	})
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.wrapKeyByID", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "algorithm is required")
}

// ===========================================================================
// UnwrapKeyByID
// ===========================================================================

func newUnwrapByIDParams() *transport.UnwrapKeyByIDRequest {
	return &transport.UnwrapKeyByIDRequest{
		WrappedKey:           []byte("wrapped-blob"),
		UnwrappingKeyID:      "kek",
		UnwrappingKeyBackend: "kek-be",
		Algorithm:            "RSAES_OAEP_SHA_256",
		TargetKeyID:          "imported-key",
		TargetKeyBackend:     "target-be",
		TargetKeyType:        "symmetric",
		TargetKeySize:        256,
	}
}

func TestHandler_UnwrapKeyByID_Success(t *testing.T) {
	kek := newFakeIEProvider(&types.KeyAttributes{CN: "kek"})
	target := newFakeIEProvider()
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"kek-be": kek, "target-be": target})

	// Supply a genuine RSA-OAEP blob wrapped under the designated unwrapping
	// key. The previous fixture passed the literal bytes "wrapped-blob", which
	// only worked while the service routed through the import ceremony and
	// never actually decrypted anything -- an unwrap test that could not fail
	// on a broken unwrap.
	const material = "unwrapped-key-material"
	wrapped, wrapErr := rsa.EncryptOAEP(crypto.SHA256.New(), rand.Reader,
		&kek.wrappingKey.PublicKey, []byte(material), nil)
	require.NoError(t, wrapErr)

	params := newUnwrapByIDParams()
	params.WrappedKey = wrapped
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unwrapKeyByID", Params: paramsJSON, ID: 1}
	result, err := server.handleUnwrapKeyByID(context.Background(), req)
	require.NoError(t, err)

	resp, ok := result.(*transport.UnwrapKeyByIDResponse)
	require.True(t, ok)
	assert.True(t, resp.Success)
	assert.Equal(t, "imported-key", resp.KeyID)
	assert.Equal(t, "target-be", resp.Backend)

	imported, ok := target.importedKeys["imported-key"]
	require.True(t, ok, "unwrapped material must be imported into the target backend")
	// "wrapped:" is the fake importer's own marker; the suffix is the payload
	// that reached it, which is what proves the blob was genuinely decrypted
	// rather than passed through.
	assert.Equal(t, append([]byte("wrapped:"), []byte(material)...), imported.WrappedKey,
		"the imported material must be what the blob actually decrypted to")
}

func TestHandler_UnwrapKeyByID_BackendLacksCapability(t *testing.T) {
	provider := &fakeMinimalProvider{keys: []*types.KeyAttributes{{CN: "kek"}}}
	server := newKeyOpsServer(t, map[string]types.KeyProvider{"no-caps": provider})

	params := newUnwrapByIDParams()
	params.UnwrappingKeyBackend = "no-caps"
	params.TargetKeyBackend = "no-caps"
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unwrapKeyByID", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeMethodNotFound, resp.Error.Code)
}

func TestHandler_UnwrapKeyByID_ValidationError(t *testing.T) {
	server := createTestServer(t)

	// Missing wrapped_key is a required-field validation failure.
	params := newUnwrapByIDParams()
	params.WrappedKey = nil
	paramsJSON, err := json.Marshal(params)
	require.NoError(t, err)

	req := &JSONRPCRequest{JSONRPC: "2.0", Method: "xkms.unwrapKeyByID", Params: paramsJSON, ID: 1}
	resp := invokeRequest(server, context.Background(), req)
	require.NotNil(t, resp.Error)
	assert.Equal(t, ErrCodeInvalidParams, resp.Error.Code)
	assert.Contains(t, resp.Error.Message, "wrapped_key is required")
}

// ===========================================================================
// fakeMinimalProvider: a types.KeyProvider with NO import/export, attestation,
// or ECDH capability. Used to drive the "backend lacks capability" path
// through the dispatcher for ExportKeyMaterial, WrapKeyByID, and
// UnwrapKeyByID (which all require backend.ImportExportBackend).
// ===========================================================================

type fakeMinimalProvider struct {
	keys []*types.KeyAttributes
}

func (p *fakeMinimalProvider) Type() types.BackendType { return "fake-minimal" }
func (p *fakeMinimalProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true}
}
func (p *fakeMinimalProvider) GenerateKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("fake minimal provider: generate not supported")
}
func (p *fakeMinimalProvider) GetKey(_ context.Context, _ *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errors.New("fake minimal provider: key not found")
}
func (p *fakeMinimalProvider) DeleteKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *fakeMinimalProvider) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return p.keys, nil
}
func (p *fakeMinimalProvider) Signer(_ context.Context, _ *types.KeyAttributes) (crypto.Signer, error) {
	return nil, errors.New("fake minimal provider: signer not supported")
}
func (p *fakeMinimalProvider) Decrypter(_ context.Context, _ *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, errors.New("fake minimal provider: decrypter not supported")
}
func (p *fakeMinimalProvider) RotateKey(_ context.Context, _ *types.KeyAttributes) error { return nil }
func (p *fakeMinimalProvider) Close() error                                              { return nil }

var _ types.KeyProvider = (*fakeMinimalProvider)(nil)
