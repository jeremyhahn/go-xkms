// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"crypto/sha256"
	"encoding/json"
	"encoding/pem"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// mcpImportOnlyProvider implements types.KeyProvider and backend.ImportBackend
// only, modeling AWS KMS's real capability split at the interface level (no
// Export* methods exist to stub out) rather than through a runtime refusal.
// See pkg/xkms's identical fixture for why the split matters (go-xkms#1216).
type mcpImportOnlyProvider struct {
	mu          sync.Mutex
	keys        map[string]*types.KeyAttributes
	wrappingKey *rsa.PrivateKey
}

func newMCPImportOnlyProvider(t *testing.T) *mcpImportOnlyProvider {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &mcpImportOnlyProvider{keys: make(map[string]*types.KeyAttributes), wrappingKey: wrappingKey}
}

func (p *mcpImportOnlyProvider) Type() types.BackendType { return types.BackendTypeAWSKMS }
func (p *mcpImportOnlyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true}
}
func (p *mcpImportOnlyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *mcpImportOnlyProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpImportOnlyProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, attrs.CN)
	return nil
}
func (p *mcpImportOnlyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *mcpImportOnlyProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpImportOnlyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpImportOnlyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *mcpImportOnlyProvider) Close() error { return nil }

func (p *mcpImportOnlyProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{WrappingPublicKey: &p.wrappingKey.PublicKey, Algorithm: algorithm, ImportToken: []byte("token"), KeySpec: "AES_256"}, nil
}
func (p *mcpImportOnlyProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	pub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, backend.ErrInvalidAlgorithm
	}
	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, keyMaterial, nil)
	if err != nil {
		return nil, err
	}
	return &backend.WrappedKeyMaterial{WrappedKey: wrapped, Algorithm: params.Algorithm, ImportToken: params.ImportToken}, nil
}
func (p *mcpImportOnlyProvider) UnwrapKey(_ context.Context, wrapped *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, p.wrappingKey, wrapped.WrappedKey, nil)
}
func (p *mcpImportOnlyProvider) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if _, err := p.UnwrapKey(ctx, wrapped, nil); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[attrs.CN] = attrs
	return nil
}

var (
	_ types.KeyProvider     = (*mcpImportOnlyProvider)(nil)
	_ backend.ImportBackend = (*mcpImportOnlyProvider)(nil)
)

// mcpExportOnlyProvider is mcpImportOnlyProvider's export-side mirror: no
// Import half at all.
type mcpExportOnlyProvider struct {
	mu   sync.Mutex
	keys map[string]*types.KeyAttributes
}

func newMCPExportOnlyProvider() *mcpExportOnlyProvider {
	return &mcpExportOnlyProvider{keys: map[string]*types.KeyAttributes{
		"export-me": {CN: "export-me", KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true},
	}}
}

func (p *mcpExportOnlyProvider) Type() types.BackendType { return types.BackendTypeSoftware }
func (p *mcpExportOnlyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Export: true}
}
func (p *mcpExportOnlyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *mcpExportOnlyProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpExportOnlyProvider) DeleteKey(context.Context, *types.KeyAttributes) error { return nil }
func (p *mcpExportOnlyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *mcpExportOnlyProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpExportOnlyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *mcpExportOnlyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *mcpExportOnlyProvider) Close() error { return nil }

func (p *mcpExportOnlyProvider) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported:" + attrs.CN), Algorithm: algorithm}, nil
}
func (p *mcpExportOnlyProvider) ExportKeyTo(_ context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported-to:" + attrs.CN), Algorithm: dstParams.Algorithm, ImportToken: dstParams.ImportToken}, nil
}
func (p *mcpExportOnlyProvider) ExportKeyMaterial(context.Context, *types.KeyAttributes) ([]byte, error) {
	return []byte("raw-material"), nil
}

var (
	_ types.KeyProvider     = (*mcpExportOnlyProvider)(nil)
	_ backend.ExportBackend = (*mcpExportOnlyProvider)(nil)
)

// setupCapabilitySplitServer registers backendName's provider as both a
// named and the default backend, using xkms.New's real compositeBackend
// (matching how every real backend is registered), so an embedded-style
// caller that omits a backend name still reaches it.
func setupCapabilitySplitServer(t *testing.T, backendName string, provider types.KeyProvider) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	ks, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{backendName: ks},
		DefaultBackend: backendName,
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)

	server, err := NewServer(&Config{XKMSService: svc, Authenticator: auth.NewNoOpAuthenticator()})
	require.NoError(t, err)
	return server
}

func mcpRPC(t *testing.T, method string, params any) *JSONRPCRequest {
	t.Helper()
	raw, err := json.Marshal(params)
	require.NoError(t, err)
	return &JSONRPCRequest{JSONRPC: "2.0", Method: method, Params: raw, ID: 1}
}

// TestMCP_ImportOnlyBackend_ImportsThroughEveryMethod is the go-xkms#1216
// regression test for MCP: getImportParameters, wrapKey and importKeyMaterial
// all succeed against a backend implementing only backend.ImportBackend, and
// exportKey refuses with the typed capability sentinel rather than the
// pre-fix undifferentiated refusal that also demanded the export half.
func TestMCP_ImportOnlyBackend_ImportsThroughEveryMethod(t *testing.T) {
	server := setupCapabilitySplitServer(t, "import-only", newMCPImportOnlyProvider(t))
	ctx := context.Background()

	paramsResult, err := server.handleGetImportParameters(ctx, mcpRPC(t, "xkms.getImportParameters", GetImportParametersParams{
		KeyID: "mcp-import-only-key", Backend: "import-only", Algorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric", KeySize: 256,
	}))
	require.NoError(t, err)
	params, ok := paramsResult.(GetImportParametersResult)
	require.True(t, ok)

	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)

	block, _ := pem.Decode([]byte(params.WrappingPublicKeyPEM))
	require.NotNil(t, block)

	wrapResult, err := server.handleWrapKey(ctx, mcpRPC(t, "xkms.wrapKey", WrapKeyParams{
		KeyMaterial: material, WrappingPublicKeyPEM: params.WrappingPublicKeyPEM,
		ImportToken: params.ImportToken, Algorithm: params.Algorithm, Backend: "import-only",
	}))
	require.NoError(t, err)
	wrapped, ok := wrapResult.(WrapKeyResult)
	require.True(t, ok)

	importResult, err := server.handleImportKeyMaterial(ctx, mcpRPC(t, "xkms.importKeyMaterial", ImportKeyParams{
		KeyID: "mcp-import-only-key", Backend: "import-only", KeyType: "symmetric", KeySize: 256,
		WrappedKey: wrapped.WrappedKey, Algorithm: wrapped.Algorithm, ImportToken: wrapped.ImportToken,
	}))
	require.NoError(t, err)
	importMap, ok := importResult.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, true, importMap["success"])

	_, err = server.handleExportKey(ctx, mcpRPC(t, "xkms.exportKey", ExportKeyParams{
		KeyID: "mcp-import-only-key", Backend: "import-only", Algorithm: "RSAES_OAEP_SHA_256",
	}))
	require.Error(t, err)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeMethodNotFound, keyErr.Code)
}

// TestMCP_ExportOnlyBackend_ExportsThroughTheMethod is the export mirror of
// TestMCP_ImportOnlyBackend_ImportsThroughEveryMethod.
func TestMCP_ExportOnlyBackend_ExportsThroughTheMethod(t *testing.T) {
	server := setupCapabilitySplitServer(t, "export-only", newMCPExportOnlyProvider())
	ctx := context.Background()

	exportResult, err := server.handleExportKey(ctx, mcpRPC(t, "xkms.exportKey", ExportKeyParams{
		KeyID: "export-me", Backend: "export-only", Algorithm: "RSAES_OAEP_SHA_256",
	}))
	require.NoError(t, err)
	exported, ok := exportResult.(ExportKeyResult)
	require.True(t, ok)
	assert.Equal(t, "exported:export-me", string(exported.WrappedKey))

	_, err = server.handleImportKeyMaterial(ctx, mcpRPC(t, "xkms.importKeyMaterial", ImportKeyParams{
		KeyID: "new-key", Backend: "export-only", KeyType: "symmetric", KeySize: 256,
		WrappedKey: []byte("wrapped"), Algorithm: "RSAES_OAEP_SHA_256",
	}))
	require.Error(t, err)
	var keyErr *KeyOpError
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeMethodNotFound, keyErr.Code)

	_, err = server.handleGetImportParameters(ctx, mcpRPC(t, "xkms.getImportParameters", GetImportParametersParams{
		KeyID: "new-key", Backend: "export-only", Algorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric",
	}))
	require.Error(t, err)
	require.ErrorAs(t, err, &keyErr)
	assert.Equal(t, ErrCodeMethodNotFound, keyErr.Code)
}
