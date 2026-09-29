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

package grpc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/signing/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// grpcImportOnlyProvider implements types.KeyProvider and backend.ImportBackend
// only, modeling AWS KMS's real capability split at the interface level (no
// Export* methods exist to stub out) rather than through a runtime refusal.
// See pkg/xkms's identical fixture for why the split matters (go-xkms#1216).
type grpcImportOnlyProvider struct {
	mu          sync.Mutex
	keys        map[string]*types.KeyAttributes
	wrappingKey *rsa.PrivateKey
}

func newGRPCImportOnlyProvider(t *testing.T) *grpcImportOnlyProvider {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &grpcImportOnlyProvider{keys: make(map[string]*types.KeyAttributes), wrappingKey: wrappingKey}
}

func (p *grpcImportOnlyProvider) Type() types.BackendType { return types.BackendTypeAWSKMS }
func (p *grpcImportOnlyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true}
}
func (p *grpcImportOnlyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *grpcImportOnlyProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcImportOnlyProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, attrs.CN)
	return nil
}
func (p *grpcImportOnlyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *grpcImportOnlyProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcImportOnlyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcImportOnlyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *grpcImportOnlyProvider) Close() error { return nil }

func (p *grpcImportOnlyProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{WrappingPublicKey: &p.wrappingKey.PublicKey, Algorithm: algorithm, ImportToken: []byte("token"), KeySpec: "AES_256"}, nil
}
func (p *grpcImportOnlyProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
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
func (p *grpcImportOnlyProvider) UnwrapKey(_ context.Context, wrapped *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, p.wrappingKey, wrapped.WrappedKey, nil)
}
func (p *grpcImportOnlyProvider) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	if _, err := p.UnwrapKey(ctx, wrapped, nil); err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[attrs.CN] = attrs
	return nil
}

var (
	_ types.KeyProvider     = (*grpcImportOnlyProvider)(nil)
	_ backend.ImportBackend = (*grpcImportOnlyProvider)(nil)
)

// grpcExportOnlyProvider is grpcImportOnlyProvider's export-side mirror: no
// Import half at all.
type grpcExportOnlyProvider struct {
	mu   sync.Mutex
	keys map[string]*types.KeyAttributes
}

func newGRPCExportOnlyProvider() *grpcExportOnlyProvider {
	return &grpcExportOnlyProvider{keys: map[string]*types.KeyAttributes{
		"export-me": {CN: "export-me", KeyType: types.KeyTypeSecret, StoreType: types.StoreSoftware, SymmetricAlgorithm: types.SymmetricAES256GCM, Exportable: true},
	}}
}

func (p *grpcExportOnlyProvider) Type() types.BackendType { return types.BackendTypeSoftware }
func (p *grpcExportOnlyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Export: true}
}
func (p *grpcExportOnlyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *grpcExportOnlyProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcExportOnlyProvider) DeleteKey(context.Context, *types.KeyAttributes) error { return nil }
func (p *grpcExportOnlyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *grpcExportOnlyProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcExportOnlyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *grpcExportOnlyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *grpcExportOnlyProvider) Close() error { return nil }

func (p *grpcExportOnlyProvider) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported:" + attrs.CN), Algorithm: algorithm}, nil
}
func (p *grpcExportOnlyProvider) ExportKeyTo(_ context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported-to:" + attrs.CN), Algorithm: dstParams.Algorithm, ImportToken: dstParams.ImportToken}, nil
}
func (p *grpcExportOnlyProvider) ExportKeyMaterial(context.Context, *types.KeyAttributes) ([]byte, error) {
	return []byte("raw-material"), nil
}

var (
	_ types.KeyProvider     = (*grpcExportOnlyProvider)(nil)
	_ backend.ExportBackend = (*grpcExportOnlyProvider)(nil)
)

// grpcProviderBackedKeyStore adapts a types.KeyProvider directly into a full
// xkms.Backend by delegating every read and write through the provider, the
// way a real compositeBackend does. It mirrors pkg/xkms's identical test
// fixture (providerBackedKeyStore).
type grpcProviderBackedKeyStore struct {
	provider  types.KeyProvider
	storeType types.StoreType
}

func newGRPCProviderBackedKeyStore(provider types.KeyProvider, storeType types.StoreType) *grpcProviderBackedKeyStore {
	return &grpcProviderBackedKeyStore{provider: provider, storeType: storeType}
}

func (b *grpcProviderBackedKeyStore) KeyProvider() types.KeyProvider { return b.provider }
func (b *grpcProviderBackedKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}
func (b *grpcProviderBackedKeyStore) SignerStore() store.SignerStorer { return nil }
func (b *grpcProviderBackedKeyStore) Type() types.StoreType           { return b.storeType }

func (b *grpcProviderBackedKeyStore) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.RSA
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) GenerateEd25519(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.Ed25519
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return b.provider.GetKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return b.provider.DeleteKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return b.provider.ListKeys(ctx)
}
func (b *grpcProviderBackedKeyStore) RotateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, b.provider.RotateKey(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return b.provider.Signer(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return b.provider.Decrypter(ctx, attrs)
}
func (b *grpcProviderBackedKeyStore) SaveCert(context.Context, string, *x509.Certificate) error {
	return nil
}
func (b *grpcProviderBackedKeyStore) GetCert(context.Context, string) (*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) DeleteCert(context.Context, string) error { return nil }
func (b *grpcProviderBackedKeyStore) ListCerts(context.Context) ([]string, error) {
	return nil, nil
}
func (b *grpcProviderBackedKeyStore) CertExists(context.Context, string) (bool, error) {
	return false, nil
}
func (b *grpcProviderBackedKeyStore) SaveCertChain(context.Context, string, []*x509.Certificate) error {
	return nil
}
func (b *grpcProviderBackedKeyStore) GetCertChain(context.Context, string) ([]*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) GetTLSCertificate(context.Context, string, *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) GetKeyByID(context.Context, string) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) GetSignerByID(context.Context, string) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) GetDecrypterByID(context.Context, string) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *grpcProviderBackedKeyStore) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return nil, backend.ErrOperationNotSupported
}
func (b *grpcProviderBackedKeyStore) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, backend.ErrOperationNotSupported
}
func (b *grpcProviderBackedKeyStore) CanSeal() bool { return false }
func (b *grpcProviderBackedKeyStore) Close() error  { return b.provider.Close() }

var _ xkms.Backend = (*grpcProviderBackedKeyStore)(nil)

// setupCapabilitySplitService registers backendName as both a named and the
// default backend, so an embedded-style caller that omits a backend name
// still reaches it.
func setupCapabilitySplitService(t *testing.T, backendName string, ks xkms.Backend) *Service {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{backendName: ks},
		DefaultBackend: backendName,
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)
	return NewService(nil, nil, svc)
}

// TestGRPC_ImportOnlyBackend_ImportsThroughEveryRPC is the go-xkms#1216
// regression test for gRPC: GetImportParameters, WrapKey and ImportKey all
// succeed against a backend implementing only backend.ImportBackend, and
// ExportKey refuses with Unimplemented rather than the pre-fix
// undifferentiated refusal that also demanded the export half.
func TestGRPC_ImportOnlyBackend_ImportsThroughEveryRPC(t *testing.T) {
	ks := newGRPCProviderBackedKeyStore(newGRPCImportOnlyProvider(t), types.StoreAWSKMS)
	service := setupCapabilitySplitService(t, "import-only", ks)
	ctx := context.Background()

	params, err := service.GetImportParameters(ctx, &pb.GetImportParametersRequest{
		KeyId: "grpc-import-only-key", Backend: "import-only",
		WrappingAlgorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric", KeySize: 256,
	})
	require.NoError(t, err)

	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)

	wrapped, err := service.WrapKey(ctx, &pb.WrapKeyRequest{
		KeyMaterial: material, WrappingPublicKey: params.WrappingPublicKey,
		ImportToken: params.ImportToken, Algorithm: params.Algorithm, Backend: "import-only",
	})
	require.NoError(t, err)

	importResp, err := service.ImportKey(ctx, &pb.ImportKeyRequest{
		KeyId: "grpc-import-only-key", Backend: "import-only",
		WrappedKey: wrapped.WrappedKey, Algorithm: wrapped.Algorithm,
		ImportToken: wrapped.ImportToken, KeyType: "symmetric", KeySize: 256,
	})
	require.NoError(t, err)
	assert.True(t, importResp.Success)

	_, err = service.ExportKey(ctx, &pb.ExportKeyRequest{
		KeyId: "grpc-import-only-key", Backend: "import-only", WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}

// TestGRPC_ExportOnlyBackend_ExportsThroughTheRPC is the export mirror of
// TestGRPC_ImportOnlyBackend_ImportsThroughEveryRPC.
func TestGRPC_ExportOnlyBackend_ExportsThroughTheRPC(t *testing.T) {
	ks := newGRPCProviderBackedKeyStore(newGRPCExportOnlyProvider(), types.StoreSoftware)
	service := setupCapabilitySplitService(t, "export-only", ks)
	ctx := context.Background()

	resp, err := service.ExportKey(ctx, &pb.ExportKeyRequest{
		KeyId: "export-me", Backend: "export-only", WrappingAlgorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.Equal(t, "exported:export-me", string(resp.WrappedKey))

	_, err = service.ImportKey(ctx, &pb.ImportKeyRequest{
		KeyId: "new-key", Backend: "export-only", WrappedKey: []byte("wrapped"),
		Algorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric", KeySize: 256,
	})
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())

	_, err = service.GetImportParameters(ctx, &pb.GetImportParametersRequest{
		KeyId: "new-key", Backend: "export-only", WrappingAlgorithm: "RSAES_OAEP_SHA_256", KeyType: "symmetric",
	})
	require.Error(t, err)
	st, ok = status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unimplemented, st.Code())
}
