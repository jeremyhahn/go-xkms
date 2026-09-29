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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/signing/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// providerBackedKeyStore adapts a types.KeyProvider directly into a full
// Backend by delegating every read and write through the provider, unlike
// mockKeyStore (service_test.go), which keeps its own storage independent of
// whatever provider is attached to it. These tests need ListKeys, GetKey and
// DeleteKey to see exactly what the provider's own ImportKey/ExportKey
// methods recorded, the way a real compositeBackend does.
type providerBackedKeyStore struct {
	provider  types.KeyProvider
	storeType types.StoreType
}

func newProviderBackedKeyStore(provider types.KeyProvider, storeType types.StoreType) *providerBackedKeyStore {
	return &providerBackedKeyStore{provider: provider, storeType: storeType}
}

func (b *providerBackedKeyStore) KeyProvider() types.KeyProvider { return b.provider }
func (b *providerBackedKeyStore) CertStorage() certstore.CertificateStorageAdapter {
	return nil
}
func (b *providerBackedKeyStore) SignerStore() store.SignerStorer { return nil }
func (b *providerBackedKeyStore) Type() types.StoreType           { return b.storeType }

func (b *providerBackedKeyStore) GenerateRSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.RSA
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *providerBackedKeyStore) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.ECDSA
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *providerBackedKeyStore) GenerateEd25519(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	attrs.KeyAlgorithm = x509.Ed25519
	return b.provider.GenerateKey(ctx, attrs)
}
func (b *providerBackedKeyStore) GetKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return b.provider.GetKey(ctx, attrs)
}
func (b *providerBackedKeyStore) DeleteKey(ctx context.Context, attrs *types.KeyAttributes) error {
	return b.provider.DeleteKey(ctx, attrs)
}
func (b *providerBackedKeyStore) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	return b.provider.ListKeys(ctx)
}
func (b *providerBackedKeyStore) RotateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, b.provider.RotateKey(ctx, attrs)
}
func (b *providerBackedKeyStore) Signer(ctx context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	return b.provider.Signer(ctx, attrs)
}
func (b *providerBackedKeyStore) Decrypter(ctx context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	return b.provider.Decrypter(ctx, attrs)
}
func (b *providerBackedKeyStore) SaveCert(context.Context, string, *x509.Certificate) error {
	return nil
}
func (b *providerBackedKeyStore) GetCert(context.Context, string) (*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) DeleteCert(context.Context, string) error { return nil }
func (b *providerBackedKeyStore) ListCerts(context.Context) ([]string, error) {
	return nil, nil
}
func (b *providerBackedKeyStore) CertExists(context.Context, string) (bool, error) {
	return false, nil
}
func (b *providerBackedKeyStore) SaveCertChain(context.Context, string, []*x509.Certificate) error {
	return nil
}
func (b *providerBackedKeyStore) GetCertChain(context.Context, string) ([]*x509.Certificate, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) GetTLSCertificate(context.Context, string, *types.KeyAttributes) (tls.Certificate, error) {
	return tls.Certificate{}, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) GetKeyByID(context.Context, string) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) GetSignerByID(context.Context, string) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) GetDecrypterByID(context.Context, string) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (b *providerBackedKeyStore) Seal(context.Context, []byte, *types.SealOptions) (*types.SealedData, error) {
	return nil, backend.ErrOperationNotSupported
}
func (b *providerBackedKeyStore) Unseal(context.Context, *types.SealedData, *types.UnsealOptions) ([]byte, error) {
	return nil, backend.ErrOperationNotSupported
}
func (b *providerBackedKeyStore) CanSeal() bool { return false }
func (b *providerBackedKeyStore) Close() error  { return b.provider.Close() }

var _ Backend = (*providerBackedKeyStore)(nil)

// These tests are the pkg/xkms half of go-xkms#1216: a backend that
// genuinely implements only one direction of the import/export ceremony --
// AWS KMS's real shape for import, and a hypothetical export-only backend
// for the mirror case -- must be reachable for the half it supports through
// the service, the embedded (package-level) API, a tenant-scoped view, and
// the PIV key generator, none of which may demand the other half.

// importOnlyKeyProvider implements types.KeyProvider and backend.ImportBackend
// only. It deliberately has no Export* methods at all, so it does not
// satisfy backend.ExportBackend or the full backend.ImportExportBackend
// union -- modeling AWS KMS's capability split at the interface level, the
// way a backend that never needed a stub Export half would look.
type importOnlyKeyProvider struct {
	mu          sync.Mutex
	keys        map[string]*types.KeyAttributes
	privKeys    map[string]crypto.PrivateKey
	wrappingKey *rsa.PrivateKey
}

func newImportOnlyKeyProvider(t *testing.T) *importOnlyKeyProvider {
	t.Helper()
	wrappingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return &importOnlyKeyProvider{
		keys:        make(map[string]*types.KeyAttributes),
		privKeys:    make(map[string]crypto.PrivateKey),
		wrappingKey: wrappingKey,
	}
}

func (p *importOnlyKeyProvider) Type() types.BackendType { return types.BackendTypeAWSKMS }
func (p *importOnlyKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Import: true}
}
func (p *importOnlyKeyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *importOnlyKeyProvider) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.privKeys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return key, nil
}
func (p *importOnlyKeyProvider) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.keys, attrs.CN)
	return nil
}
func (p *importOnlyKeyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *importOnlyKeyProvider) Signer(_ context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	key, ok := p.privKeys[attrs.CN]
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, backend.ErrKeyNotFound
	}
	return signer, nil
}
func (p *importOnlyKeyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *importOnlyKeyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *importOnlyKeyProvider) Close() error { return nil }

func (p *importOnlyKeyProvider) GetImportParameters(_ context.Context, _ *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.ImportParameters, error) {
	return &backend.ImportParameters{
		WrappingPublicKey: &p.wrappingKey.PublicKey,
		Algorithm:         algorithm,
		ImportToken:       []byte("import-only-token"),
		KeySpec:           "AES_256",
	}, nil
}
func (p *importOnlyKeyProvider) WrapKey(_ context.Context, keyMaterial []byte, params *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
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
func (p *importOnlyKeyProvider) UnwrapKey(_ context.Context, wrapped *backend.WrappedKeyMaterial, _ *backend.ImportParameters) ([]byte, error) {
	return rsa.DecryptOAEP(sha256.New(), rand.Reader, p.wrappingKey, wrapped.WrappedKey, nil)
}
func (p *importOnlyKeyProvider) ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *backend.WrappedKeyMaterial) error {
	material, err := p.UnwrapKey(ctx, wrapped, nil)
	if err != nil {
		return err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[attrs.CN] = attrs
	// The PIV import ceremony wraps a PKCS#8-encoded private key; parsing it
	// back lets Signer/GetKey answer for real after import, the way a real
	// backend's own object store would. A plain AES key import (the BYOK
	// ceremony tests below) is not PKCS#8, so parse failure is expected and
	// silently ignored there.
	if privKey, parseErr := x509.ParsePKCS8PrivateKey(material); parseErr == nil {
		p.privKeys[attrs.CN] = privKey
	}
	return nil
}

var (
	_ types.KeyProvider     = (*importOnlyKeyProvider)(nil)
	_ backend.ImportBackend = (*importOnlyKeyProvider)(nil)
)

// TestImportOnlyKeyProvider_DoesNotSatisfyExportBackend pins the fixture's
// shape: if it satisfied backend.ExportBackend too, the tests below would no
// longer exercise an import-only capability split.
func TestImportOnlyKeyProvider_DoesNotSatisfyExportBackend(t *testing.T) {
	var provider types.KeyProvider = newImportOnlyKeyProvider(t)
	_, ok := provider.(backend.ExportBackend)
	assert.False(t, ok, "importOnlyKeyProvider must not satisfy backend.ExportBackend")
	_, ok = provider.(backend.ImportExportBackend)
	assert.False(t, ok, "importOnlyKeyProvider must not satisfy the full backend.ImportExportBackend union")
}

// exportOnlyKeyProvider implements types.KeyProvider and backend.ExportBackend
// only, the mirror of importOnlyKeyProvider: no Import half at all.
type exportOnlyKeyProvider struct {
	mu   sync.Mutex
	keys map[string]*types.KeyAttributes
}

func newExportOnlyKeyProvider() *exportOnlyKeyProvider {
	return &exportOnlyKeyProvider{
		keys: map[string]*types.KeyAttributes{
			"export-me": {
				CN:                 "export-me",
				KeyType:            types.KeyTypeSecret,
				StoreType:          types.StoreSoftware,
				SymmetricAlgorithm: types.SymmetricAES256GCM,
				Exportable:         true,
			},
		},
	}
}

func (p *exportOnlyKeyProvider) Type() types.BackendType { return types.BackendTypeSoftware }
func (p *exportOnlyKeyProvider) Capabilities() types.Capabilities {
	return types.Capabilities{Keys: true, Export: true}
}
func (p *exportOnlyKeyProvider) GenerateKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrOperationNotSupported
}
func (p *exportOnlyKeyProvider) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *exportOnlyKeyProvider) DeleteKey(context.Context, *types.KeyAttributes) error { return nil }
func (p *exportOnlyKeyProvider) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]*types.KeyAttributes, 0, len(p.keys))
	for _, a := range p.keys {
		out = append(out, a)
	}
	return out, nil
}
func (p *exportOnlyKeyProvider) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *exportOnlyKeyProvider) Decrypter(context.Context, *types.KeyAttributes) (crypto.Decrypter, error) {
	return nil, backend.ErrKeyNotFound
}
func (p *exportOnlyKeyProvider) RotateKey(context.Context, *types.KeyAttributes) error {
	return backend.ErrOperationNotSupported
}
func (p *exportOnlyKeyProvider) Close() error { return nil }

func (p *exportOnlyKeyProvider) ExportKey(_ context.Context, attrs *types.KeyAttributes, algorithm backend.WrappingAlgorithm) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported:" + attrs.CN), Algorithm: algorithm}, nil
}
func (p *exportOnlyKeyProvider) ExportKeyTo(_ context.Context, attrs *types.KeyAttributes, dstParams *backend.ImportParameters) (*backend.WrappedKeyMaterial, error) {
	return &backend.WrappedKeyMaterial{WrappedKey: []byte("exported-to:" + attrs.CN), Algorithm: dstParams.Algorithm, ImportToken: dstParams.ImportToken}, nil
}
func (p *exportOnlyKeyProvider) ExportKeyMaterial(context.Context, *types.KeyAttributes) ([]byte, error) {
	return []byte("raw-symmetric-material"), nil
}

var (
	_ types.KeyProvider     = (*exportOnlyKeyProvider)(nil)
	_ backend.ExportBackend = (*exportOnlyKeyProvider)(nil)
)

// TestExportOnlyKeyProvider_DoesNotSatisfyImportBackend is exportOnlyKeyProvider's
// half of the fixture-shape pin.
func TestExportOnlyKeyProvider_DoesNotSatisfyImportBackend(t *testing.T) {
	var provider types.KeyProvider = newExportOnlyKeyProvider()
	_, ok := provider.(backend.ImportBackend)
	assert.False(t, ok, "exportOnlyKeyProvider must not satisfy backend.ImportBackend")
	_, ok = provider.(backend.ImportExportBackend)
	assert.False(t, ok, "exportOnlyKeyProvider must not satisfy the full backend.ImportExportBackend union")
}

// setupImportOnlyService registers an import-only backend as both a named
// and the default backend, so embedded (package-level) calls that omit a
// backend name still reach it.
func setupImportOnlyService(t *testing.T) (*XKMSService, *importOnlyKeyProvider) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	provider := newImportOnlyKeyProvider(t)
	ks := newProviderBackedKeyStore(provider, types.StoreAWSKMS)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"import-only": ks},
		DefaultBackend: "import-only",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc, provider
}

// setupExportOnlyService is setupImportOnlyService's export-only mirror.
func setupExportOnlyService(t *testing.T) *XKMSService {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	ks := newProviderBackedKeyStore(newExportOnlyKeyProvider(), types.StoreSoftware)

	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"export-only": ks},
		DefaultBackend: "export-only",
	}))

	svc, err := Get()
	require.NoError(t, err)
	return svc
}

// runImportOnlyCeremony drives the full BYOK ceremony (parameters, wrap,
// import) against the named service and returns ImportKey's error.
func runImportOnlyCeremony(t *testing.T, svc *XKMSService, keyID string, material []byte) error {
	t.Helper()
	ctx := context.Background()
	const wrapAlg = "RSAES_OAEP_SHA_256"

	params, err := svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "import-only",
		KeyID:     keyID,
		Algorithm: wrapAlg,
		KeyType:   "aes",
		KeySize:   256,
	})
	require.NoError(t, err)

	wrapped, err := svc.WrapKey(ctx, &transport.WrapKeyRequest{
		Backend:           "import-only",
		KeyMaterial:       material,
		Algorithm:         params.Algorithm,
		WrappingPublicKey: params.WrappingPublicKey,
		ImportToken:       params.ImportToken,
		KeySpec:           params.KeySpec,
	})
	require.NoError(t, err)

	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "import-only",
		KeyID:              keyID,
		KeyType:            "aes",
		KeySize:            256,
		WrappedKeyMaterial: wrapped.WrappedKeyMaterial,
		Algorithm:          wrapped.Algorithm,
		ImportToken:        params.ImportToken,
	})
	return err
}

// TestXKMSService_ImportOnlyBackend_ImportsThroughTheService is the
// go-xkms#1216 regression test at the service layer: every import-side
// operation succeeds against a backend implementing only
// backend.ImportBackend, and the export-side operations refuse with the
// typed capability sentinel rather than the pre-fix undifferentiated
// "import/export" refusal.
func TestXKMSService_ImportOnlyBackend_ImportsThroughTheService(t *testing.T) {
	svc, _ := setupImportOnlyService(t)
	ctx := context.Background()

	material := make([]byte, 32)
	_, err := rand.Read(material)
	require.NoError(t, err)

	require.NoError(t, runImportOnlyCeremony(t, svc, "aws-shaped-key", material))

	_, err = svc.ExportKey(ctx, &transport.ExportKeyRequest{
		Backend:   "import-only",
		KeyID:     "aws-shaped-key",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)

	_, err = svc.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{
		Backend: "import-only",
		KeyID:   "aws-shaped-key",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

// TestXKMSService_ExportOnlyBackend_ExportsThroughTheService is the export
// mirror of TestXKMSService_ImportOnlyBackend_ImportsThroughTheService.
func TestXKMSService_ExportOnlyBackend_ExportsThroughTheService(t *testing.T) {
	svc := setupExportOnlyService(t)
	ctx := context.Background()

	resp, err := svc.ExportKey(ctx, &transport.ExportKeyRequest{
		Backend:   "export-only",
		KeyID:     "export-me",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	require.NoError(t, err)
	assert.Equal(t, "exported:export-me", string(resp.WrappedKeyMaterial))

	_, err = svc.ImportKey(ctx, &transport.ImportKeyRequest{
		Backend:            "export-only",
		KeyID:              "new-key",
		KeyType:            "aes",
		KeySize:            256,
		WrappedKeyMaterial: []byte("wrapped"),
		Algorithm:          "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)

	_, err = svc.GetImportParameters(ctx, &transport.GetImportParametersRequest{
		Backend:   "export-only",
		KeyID:     "new-key",
		Algorithm: "RSAES_OAEP_SHA_256",
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrOperationNotSupported)
}

// TestXKMSService_EmbeddedAPI_ImportOnlyBackend proves the package-level
// (embedded transport) functions carry the same directional split as the
// XKMSService methods.
func TestXKMSService_EmbeddedAPI_ImportOnlyBackend(t *testing.T) {
	setupImportOnlyService(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{CN: "embedded-key", StoreType: types.StoreAWSKMS, SymmetricAlgorithm: types.SymmetricAES256GCM}
	params, err := GetImportParameters(ctx, "import-only", attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)

	wrapped, err := WrapKey(ctx, "import-only", material, params)
	require.NoError(t, err)

	require.NoError(t, ImportKey(ctx, "import-only", attrs, wrapped))

	_, err = ExportKey(ctx, "embedded-key", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
}

// TestXKMSService_EmbeddedAPI_ExportOnlyBackend is the embedded-API export
// mirror.
func TestXKMSService_EmbeddedAPI_ExportOnlyBackend(t *testing.T) {
	setupExportOnlyService(t)
	ctx := context.Background()

	wrapped, err := ExportKey(ctx, "export-me", backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, "exported:export-me", string(wrapped.WrappedKey))

	attrs := &types.KeyAttributes{CN: "new-key", StoreType: types.StoreSoftware, SymmetricAlgorithm: types.SymmetricAES256GCM}
	err = ImportKey(ctx, "export-only", attrs, &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped")})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
}

// TestTenantScopedBackend_PreservesImportOnlyHalf proves the tenant wrapper
// exposes exactly the half its base implements: import methods succeed
// (scoped), export methods refuse with the typed sentinel, for a base that
// implements only backend.ImportBackend. Before go-xkms#1216 the wrapper's
// capability probe required the base to satisfy the full
// backend.ImportExportBackend union, so this base -- which never has and
// never will implement Export* -- would have had its working import half
// blocked too.
func TestTenantScopedBackend_PreservesImportOnlyHalf(t *testing.T) {
	ctx := context.Background()
	provider := newImportOnlyKeyProvider(t)
	ks := newProviderBackedKeyStore(provider, types.StoreAWSKMS)
	scoped := NewTenantScopedBackend(ks, "acme")

	attrs := &types.KeyAttributes{CN: "tenant-key", SymmetricAlgorithm: types.SymmetricAES256GCM}
	params, err := scoped.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)

	material := make([]byte, 32)
	_, err = rand.Read(material)
	require.NoError(t, err)

	wrapped, err := scoped.WrapKey(ctx, material, params)
	require.NoError(t, err)

	require.NoError(t, scoped.ImportKey(ctx, attrs, wrapped))

	// The tenant stamp reached the stored attributes: the base provider's
	// own record carries TenantID "acme".
	provider.mu.Lock()
	stored, ok := provider.keys["tenant-key"]
	provider.mu.Unlock()
	require.True(t, ok)
	assert.Equal(t, "acme", stored.TenantID)

	_, err = scoped.ExportKey(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
	_, err = scoped.ExportKeyMaterial(ctx, attrs)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
}

// TestTenantScopedBackend_PreservesExportOnlyHalf is the export mirror of
// TestTenantScopedBackend_PreservesImportOnlyHalf.
func TestTenantScopedBackend_PreservesExportOnlyHalf(t *testing.T) {
	ctx := context.Background()
	ks := newProviderBackedKeyStore(newExportOnlyKeyProvider(), types.StoreSoftware)
	scoped := NewTenantScopedBackend(ks, "acme")

	attrs := &types.KeyAttributes{CN: "export-me"}
	wrapped, err := scoped.ExportKey(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	require.NoError(t, err)
	assert.Equal(t, "exported:export-me", string(wrapped.WrappedKey))

	_, err = scoped.GetImportParameters(ctx, attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
	err = scoped.ImportKey(ctx, attrs, &backend.WrappedKeyMaterial{})
	assert.ErrorIs(t, err, ErrImportExportNotSupported)
}

// TestBackendPIVKeyGenerator_ImportPIVKey_ImportOnlyBackendSucceeds proves
// PIV key installation -- which only ever needs the import half -- reaches an
// import-only backend, where the pre-fix union-based resolution would have
// refused it because the backend cannot export.
func TestBackendPIVKeyGenerator_ImportPIVKey_ImportOnlyBackendSucceeds(t *testing.T) {
	ctx := context.Background()
	provider := newImportOnlyKeyProvider(t)
	ks := newProviderBackedKeyStore(provider, types.StoreAWSKMS)

	gen := newBackendPIVKeyGenerator(ks, types.StoreAWSKMS)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = gen.ImportPIVKey(ctx, pivcert.PIVSlot(pivcert.PIVSlotAuthentication), "ecdsap256", "piv-import-only", key)
	// The generator confirms the backend recorded KeyOriginImported by
	// reading it back through ks.ListKeys; the mock provider stores the
	// caller-supplied attrs verbatim, including that origin, so the
	// round trip succeeds end to end.
	require.NoError(t, err)

	provider.mu.Lock()
	_, ok := provider.keys["piv-import-only"]
	provider.mu.Unlock()
	assert.True(t, ok, "the imported PIV key must reach the import-only backend's store")
}
