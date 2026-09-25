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

package xkms

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/signing/store"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ============================================================
// recordingBackend – minimal Backend mock for tenant tests.
// Each operation records the last KeyAttributes it received
// and the last keyID for cert operations so tests can assert
// on both.
// ============================================================

type recordingBackend struct {
	// listKeys and listCerts drive the tenant-filtering tests.
	listKeys     []*types.KeyAttributes
	listKeysErr  error
	listCerts    []string
	listCertsErr error

	mu sync.Mutex

	lastAttrs *types.KeyAttributes
	lastKeyID string

	// Canned return values.
	generateRSAErr     error
	generateECDSAErr   error
	generateEd25519Err error
	getKeyErr          error
	deleteKeyErr       error
	rotateKeyErr       error
	signerErr          error
	decrypterErr       error
	saveCertErr        error
	getCertErr         error
	deleteCertErr      error
	saveCertChainErr   error
	getCertChainErr    error
	certExistsErr      error
	getTLSCertErr      error
	closeErr           error

	// signerStoreMock backs SignerStore(); nil unless a test sets it.
	signerStoreMock store.SignerStorer
}

var _ Backend = (*recordingBackend)(nil)

func (r *recordingBackend) setAttrs(attrs *types.KeyAttributes) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastAttrs = attrs
}

func (r *recordingBackend) setCertKeyID(keyID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lastKeyID = keyID
}

func (r *recordingBackend) getLastAttrs() *types.KeyAttributes {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastAttrs
}

func (r *recordingBackend) getLastKeyID() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lastKeyID
}

// Type reports StoreSoftware unconditionally: none of the tenant-scoping
// tests this fake serves distinguish backends by kind.
func (r *recordingBackend) Type() types.StoreType {
	return types.StoreSoftware
}

func (r *recordingBackend) GenerateRSA(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateRSAErr
}

func (r *recordingBackend) GenerateECDSA(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateECDSAErr
}

func (r *recordingBackend) GenerateEd25519(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateEd25519Err
}

func (r *recordingBackend) GetKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.getKeyErr
}

func (r *recordingBackend) DeleteKey(_ context.Context, attrs *types.KeyAttributes) error {
	r.setAttrs(attrs)
	return r.deleteKeyErr
}

func (r *recordingBackend) ListKeys(_ context.Context) ([]*types.KeyAttributes, error) {
	return r.listKeys, r.listKeysErr
}

func (r *recordingBackend) RotateKey(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.rotateKeyErr
}

func (r *recordingBackend) Signer(_ context.Context, attrs *types.KeyAttributes) (crypto.Signer, error) {
	r.setAttrs(attrs)
	return nil, r.signerErr
}

func (r *recordingBackend) Decrypter(_ context.Context, attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	r.setAttrs(attrs)
	return nil, r.decrypterErr
}

func (r *recordingBackend) SaveCert(_ context.Context, keyID string, cert *x509.Certificate) error {
	r.setCertKeyID(keyID)
	return r.saveCertErr
}

func (r *recordingBackend) GetCert(_ context.Context, keyID string) (*x509.Certificate, error) {
	r.setCertKeyID(keyID)
	return nil, r.getCertErr
}

func (r *recordingBackend) DeleteCert(_ context.Context, keyID string) error {
	r.setCertKeyID(keyID)
	return r.deleteCertErr
}

func (r *recordingBackend) SaveCertChain(_ context.Context, keyID string, chain []*x509.Certificate) error {
	r.setCertKeyID(keyID)
	return r.saveCertChainErr
}

func (r *recordingBackend) GetCertChain(_ context.Context, keyID string) ([]*x509.Certificate, error) {
	r.setCertKeyID(keyID)
	return nil, r.getCertChainErr
}

func (r *recordingBackend) ListCerts(_ context.Context) ([]string, error) {
	return r.listCerts, r.listCertsErr
}

func (r *recordingBackend) CertExists(_ context.Context, keyID string) (bool, error) {
	r.setCertKeyID(keyID)
	return false, r.certExistsErr
}

func (r *recordingBackend) GetTLSCertificate(_ context.Context, keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	r.setCertKeyID(keyID)
	r.setAttrs(attrs)
	return tls.Certificate{}, r.getTLSCertErr
}

func (r *recordingBackend) GetKeyByID(_ context.Context, keyID string) (crypto.PrivateKey, error) {
	return nil, nil
}

func (r *recordingBackend) GetSignerByID(_ context.Context, keyID string) (crypto.Signer, error) {
	return nil, nil
}

func (r *recordingBackend) GetDecrypterByID(_ context.Context, keyID string) (crypto.Decrypter, error) {
	return nil, nil
}

func (r *recordingBackend) Seal(_ context.Context, data []byte, _ *types.SealOptions) (*types.SealedData, error) {
	return nil, nil
}

func (r *recordingBackend) Unseal(_ context.Context, _ *types.SealedData, _ *types.UnsealOptions) ([]byte, error) {
	return nil, nil
}

func (r *recordingBackend) CanSeal() bool { return false }

func (r *recordingBackend) KeyProvider() types.KeyProvider { return nil }

func (r *recordingBackend) CertStorage() certstore.CertificateStorageAdapter { return nil }

func (r *recordingBackend) SignerStore() store.SignerStorer { return r.signerStoreMock }

func (r *recordingBackend) Close() error { return r.closeErr }

// ============================================================
// helpers
// ============================================================

func newBaseAttrs() *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           "my-key",
		KeyAlgorithm: x509.ECDSA,
	}
}

func generateTestCertTenant(t *testing.T) *x509.Certificate {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// ============================================================
// Tests
// ============================================================

func TestNewTenantScopedBackend_ValidWrapper(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	require.NotNil(t, tsb)
	assert.Equal(t, "acme", tsb.tenantID)
	assert.Same(t, base, tsb.base)
}

// TestTenantScopedBackend_InterfaceCompliance verifies the compile-time check
// embedded in the source file still holds when exercised via a local variable.
func TestTenantScopedBackend_InterfaceCompliance(t *testing.T) {
	var _ Backend = (*TenantScopedBackend)(nil)
}

// TestTenantScopedBackend_SignerStore_Delegates verifies SignerStore reaches
// the base backend's configured store, tenant-scoped rather than passed
// through unchanged: a key saved through the tenant-scoped view is readable
// back through it, but not under its original (unscoped) CN on the base
// store directly.
func TestTenantScopedBackend_SignerStore_Delegates(t *testing.T) {
	baseStore := store.NewSignerStore(nil, storage.New())
	base := &recordingBackend{signerStoreMock: baseStore}
	tsb := NewTenantScopedBackend(base, "acme")

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	attrs := &types.KeyAttributes{CN: "delegated-key", KeyAlgorithm: x509.ECDSA}
	require.NoError(t, tsb.SignerStore().Save(attrs, key))

	// Readable back through the tenant-scoped view.
	got, err := tsb.SignerStore().Get(attrs)
	require.NoError(t, err)
	assert.True(t, key.PublicKey.Equal(got.(*ecdsa.PrivateKey).Public()))

	// Not present under its original CN directly on the base store: the
	// tenant-scoped view reached the base store with a different (prefixed)
	// CN, not the same one it was given.
	_, err = baseStore.Get(attrs)
	assert.Error(t, err)
}

// TestTenantScopedBackend_SignerStore_NilBase verifies SignerStore returns
// nil, not a panic, when the base backend has none configured.
func TestTenantScopedBackend_SignerStore_NilBase(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	assert.Nil(t, tsb.SignerStore())
}

// TestTenantScopedBackend_SignerStore_IsolatesTenantsOnSameBlobCN verifies
// go-xkms#724's tenant-isolation requirement directly: two tenants signing
// under the same key CN and the same BlobCN, against one shared underlying
// SignerStore (as they would sharing one compositeBackend), each read back
// only their own record. Without scoping, the second SaveSignature would
// silently overwrite the first tenant's record -- a cross-tenant integrity
// denial of service, not merely a mix-up, since it destroys the other
// tenant's ability to integrity-check its own blob.
func TestTenantScopedBackend_SignerStore_IsolatesTenantsOnSameBlobCN(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	sharedStore := store.NewSignerStore(nil, storage.New())
	base := &recordingBackend{signerStoreMock: sharedStore}

	tenantA := NewTenantScopedBackend(base, "tenant-a")
	tenantB := NewTenantScopedBackend(base, "tenant-b")

	attrs := &types.KeyAttributes{CN: "shared-key-name"}
	const blobCN = "shared-blob-cn"

	digestA := sha256.Sum256([]byte("tenant a's blob"))
	digestB := sha256.Sum256([]byte("tenant b's blob"))

	sigA, err := ecdsa.SignASN1(rand.Reader, key, digestA[:])
	require.NoError(t, err)
	sigB, err := ecdsa.SignASN1(rand.Reader, key, digestB[:])
	require.NoError(t, err)

	require.NoError(t, tenantA.SignerStore().SaveSignature(
		&store.SignerOpts{KeyAttributes: attrs, BlobCN: blobCN}, sigA, digestA[:]))
	require.NoError(t, tenantB.SignerStore().SaveSignature(
		&store.SignerOpts{KeyAttributes: attrs, BlobCN: blobCN}, sigB, digestB[:]))

	// Tenant A verifying its own blob under the shared BlobCN passes.
	verifierA := types.NewVerifier(&types.VerifyOpts{
		Hash:             crypto.SHA256,
		KeyAttributes:    attrs,
		BlobCN:           blobCN,
		IntegrityCheck:   true,
		ChecksumProvider: tenantA.SignerStore(),
	})
	assert.NoError(t, verifierA.Verify(&key.PublicKey, digestA[:], sigA))

	// Tenant B verifying tenant A's (validly signed) blob under the same
	// BlobCN fails the integrity check: tenant B's SignerStore sees only
	// tenant B's own record for this CN and BlobCN, never tenant A's.
	verifierB := types.NewVerifier(&types.VerifyOpts{
		Hash:             crypto.SHA256,
		KeyAttributes:    attrs,
		BlobCN:           blobCN,
		IntegrityCheck:   true,
		ChecksumProvider: tenantB.SignerStore(),
	})
	err = verifierB.Verify(&key.PublicKey, digestA[:], sigA)
	require.Error(t, err)
	assert.ErrorIs(t, err, types.ErrIntegrityCheckFailed)

	// Tenant B verifying its own blob under the shared BlobCN still passes.
	assert.NoError(t, verifierB.Verify(&key.PublicKey, digestB[:], sigB))
}

// ============================================================
// Key operations – TenantID injection
// ============================================================

func TestTenantScopedBackend_GenerateRSA_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "tenant-a")

	attrs := newBaseAttrs()
	_, _ = tsb.GenerateRSA(context.Background(), attrs)

	got := base.getLastAttrs()
	require.NotNil(t, got)
	assert.Equal(t, "tenant-a", got.TenantID)
	// Original struct must not be mutated.
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_GenerateECDSA_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "tenant-b")

	attrs := newBaseAttrs()
	_, _ = tsb.GenerateECDSA(context.Background(), attrs)

	assert.Equal(t, "tenant-b", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_GenerateEd25519_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "tenant-c")

	attrs := newBaseAttrs()
	_, _ = tsb.GenerateEd25519(context.Background(), attrs)

	assert.Equal(t, "tenant-c", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_GetKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.GetKey(context.Background(), attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_DeleteKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_ = tsb.DeleteKey(context.Background(), attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_RotateKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.RotateKey(context.Background(), attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_Signer_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.Signer(context.Background(), attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_Decrypter_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.Decrypter(context.Background(), attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

// ============================================================
// Key operations – nil attrs handling (scopeAttrs guard)
// ============================================================

func TestTenantScopedBackend_ScopeAttrs_NilPassthrough(t *testing.T) {
	tsb := NewTenantScopedBackend(&recordingBackend{}, "t1")
	// scopeAttrs is called with nil – must return nil, not panic.
	got := tsb.scopeAttrs(nil)
	assert.Nil(t, got)
}

// ============================================================
// Cert operations – keyID prefix
// ============================================================

func TestTenantScopedBackend_SaveCert_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	cert := generateTestCertTenant(t)
	_ = tsb.SaveCert(context.Background(), "server.crt", cert)

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_GetCert_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.GetCert(context.Background(), "server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_DeleteCert_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_ = tsb.DeleteCert(context.Background(), "server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_SaveCertChain_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_ = tsb.SaveCertChain(context.Background(), "ca-chain", nil)

	assert.Equal(t, "acme/ca-chain", base.getLastKeyID())
}

func TestTenantScopedBackend_GetCertChain_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.GetCertChain(context.Background(), "ca-chain")

	assert.Equal(t, "acme/ca-chain", base.getLastKeyID())
}

func TestTenantScopedBackend_CertExists_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.CertExists(context.Background(), "server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_GetTLSCertificate_PrefixesKeyIDAndSetsAttrs(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	attrs := newBaseAttrs()
	_, _ = tsb.GetTLSCertificate(context.Background(), "server.crt", attrs)

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
	assert.Equal(t, "acme", base.getLastAttrs().TenantID)
}

// ============================================================
// Passthrough operations – no tenant scoping
// ============================================================

func TestTenantScopedBackend_ListKeys_HidesOtherTenants(t *testing.T) {
	// A key ID is only unique within a tenant, and findKeyAttrs resolves a key
	// by matching the common name against ListKeys. An unfiltered listing would
	// therefore let one tenant reach another tenant's key by naming it.
	base := &recordingBackend{listKeys: []*types.KeyAttributes{
		{CN: "shared-name", TenantID: "acme"},
		{CN: "shared-name", TenantID: "other"},
		{CN: "other-only", TenantID: "other"},
		{CN: "unscoped"},
	}}
	tsb := NewTenantScopedBackend(base, "acme")

	keys, err := tsb.ListKeys(context.Background())
	require.NoError(t, err)

	require.Len(t, keys, 1, "only the tenant's own keys may be visible")
	assert.Equal(t, "shared-name", keys[0].CN)
	assert.Equal(t, "acme", keys[0].TenantID)
}

func TestTenantScopedBackend_ListKeys_EmptyWhenTenantOwnsNothing(t *testing.T) {
	base := &recordingBackend{listKeys: []*types.KeyAttributes{
		{CN: "a", TenantID: "other"},
		{CN: "b"},
	}}
	tsb := NewTenantScopedBackend(base, "acme")

	keys, err := tsb.ListKeys(context.Background())
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestTenantScopedBackend_ListKeys_PropagatesError(t *testing.T) {
	base := &recordingBackend{listKeysErr: errors.New("backend down")}
	tsb := NewTenantScopedBackend(base, "acme")

	_, err := tsb.ListKeys(context.Background())
	require.Error(t, err)
}

func TestTenantScopedBackend_ListCerts_ScopesToTenantNamespace(t *testing.T) {
	// Every other certificate method addresses storage through scopeCertKeyID,
	// so the listing must apply the same namespace and return tenant-relative
	// key IDs rather than another tenant's entries.
	base := &recordingBackend{listCerts: []string{
		"acme/server", "acme/client", "other/server", "unscoped",
	}}
	tsb := NewTenantScopedBackend(base, "acme")

	certs, err := tsb.ListCerts(context.Background())
	require.NoError(t, err)

	assert.ElementsMatch(t, []string{"server", "client"}, certs)
}

func TestTenantScopedBackend_ListCerts_PropagatesError(t *testing.T) {
	base := &recordingBackend{listCertsErr: errors.New("backend down")}
	tsb := NewTenantScopedBackend(base, "acme")

	_, err := tsb.ListCerts(context.Background())
	require.Error(t, err)
}

func TestTenantScopedBackend_Close_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	err := tsb.Close()
	require.NoError(t, err)
}

// ============================================================
// Table-driven test covering all key operations set TenantID
// ============================================================

func TestTenantScopedBackend_AllKeyOps_SetTenantID(t *testing.T) {
	const tenantID = "org-x"

	tests := []struct {
		name string
		call func(tsb *TenantScopedBackend, base *recordingBackend)
	}{
		{
			name: "GenerateRSA",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				attrs := &types.KeyAttributes{CN: "k"}
				_, _ = tsb.GenerateRSA(context.Background(), attrs)
			},
		},
		{
			name: "GenerateECDSA",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GenerateECDSA(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "GenerateEd25519",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GenerateEd25519(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "GetKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GetKey(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "DeleteKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_ = tsb.DeleteKey(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "RotateKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.RotateKey(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "Signer",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.Signer(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "Decrypter",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.Decrypter(context.Background(), &types.KeyAttributes{CN: "k"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &recordingBackend{}
			tsb := NewTenantScopedBackend(base, tenantID)
			tt.call(tsb, base)
			assert.Equal(t, tenantID, base.getLastAttrs().TenantID, "TenantID not set by %s", tt.name)
		})
	}
}

// ============================================================
// Table-driven test covering all cert operations prefix keyID
// ============================================================

func TestTenantScopedBackend_AllCertOps_PrefixKeyID(t *testing.T) {
	const (
		tenantID = "corp"
		rawKeyID = "leaf"
		wantID   = "corp/leaf"
	)

	tests := []struct {
		name string
		call func(tsb *TenantScopedBackend)
	}{
		{
			name: "SaveCert",
			call: func(tsb *TenantScopedBackend) { _ = tsb.SaveCert(context.Background(), rawKeyID, nil) },
		},
		{
			name: "GetCert",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.GetCert(context.Background(), rawKeyID) },
		},
		{
			name: "DeleteCert",
			call: func(tsb *TenantScopedBackend) { _ = tsb.DeleteCert(context.Background(), rawKeyID) },
		},
		{
			name: "SaveCertChain",
			call: func(tsb *TenantScopedBackend) { _ = tsb.SaveCertChain(context.Background(), rawKeyID, nil) },
		},
		{
			name: "GetCertChain",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.GetCertChain(context.Background(), rawKeyID) },
		},
		{
			name: "CertExists",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.CertExists(context.Background(), rawKeyID) },
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			base := &recordingBackend{}
			tsb := NewTenantScopedBackend(base, tenantID)
			tt.call(tsb)
			assert.Equal(t, wantID, base.getLastKeyID(), "keyID not prefixed by %s", tt.name)
		})
	}
}

// ============================================================
// Verify original attrs are not mutated by scopeAttrs
// ============================================================

func TestTenantScopedBackend_ScopeAttrs_DoesNotMutateOriginal(t *testing.T) {
	tsb := NewTenantScopedBackend(&recordingBackend{}, "tenant-z")

	original := &types.KeyAttributes{
		CN:       "my-key",
		TenantID: "original-tenant",
	}

	// Generate an EC key so scopeAttrs is invoked via GenerateECDSA.
	_, _ = tsb.GenerateECDSA(context.Background(), original)

	// The original struct must still carry its pre-call TenantID.
	assert.Equal(t, "original-tenant", original.TenantID)
}

// ============================================================
// Sealing passthrough – no tenant scoping applied
// ============================================================

func TestTenantScopedBackend_Seal_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t")

	sealed, err := tsb.Seal(context.Background(), []byte("data"), nil)
	require.NoError(t, err)
	assert.Nil(t, sealed)
}

func TestTenantScopedBackend_Unseal_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t")

	data, err := tsb.Unseal(context.Background(), nil, nil)
	require.NoError(t, err)
	assert.Nil(t, data)
}

func TestTenantScopedBackend_CanSeal_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t")
	assert.False(t, tsb.CanSeal())
}

// ============================================================
// Verify ECDSA key generation with a real key in the base mock
// ============================================================

func TestTenantScopedBackend_GenerateECDSA_RealKey(t *testing.T) {
	// Use the service-level mockKeyStore which generates real keys so we can
	// confirm the key actually flows through.
	software := newMockKeyStore("sw")
	tsb := NewTenantScopedBackend(software, "tenant-real")

	key, err := tsb.GenerateECDSA(context.Background(), &types.KeyAttributes{
		CN:           "real-key",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected *ecdsa.PrivateKey")
}

func TestTenantScopedBackend_GenerateRSA_RealKey(t *testing.T) {
	software := newMockKeyStore("sw")
	tsb := NewTenantScopedBackend(software, "tenant-rsa")

	key, err := tsb.GenerateRSA(context.Background(), &types.KeyAttributes{
		CN:           "rsa-key",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(*rsa.PrivateKey)
	assert.True(t, ok, "expected *rsa.PrivateKey")
}

func TestTenantScopedBackend_GenerateEd25519_RealKey(t *testing.T) {
	software := newMockKeyStore("sw")
	tsb := NewTenantScopedBackend(software, "tenant-ed")

	key, err := tsb.GenerateEd25519(context.Background(), &types.KeyAttributes{
		CN:           "ed-key",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(ed25519.PrivateKey)
	assert.True(t, ok, "expected ed25519.PrivateKey")
}

// ============================================================
// Unified Key ID methods and lifecycle accessors — passthrough
// coverage using recordingBackend (canned nil/nil) and mockKeyStore
// (real key material) to exercise both trivial passthrough and
// realistic success/error propagation.
// ============================================================

func TestTenantScopedBackend_GetKeyByID_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	key, err := tsb.GetKeyByID(context.Background(), "some-key")
	require.NoError(t, err)
	assert.Nil(t, key)
}

func TestTenantScopedBackend_GetSignerByID_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	signer, err := tsb.GetSignerByID(context.Background(), "some-key")
	require.NoError(t, err)
	assert.Nil(t, signer)
}

func TestTenantScopedBackend_GetDecrypterByID_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	decrypter, err := tsb.GetDecrypterByID(context.Background(), "some-key")
	require.NoError(t, err)
	assert.Nil(t, decrypter)
}

func TestTenantScopedBackend_KeyProvider_Passthrough(t *testing.T) {
	software := newMockKeyStoreWithSealer("sw", "software")
	tsb := NewTenantScopedBackend(software, "acme")

	kp := tsb.KeyProvider()
	require.NotNil(t, kp)
	assert.Same(t, software.backend, kp)
}

func TestTenantScopedBackend_CertStorage_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	// recordingBackend.CertStorage returns nil; verify the wrapper delegates
	// rather than substituting its own value.
	assert.Nil(t, tsb.CertStorage())
}

func TestTenantScopedBackend_GetKeyByID_RealBackend_Success(t *testing.T) {
	software := newMockKeyStore("sw")
	ctx := context.Background()
	_, err := software.GenerateECDSA(ctx, &types.KeyAttributes{CN: "my-ec-key"})
	require.NoError(t, err)

	tsb := NewTenantScopedBackend(software, "acme")

	key, err := tsb.GetKeyByID(ctx, "my-ec-key")
	require.NoError(t, err)
	require.NotNil(t, key)
	_, ok := key.(*ecdsa.PrivateKey)
	assert.True(t, ok, "expected *ecdsa.PrivateKey")
}

func TestTenantScopedBackend_GetKeyByID_RealBackend_NotFound(t *testing.T) {
	software := newMockKeyStore("sw")
	tsb := NewTenantScopedBackend(software, "acme")

	_, err := tsb.GetKeyByID(context.Background(), "missing-key")
	require.Error(t, err)
}

func TestTenantScopedBackend_GetSignerByID_RealBackend_Success(t *testing.T) {
	software := newMockKeyStore("sw")
	ctx := context.Background()
	_, err := software.GenerateECDSA(ctx, &types.KeyAttributes{CN: "signer-key"})
	require.NoError(t, err)

	tsb := NewTenantScopedBackend(software, "acme")

	signer, err := tsb.GetSignerByID(ctx, "signer-key")
	require.NoError(t, err)
	require.NotNil(t, signer)
}

func TestTenantScopedBackend_GetSignerByID_RealBackend_NotFound(t *testing.T) {
	software := newMockKeyStore("sw")
	tsb := NewTenantScopedBackend(software, "acme")

	_, err := tsb.GetSignerByID(context.Background(), "missing-signer")
	require.Error(t, err)
}

func TestTenantScopedBackend_GetDecrypterByID_RealBackend_Success(t *testing.T) {
	software := newMockKeyStore("sw")
	ctx := context.Background()
	_, err := software.GenerateRSA(ctx, &types.KeyAttributes{CN: "decrypt-key"})
	require.NoError(t, err)

	tsb := NewTenantScopedBackend(software, "acme")

	decrypter, err := tsb.GetDecrypterByID(ctx, "decrypt-key")
	require.NoError(t, err)
	require.NotNil(t, decrypter)
}

func TestTenantScopedBackend_GetDecrypterByID_RealBackend_UnsupportedKey(t *testing.T) {
	software := newMockKeyStore("sw")
	ctx := context.Background()
	// ECDSA keys do not implement crypto.Decrypter in mockKeyStore.
	_, err := software.GenerateECDSA(ctx, &types.KeyAttributes{CN: "ec-decrypt-key"})
	require.NoError(t, err)

	tsb := NewTenantScopedBackend(software, "acme")

	_, err = tsb.GetDecrypterByID(ctx, "ec-decrypt-key")
	require.Error(t, err)
}

// ============================================================
// Cross-tenant key identity over a real backend.
//
// The mock above answers ListKeys from a canned slice whose TenantID the test
// sets itself, so it can only prove the filter reads a field. These tests wire
// a real software backend -- the same pkg/keyprovider/pkcs8 provider the
// service uses -- so the oracle is the stored key itself: the same common name
// under two tenants must be two keys, and each tenant must resolve its own.
// ============================================================

// realTenantBackends returns a Backend backed by a real in-memory software
// key provider, together with tenant-scoped views for tenantA and tenantB.
func realTenantBackends(t *testing.T, tenantA, tenantB string) (Backend, *TenantScopedBackend, *TenantScopedBackend) {
	t.Helper()

	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	base, err := New(&BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })

	return base, NewTenantScopedBackend(base, tenantA), NewTenantScopedBackend(base, tenantB)
}

// tenantTestAttrs builds RSA attributes for cn with no tenant set; the scoped
// backend is what must apply the tenant.
func tenantTestAttrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:            cn,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	}
}

// rsaPublicOf returns the public half of a generated key. The software
// backend hands back an opaque handle rather than the private key itself, so
// the public half is read through crypto.Signer.
func rsaPublicOf(t *testing.T, key crypto.PrivateKey) *rsa.PublicKey {
	t.Helper()
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case crypto.Signer:
		pub, ok := k.Public().(*rsa.PublicKey)
		require.True(t, ok, "expected an RSA public key, got %T", k.Public())
		return pub
	default:
		t.Fatalf("generated key exposes no public half: %T", key)
		return nil
	}
}

// TestTenantScopedBackend_RealBackend_CrossTenantKeyIdentity proves a
// tenant-scoped view resolves the tenant's own key and not another tenant's
// key of the same name.
//
// This is the end-to-end shape the service layer uses: findKeyAttrs matches a
// caller-supplied key ID against the scoped listing, and the resulting
// attributes are handed straight to Signer. While the provider dropped the
// tenant when it reconstructed those attributes, the scoped listing was empty
// and every tenant-scoped operation failed on the tenant's own key.
func TestTenantScopedBackend_RealBackend_CrossTenantKeyIdentity(t *testing.T) {
	ctx := context.Background()
	_, tenantA, tenantB := realTenantBackends(t, "tenant-a", "tenant-b")

	const sharedCN = "shared-name"
	keyA, err := tenantA.GenerateRSA(ctx, tenantTestAttrs(sharedCN))
	require.NoError(t, err)
	keyB, err := tenantB.GenerateRSA(ctx, tenantTestAttrs(sharedCN))
	require.NoError(t, err)

	pubA, pubB := rsaPublicOf(t, keyA), rsaPublicOf(t, keyB)
	require.False(t, pubA.Equal(pubB),
		"the same name under two tenants must be two distinct keys")

	// Each tenant sees exactly its own key, reported as its own.
	listedA, err := tenantA.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, listedA, 1, "tenant-a must see exactly its own key")
	assert.Equal(t, "tenant-a", listedA[0].TenantID)
	assert.Equal(t, sharedCN, listedA[0].CN)

	listedB, err := tenantB.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, listedB, 1, "tenant-b must see exactly its own key")
	assert.Equal(t, "tenant-b", listedB[0].TenantID)

	// The service layer's own resolution path: find by common name, then sign.
	attrsA, err := findKeyAttrs(ctx, tenantA, sharedCN)
	require.NoError(t, err, "a tenant must be able to resolve its own key by name")
	signerA, err := tenantA.Signer(ctx, attrsA)
	require.NoError(t, err)
	assert.True(t, signerA.Public().(*rsa.PublicKey).Equal(pubA),
		"tenant-a resolved a key that is not its own")

	attrsB, err := findKeyAttrs(ctx, tenantB, sharedCN)
	require.NoError(t, err)
	signerB, err := tenantB.Signer(ctx, attrsB)
	require.NoError(t, err)
	assert.True(t, signerB.Public().(*rsa.PublicKey).Equal(pubB),
		"tenant-b resolved a key that is not its own")
}

// TestTenantScopedBackend_RealBackend_ForeignTenantKeyIsUnreachable is the
// negative control: a tenant that owns nothing must not reach another tenant's
// key by naming it, and must not be handed the untenanted key of that name
// either.
func TestTenantScopedBackend_RealBackend_ForeignTenantKeyIsUnreachable(t *testing.T) {
	ctx := context.Background()
	base, tenantA, tenantB := realTenantBackends(t, "tenant-a", "tenant-b")

	const cn = "only-tenant-a-has-this"
	_, err := tenantA.GenerateRSA(ctx, tenantTestAttrs(cn))
	require.NoError(t, err)
	_, err = base.GenerateRSA(ctx, tenantTestAttrs(cn))
	require.NoError(t, err, "an untenanted key of the same name must be storable alongside it")

	listedB, err := tenantB.ListKeys(ctx)
	require.NoError(t, err)
	assert.Empty(t, listedB, "a tenant that owns no key must see none")

	_, err = findKeyAttrs(ctx, tenantB, cn)
	require.Error(t, err, "naming another tenant's key must not resolve it")
	assert.ErrorIs(t, err, ErrKeyNotFound)

	_, err = tenantB.GetKey(ctx, tenantTestAttrs(cn))
	require.Error(t, err, "a tenant must not read another tenant's key material")
}

// TestTenantScopedBackend_RealBackend_UntenantedViewSeesOnlyUntenantedKeys
// covers the single-tenant deployment: an unscoped caller must keep seeing the
// keys it always saw, and must not inherit any tenant's keys.
func TestTenantScopedBackend_RealBackend_UntenantedViewSeesOnlyUntenantedKeys(t *testing.T) {
	ctx := context.Background()
	base, tenantA, _ := realTenantBackends(t, "tenant-a", "tenant-b")

	_, err := base.GenerateRSA(ctx, tenantTestAttrs("plain-key"))
	require.NoError(t, err)
	_, err = tenantA.GenerateRSA(ctx, tenantTestAttrs("tenant-key"))
	require.NoError(t, err)

	// The unscoped backend is the whole store; it is the tenant-scoped view
	// that narrows it.
	all, err := base.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, all, 2)

	attrs, err := findKeyAttrs(ctx, base, "plain-key")
	require.NoError(t, err)
	assert.Empty(t, attrs.TenantID, "an untenanted key must not acquire an owner")

	listedA, err := tenantA.ListKeys(ctx)
	require.NoError(t, err)
	require.Len(t, listedA, 1)
	assert.Equal(t, "tenant-key", listedA[0].CN,
		"a tenant must not be shown the untenanted key")
}
