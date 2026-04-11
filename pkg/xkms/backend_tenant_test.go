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
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
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
	mu sync.Mutex

	lastAttrs *types.KeyAttributes
	lastKeyID string

	// Canned return values.
	generateRSAErr   error
	generateECDSAErr error
	generateEd25519Err error
	getKeyErr        error
	deleteKeyErr     error
	rotateKeyErr     error
	signerErr        error
	decrypterErr     error
	saveCertErr      error
	getCertErr       error
	deleteCertErr    error
	saveCertChainErr error
	getCertChainErr  error
	certExistsErr    error
	getTLSCertErr    error
	closeErr         error
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

func (r *recordingBackend) GenerateRSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateRSAErr
}

func (r *recordingBackend) GenerateECDSA(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateECDSAErr
}

func (r *recordingBackend) GenerateEd25519(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.generateEd25519Err
}

func (r *recordingBackend) GetKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.getKeyErr
}

func (r *recordingBackend) DeleteKey(attrs *types.KeyAttributes) error {
	r.setAttrs(attrs)
	return r.deleteKeyErr
}

func (r *recordingBackend) ListKeys() ([]*types.KeyAttributes, error) {
	return nil, nil
}

func (r *recordingBackend) RotateKey(attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	r.setAttrs(attrs)
	return nil, r.rotateKeyErr
}

func (r *recordingBackend) Signer(attrs *types.KeyAttributes) (crypto.Signer, error) {
	r.setAttrs(attrs)
	return nil, r.signerErr
}

func (r *recordingBackend) Decrypter(attrs *types.KeyAttributes) (crypto.Decrypter, error) {
	r.setAttrs(attrs)
	return nil, r.decrypterErr
}

func (r *recordingBackend) SaveCert(keyID string, cert *x509.Certificate) error {
	r.setCertKeyID(keyID)
	return r.saveCertErr
}

func (r *recordingBackend) GetCert(keyID string) (*x509.Certificate, error) {
	r.setCertKeyID(keyID)
	return nil, r.getCertErr
}

func (r *recordingBackend) DeleteCert(keyID string) error {
	r.setCertKeyID(keyID)
	return r.deleteCertErr
}

func (r *recordingBackend) SaveCertChain(keyID string, chain []*x509.Certificate) error {
	r.setCertKeyID(keyID)
	return r.saveCertChainErr
}

func (r *recordingBackend) GetCertChain(keyID string) ([]*x509.Certificate, error) {
	r.setCertKeyID(keyID)
	return nil, r.getCertChainErr
}

func (r *recordingBackend) ListCerts() ([]string, error) {
	return nil, nil
}

func (r *recordingBackend) CertExists(keyID string) (bool, error) {
	r.setCertKeyID(keyID)
	return false, r.certExistsErr
}

func (r *recordingBackend) GetTLSCertificate(keyID string, attrs *types.KeyAttributes) (tls.Certificate, error) {
	r.setCertKeyID(keyID)
	r.setAttrs(attrs)
	return tls.Certificate{}, r.getTLSCertErr
}

func (r *recordingBackend) GetKeyByID(keyID string) (crypto.PrivateKey, error) {
	return nil, nil
}

func (r *recordingBackend) GetSignerByID(keyID string) (crypto.Signer, error) {
	return nil, nil
}

func (r *recordingBackend) GetDecrypterByID(keyID string) (crypto.Decrypter, error) {
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

// ============================================================
// Key operations – TenantID injection
// ============================================================

func TestTenantScopedBackend_GenerateRSA_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "tenant-a")

	attrs := newBaseAttrs()
	_, _ = tsb.GenerateRSA(attrs)

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
	_, _ = tsb.GenerateECDSA(attrs)

	assert.Equal(t, "tenant-b", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_GenerateEd25519_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "tenant-c")

	attrs := newBaseAttrs()
	_, _ = tsb.GenerateEd25519(attrs)

	assert.Equal(t, "tenant-c", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_GetKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.GetKey(attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
	assert.Empty(t, attrs.TenantID)
}

func TestTenantScopedBackend_DeleteKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_ = tsb.DeleteKey(attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_RotateKey_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.RotateKey(attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_Signer_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.Signer(attrs)

	assert.Equal(t, "t1", base.getLastAttrs().TenantID)
}

func TestTenantScopedBackend_Decrypter_SetsTenantID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "t1")

	attrs := newBaseAttrs()
	_, _ = tsb.Decrypter(attrs)

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
	_ = tsb.SaveCert("server.crt", cert)

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_GetCert_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.GetCert("server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_DeleteCert_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_ = tsb.DeleteCert("server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_SaveCertChain_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_ = tsb.SaveCertChain("ca-chain", nil)

	assert.Equal(t, "acme/ca-chain", base.getLastKeyID())
}

func TestTenantScopedBackend_GetCertChain_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.GetCertChain("ca-chain")

	assert.Equal(t, "acme/ca-chain", base.getLastKeyID())
}

func TestTenantScopedBackend_CertExists_PrefixesKeyID(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	_, _ = tsb.CertExists("server.crt")

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
}

func TestTenantScopedBackend_GetTLSCertificate_PrefixesKeyIDAndSetsAttrs(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	attrs := newBaseAttrs()
	_, _ = tsb.GetTLSCertificate("server.crt", attrs)

	assert.Equal(t, "acme/server.crt", base.getLastKeyID())
	assert.Equal(t, "acme", base.getLastAttrs().TenantID)
}

// ============================================================
// Passthrough operations – no tenant scoping
// ============================================================

func TestTenantScopedBackend_ListKeys_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	keys, err := tsb.ListKeys()
	require.NoError(t, err)
	assert.Nil(t, keys)
}

func TestTenantScopedBackend_ListCerts_Passthrough(t *testing.T) {
	base := &recordingBackend{}
	tsb := NewTenantScopedBackend(base, "acme")

	certs, err := tsb.ListCerts()
	require.NoError(t, err)
	assert.Nil(t, certs)
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
				_, _ = tsb.GenerateRSA(attrs)
			},
		},
		{
			name: "GenerateECDSA",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GenerateECDSA(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "GenerateEd25519",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GenerateEd25519(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "GetKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.GetKey(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "DeleteKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_ = tsb.DeleteKey(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "RotateKey",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.RotateKey(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "Signer",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.Signer(&types.KeyAttributes{CN: "k"})
			},
		},
		{
			name: "Decrypter",
			call: func(tsb *TenantScopedBackend, _ *recordingBackend) {
				_, _ = tsb.Decrypter(&types.KeyAttributes{CN: "k"})
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
			call: func(tsb *TenantScopedBackend) { _ = tsb.SaveCert(rawKeyID, nil) },
		},
		{
			name: "GetCert",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.GetCert(rawKeyID) },
		},
		{
			name: "DeleteCert",
			call: func(tsb *TenantScopedBackend) { _ = tsb.DeleteCert(rawKeyID) },
		},
		{
			name: "SaveCertChain",
			call: func(tsb *TenantScopedBackend) { _ = tsb.SaveCertChain(rawKeyID, nil) },
		},
		{
			name: "GetCertChain",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.GetCertChain(rawKeyID) },
		},
		{
			name: "CertExists",
			call: func(tsb *TenantScopedBackend) { _, _ = tsb.CertExists(rawKeyID) },
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
	_, _ = tsb.GenerateECDSA(original)

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

	key, err := tsb.GenerateECDSA(&types.KeyAttributes{
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

	key, err := tsb.GenerateRSA(&types.KeyAttributes{
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

	key, err := tsb.GenerateEd25519(&types.KeyAttributes{
		CN:           "ed-key",
		KeyAlgorithm: x509.Ed25519,
	})
	require.NoError(t, err)
	require.NotNil(t, key)

	_, ok := key.(ed25519.PrivateKey)
	assert.True(t, ok, "expected ed25519.PrivateKey")
}
