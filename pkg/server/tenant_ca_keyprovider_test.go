package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newTenantCAKeyTestFactory returns a factory bound to a real software
// backend, with the given tenants' login CA keys provisioned.
func newTenantCAKeyTestFactory(t *testing.T, tenants ...string) (*tenantCAKeyFactory, xkms.Backend) {
	t.Helper()
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })

	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(base))
	for _, id := range tenants {
		require.NoError(t, f.EnsureTenant(context.Background(), id))
	}
	return f, base
}

// tenantSignerPublic is the tenant's login CA public key as xkms reports it,
// read through the tenant-scoped backend and not through the factory.
func tenantSignerPublic(t *testing.T, base xkms.Backend, tenantID string) crypto.PublicKey {
	t.Helper()
	ctx := context.Background()
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	keys, err := scoped.ListKeys(ctx)
	require.NoError(t, err)
	for _, attrs := range keys {
		if attrs.CN == tenantLoginCAKeyCN {
			signer, err := scoped.Signer(ctx, attrs)
			require.NoError(t, err)
			return signer.Public()
		}
	}
	t.Fatalf("tenant %q has no login CA key in the backend", tenantID)
	return nil
}

func TestTenantCAKeyFactory_ProviderSignerIsTenantKey(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t, "tenant-a")

	p, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	signer, err := p.Signer(ctx)
	require.NoError(t, err)

	want := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)
	assert.True(t, want.Equal(signer.Public()), "the provider's signer is not the tenant-scoped xkms key")

	cert, err := p.Certificate(ctx)
	require.NoError(t, err)
	assert.True(t, cert.IsCA, "the login CA certificate must be a CA")
	assert.True(t, want.Equal(cert.PublicKey), "the certificate does not carry the tenant's key")
	assert.Contains(t, cert.Subject.OrganizationalUnit, "tenant-a")
}

func TestTenantCAKeyFactory_TenantsGetDifferentKeys(t *testing.T) {
	ctx := context.Background()
	f, _ := newTenantCAKeyTestFactory(t, "tenant-a", "tenant-b")

	pa, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	pb, err := f.ProviderForTenant("tenant-b")
	require.NoError(t, err)
	sa, err := pa.Signer(ctx)
	require.NoError(t, err)
	sb, err := pb.Signer(ctx)
	require.NoError(t, err)

	assert.False(t, sa.Public().(*ecdsa.PublicKey).Equal(sb.Public()),
		"two tenants must never share a login CA key")
}

func TestTenantCAKeyFactory_UnknownTenant(t *testing.T) {
	f, _ := newTenantCAKeyTestFactory(t, "tenant-a")

	_, err := f.ProviderForTenant("tenant-z")
	require.Error(t, err)
	_, err = f.ProviderForTenant("")
	require.Error(t, err)
}

func TestTenantCAKeyFactory_Unbound(t *testing.T) {
	f := newTenantCAKeyFactory()
	_, err := f.ProviderForTenant("tenant-a")
	require.Error(t, err)
	_, err = f.TenantIDs(context.Background())
	require.Error(t, err)
	require.Error(t, f.Bind(nil))
}

func TestTenantCAKeyFactory_TenantIDs(t *testing.T) {
	f, _ := newTenantCAKeyTestFactory(t, "tenant-b", "tenant-a")

	ids, err := f.TenantIDs(context.Background())
	require.NoError(t, err)
	assert.Equal(t, []string{"tenant-a", "tenant-b"}, ids)
}

func TestTenantCAKeyFactory_EnsureTenantIsIdempotent(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t, "tenant-a")
	before := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)

	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	after := tenantSignerPublic(t, base, "tenant-a")
	assert.True(t, before.Equal(after), "EnsureTenant replaced an existing login CA key")
	require.Error(t, f.EnsureTenant(ctx, ""))
}

func TestTenantCAKeyFactory_SignatureVerifies(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t, "tenant-a")

	p, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	signer, err := p.Signer(ctx)
	require.NoError(t, err)

	digest := sha256.Sum256([]byte("login certificate tbs"))
	sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	require.NoError(t, err)

	pub := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)
	assert.True(t, ecdsa.VerifyASN1(pub, digest[:], sig), "the provider's signature does not verify with the xkms public key")
}

func TestTenantCAKeyProviderOptions(t *testing.T) {
	s := &Server{config: &config.Config{CA: ca.DefaultMultiIdentityCAConfigWithIntermediate()}}
	if opts := s.tenantCAKeyProviderOptions(); len(opts) != 1 {
		t.Fatalf("tenantCAKeyProviderOptions() returned %d options, want 1", len(opts))
	}
	// No backend is loaded yet: the factory refuses until one is.
	if _, err := s.tenantCAKeyBackend(); err == nil {
		t.Fatal("tenantCAKeyBackend() resolved a backend on a server with none")
	}
}

func TestTenantCAKeyProviderOptions_NoCA(t *testing.T) {
	s := &Server{config: &config.Config{}}
	if opts := s.tenantCAKeyProviderOptions(); len(opts) != 0 {
		t.Fatalf("tenantCAKeyProviderOptions() returned %d options, want 0", len(opts))
	}
}
