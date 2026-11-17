package server

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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
		if attrs.CN == tenantLoginCAKeyName(tenantID) {
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

// sharedTenantCABackends returns two backends over one key store and one
// certificate store: two cluster nodes that share the tenants' keys.
func sharedTenantCABackends(t *testing.T) (xkms.Backend, xkms.Backend) {
	t.Helper()
	keys, certs := storage.New(), storage.New()
	open := func() xkms.Backend {
		provider, err := software.NewBackend(&software.Config{KeyStorage: keys})
		require.NoError(t, err)
		base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: certs})
		require.NoError(t, err)
		t.Cleanup(func() { _ = base.Close() })
		return base
	}
	return open(), open()
}

// staleListBackend hides every key from its first hide ListKeys calls: the
// view of a node that looked before another node generated the key.
type staleListBackend struct {
	xkms.Backend
	hide atomic.Int32
}

func (b *staleListBackend) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	if b.hide.Add(-1) >= 0 {
		return nil, nil
	}
	return b.Backend.ListKeys(ctx)
}

// tenantLoginCA returns the public key of the tenant's login CA signer and
// its saved certificate, through the factory.
func tenantLoginCA(t *testing.T, f *tenantCAKeyFactory, tenantID string) (crypto.PublicKey, *x509.Certificate) {
	t.Helper()
	ctx := context.Background()
	p, err := f.ProviderForTenant(tenantID)
	require.NoError(t, err)
	signer, err := p.Signer(ctx)
	require.NoError(t, err)
	cert, err := p.Certificate(ctx)
	require.NoError(t, err)
	require.NotNil(t, cert)
	return signer.Public(), cert
}

// callerLoginCAKey makes a key named like the login CA key in tenantID the
// way a caller could before the name was reserved: through the backend, not
// the provisioning path.
func callerLoginCAKey(t *testing.T, base xkms.Backend, tenantID string) (*xkms.TenantScopedBackend, crypto.Signer) {
	t.Helper()
	ctx := context.Background()
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	_, err := scoped.GenerateECDSA(ctx, &types.KeyAttributes{
		CN:            tenantLoginCAKeyName(tenantID),
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	})
	require.NoError(t, err)
	attrs, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
	require.NoError(t, err)
	signer, err := scoped.Signer(ctx, attrs)
	require.NoError(t, err)
	return scoped, signer
}

// A key named qrdb-login-ca that the provisioning path did not make is a
// collision, not a login CA: before the name was reserved a caller could
// create or import one and keep its private material. The factory neither
// certifies it nor trusts a certificate a caller saved over it.
func TestTenantCAKeyFactory_RefusesKeyWithoutProvisioningProvenance(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t, "tenant-b")

	// tenant-a: a caller's key with a CA certificate the caller made over it.
	scopedA, signerA := callerLoginCAKey(t, base, "tenant-a")
	forged, err := selfSignTenantLoginCA("tenant-a", signerA)
	require.NoError(t, err)
	require.NoError(t, scopedA.SaveCert(ctx, tenantLoginCAKeyCN, forged))
	// tenant-c: a caller's key with no certificate yet.
	scopedC, _ := callerLoginCAKey(t, base, "tenant-c")

	for _, id := range []string{"tenant-a", "tenant-c"} {
		err := f.EnsureTenant(ctx, id)
		assert.ErrorContains(t, err, "collision", id)
		_, err = f.ProviderForTenant(id)
		assert.Error(t, err, "a caller's key is served as %s's login CA", id)
	}

	exists, err := scopedC.CertExists(ctx, tenantLoginCAKeyCN)
	require.NoError(t, err)
	assert.False(t, exists, "a login CA certificate was issued over a caller's key")

	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	assert.NotContains(t, ids, "tenant-a")
	assert.NotContains(t, ids, "tenant-c")
	assert.Contains(t, ids, "tenant-b")
}

func TestTenantCAKeyFactory_ConcurrentNodesConverge(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(baseA))
	b := newTenantCAKeyFactory()
	stale := &staleListBackend{Backend: baseB}
	stale.hide.Store(1)
	require.NoError(t, b.Bind(stale))

	// Node A provisions first; node B had looked before A generated the key,
	// so its generate collides with A's key.
	require.NoError(t, a.EnsureTenant(ctx, "tenant-a"))
	require.NoError(t, b.EnsureTenant(ctx, "tenant-a"), "a key another node provisioned is not a failure")

	pubA, certA := tenantLoginCA(t, a, "tenant-a")
	pubB, certB := tenantLoginCA(t, b, "tenant-a")
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(pubB), "both nodes must resolve the one persisted key")
	assert.True(t, certA.Equal(certB), "both nodes must resolve the one saved certificate")
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(certA.PublicKey), "the certificate must be over the persisted key")

	// Both at once, on a fresh tenant.
	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, f := range []*tenantCAKeyFactory{a, b} {
		wg.Add(1)
		go func(i int, f *tenantCAKeyFactory) {
			defer wg.Done()
			errs[i] = f.EnsureTenant(ctx, "tenant-b")
		}(i, f)
	}
	wg.Wait()
	require.NoError(t, errs[0])
	require.NoError(t, errs[1])
	pubA, certA = tenantLoginCA(t, a, "tenant-b")
	pubB, _ = tenantLoginCA(t, b, "tenant-b")
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(pubB))
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(certA.PublicKey))
}

// failSaveCertBackend fails its first fail SaveCert calls: a store outage, or
// a process that stopped between the key and the certificate.
type failSaveCertBackend struct {
	xkms.Backend
	fail atomic.Int32
}

func (b *failSaveCertBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	// Only the login CA certificate save fails; the provenance record the
	// provisioning path writes first goes through.
	if !strings.HasSuffix(keyID, tenantLoginCAProvenanceID) && b.fail.Add(-1) >= 0 {
		return errors.New("certificate store unavailable")
	}
	return b.Backend.SaveCert(ctx, keyID, cert)
}

func TestTenantCAKeyFactory_RetryAfterSaveCertFailure(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	flaky := &failSaveCertBackend{Backend: base}
	flaky.fail.Store(1)
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(flaky))

	require.Error(t, f.EnsureTenant(ctx, "tenant-a"), "a failed certificate save must fail provisioning")
	before := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)

	// The key is left behind without a certificate; the retry must finish it.
	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	pub, cert := tenantLoginCA(t, f, "tenant-a")
	assert.True(t, before.Equal(pub), "the retry must keep the existing key")
	assert.True(t, before.Equal(cert.PublicKey), "the retry must issue the certificate over the existing key")
	assert.True(t, cert.IsCA)
}

// The lazy path (go-qrdb's native onboarding asking for a tenant's login CA)
// must not take a key left behind by a failed certificate save as a
// provisioned login CA: once the store recovers, the next request finishes
// provisioning over the same key.
func TestTenantCAKeyFactory_LazyRetryAfterSaveCertFailure(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	flaky := &failSaveCertBackend{Backend: base}
	flaky.fail.Store(1)
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(flaky))
	f.TrackTenants(&fakeTenantService{tenants: []string{"tenant-a"}})

	_, err := f.ProviderForTenant("tenant-a")
	require.Error(t, err, "a failed certificate save must fail the lazy provisioning")
	before := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)

	p, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	cert, err := p.Certificate(ctx)
	require.NoError(t, err, "the lazy retry must save the login CA certificate")
	assert.True(t, before.Equal(cert.PublicKey), "the lazy retry must keep the existing key")
	assert.True(t, cert.IsCA)
}

// cloudKMSLikeProvider creates the key but, like the AWS KMS, Azure Key Vault
// and GCP KMS providers, returns no key from generation: the public key is
// only reachable afterwards through Signer. It records the CN each key was
// generated under, the name those providers address a key by.
type cloudKMSLikeProvider struct {
	types.KeyProvider
	mu        sync.Mutex
	generated []string
}

func (p *cloudKMSLikeProvider) GenerateKey(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if _, err := p.KeyProvider.GenerateKey(ctx, attrs); err != nil {
		return nil, err
	}
	p.mu.Lock()
	p.generated = append(p.generated, attrs.CN)
	p.mu.Unlock()
	return nil, nil
}

// A backend that returns no public key at generation still provisions each
// tenant's login CA over the remote key, under a key name that keeps the
// tenant.
func TestTenantCAKeyFactory_BackendWithoutPublicKeyAtGeneration(t *testing.T) {
	ctx := context.Background()
	inner, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	provider := &cloudKMSLikeProvider{KeyProvider: inner}
	base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })

	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(base))
	tenants := []string{"tenant-a", "tenant-b"}
	f.TrackTenants(&fakeTenantService{tenants: tenants})

	for _, id := range tenants {
		require.NoError(t, f.EnsureTenant(ctx, id), "provisioning %s", id)
		p, err := f.ProviderForTenant(id)
		require.NoError(t, err)
		cert, err := p.Certificate(ctx)
		require.NoError(t, err)
		remote := tenantSignerPublic(t, base, id).(*ecdsa.PublicKey)
		assert.True(t, remote.Equal(cert.PublicKey), "the %s login CA must certify the remote key", id)
		assert.True(t, cert.IsCA)
	}

	provider.mu.Lock()
	defer provider.mu.Unlock()
	require.Len(t, provider.generated, len(tenants))
	assert.NotEqual(t, provider.generated[0], provider.generated[1],
		"a provider that addresses keys by name must get one name per tenant")
}

// tenantlessListProvider also lists keys the way the AWS KMS, Azure Key
// Vault and GCP KMS providers do: by name, without the TenantID they were
// generated under.
type tenantlessListProvider struct {
	*cloudKMSLikeProvider
}

func (p *tenantlessListProvider) ListKeys(ctx context.Context) ([]*types.KeyAttributes, error) {
	keys, err := p.KeyProvider.ListKeys(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]*types.KeyAttributes, 0, len(keys))
	for _, attrs := range keys {
		if attrs == nil {
			continue
		}
		listed := *attrs
		listed.TenantID = ""
		out = append(out, &listed)
	}
	return out, nil
}

// On a provider that lists keys without their TenantID, each tenant's login
// CA key is still found by its name: it is enumerated, signs, and is never
// generated twice.
func TestTenantCAKeyFactory_ProviderListsKeysWithoutTenant(t *testing.T) {
	ctx := context.Background()
	inner, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)
	provider := &tenantlessListProvider{cloudKMSLikeProvider: &cloudKMSLikeProvider{KeyProvider: inner}}
	base, err := xkms.New(&xkms.BackendConfig{Backend: provider, CertStorage: storage.New()})
	require.NoError(t, err)
	t.Cleanup(func() { _ = base.Close() })

	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(base))
	tenants := []string{"tenant-a", "tenant-b"}
	f.TrackTenants(&fakeTenantService{tenants: tenants})

	for _, id := range tenants {
		require.NoError(t, f.EnsureTenant(ctx, id), "provisioning %s", id)
	}
	// A second boot pass finds the keys instead of generating new ones.
	for _, id := range tenants {
		require.NoError(t, f.EnsureTenant(ctx, id), "reprovisioning %s", id)
		p, err := f.ProviderForTenant(id)
		require.NoError(t, err)
		signer, err := p.Signer(ctx)
		require.NoError(t, err, "the %s login CA signer must resolve", id)
		cert, err := p.Certificate(ctx)
		require.NoError(t, err)
		assert.True(t, signer.Public().(*ecdsa.PublicKey).Equal(cert.PublicKey), "the %s login CA must certify its signer", id)
	}
	provider.mu.Lock()
	assert.Len(t, provider.generated, len(tenants), "each tenant's key is generated once")
	provider.mu.Unlock()

	ids, err := f.TenantIDs(ctx)
	require.NoError(t, err)
	assert.ElementsMatch(t, tenants, ids)
}

// fixedSlotProvider reports what a YubiKey PIV backend configured with one
// slot reports: every key it generates lands in that slot, whatever its name.
type fixedSlotProvider struct{ types.KeyProvider }

func (fixedSlotProvider) FixedKeySlot() bool { return true }

// fixedSlotBackend is a backend whose key provider has a fixed slot; it
// counts the keys generated on it.
type fixedSlotBackend struct {
	xkms.Backend
	generated atomic.Int32
}

func (b *fixedSlotBackend) KeyProvider() types.KeyProvider {
	return fixedSlotProvider{b.Backend.KeyProvider()}
}

func (b *fixedSlotBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.generated.Add(1)
	return b.Backend.GenerateECDSA(ctx, attrs)
}

// Every tenant's login CA on a fixed-slot backend would be the same
// hardware key: the second tenant's generate overwrites the first's slot.
// The factory refuses such a backend before it generates anything.
func TestTenantCAKeyFactory_RefusesFixedSlotBackend(t *testing.T) {
	_, base := newTenantCAKeyTestFactory(t)
	piv := &fixedSlotBackend{Backend: base}
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(piv))

	for _, tenant := range []string{"tenant-a", "tenant-b"} {
		err := f.EnsureTenant(context.Background(), tenant)
		require.Error(t, err, tenant)
		assert.ErrorContains(t, err, "fixed key slot")
	}
	assert.Zero(t, piv.generated.Load(), "no key may be generated on a fixed-slot backend")
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
