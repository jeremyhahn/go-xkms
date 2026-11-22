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
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/internal/keyslot"
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
	require.NoError(t, f.Bind(base, storage.New()))
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
	require.Error(t, f.Bind(nil, storage.New()))
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
	claims := storage.New() // shared by the nodes, as the server's shared storage is
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(baseA, claims))
	b := newTenantCAKeyFactory()
	stale := &staleListBackend{Backend: baseB}
	stale.hide.Store(1)
	require.NoError(t, b.Bind(stale, claims))

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
	// Only the login CA certificate save fails; the records the provisioning
	// path writes first go through.
	if strings.HasSuffix(keyID, tenantLoginCAKeyCN) && b.fail.Add(-1) >= 0 {
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
	require.NoError(t, f.Bind(flaky, storage.New()))

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
	require.NoError(t, f.Bind(flaky, storage.New()))
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
	require.NoError(t, f.Bind(base, storage.New()))
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
	require.NoError(t, f.Bind(base, storage.New()))
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

// failProvenanceSaveBackend fails the provenance record save while fail is
// positive, the way a store that is down right after key generation does.
type failProvenanceSaveBackend struct {
	xkms.Backend
	fail atomic.Int32
}

func (b *failProvenanceSaveBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	if strings.HasSuffix(keyID, tenantLoginCAProvenanceID) && b.fail.Add(-1) >= 0 {
		return errors.New("certificate store unavailable")
	}
	return b.Backend.SaveCert(ctx, keyID, cert)
}

// A provisioning pass that generated the key but could not record its
// provenance is finished by the next pass over the same key, once the store
// is back, instead of being refused as a collision forever.
func TestTenantCAKeyFactory_RecoversAfterFailedProvenanceSave(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	flaky := &failProvenanceSaveBackend{Backend: base}
	flaky.fail.Store(1)
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(flaky, storage.New()))

	require.Error(t, f.EnsureTenant(ctx, "tenant-a"), "a failed provenance save must fail the pass")
	before := tenantSignerPublic(t, base, "tenant-a").(*ecdsa.PublicKey)

	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"), "the next pass must recover the interrupted provisioning")
	p, err := f.ProviderForTenant("tenant-a")
	require.NoError(t, err)
	cert, err := p.Certificate(ctx)
	require.NoError(t, err)
	assert.True(t, before.Equal(cert.PublicKey), "the recovery must keep the generated key")
	assert.True(t, cert.IsCA)
}

// fixedSlotProvider reports what a YubiKey PIV backend configured with one
// slot reports: every key it generates lands in that slot, whatever its name.
type fixedSlotProvider struct{ types.KeyProvider }

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
	t.Cleanup(keyslot.Register(func(p any) (bool, bool) {
		_, ok := p.(fixedSlotProvider)
		return ok, ok
	}))
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(piv, storage.New()))

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

// An existing cluster-CA deployment keeps go-qrdb's persisted tenant login
// CAs on upgrade: without the explicit opt-in the factory is not wired, so
// login certificates those CAs issued keep their trusted issuer (Codex P1,
// review 5935040469).
func TestTenantCAKeyProviderOptions_NotOptedIn(t *testing.T) {
	s := &Server{config: &config.Config{CA: ca.DefaultMultiIdentityCAConfigWithIntermediate()}}
	if opts := s.tenantCAKeyProviderOptions(); len(opts) != 0 {
		t.Fatalf("tenantCAKeyProviderOptions() returned %d options without the opt-in, want 0", len(opts))
	}
	if s.tenantCAKeys != nil {
		t.Fatal("the tenant CA key factory was bound without the opt-in")
	}
}

func TestTenantCAKeyProviderOptions(t *testing.T) {
	s := &Server{config: &config.Config{CA: ca.DefaultMultiIdentityCAConfigWithIntermediate()}}
	WithTenantLoginCAKeys()(s)
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

// A pass that loses the provisioning claim must not generate: while the
// claim holder has made no key, the pass reports the held claim and the
// backend stays without a login CA key for the tenant.
func TestTenantCAKeyFactory_HeldClaimWithoutKeyDoesNotGenerate(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t)
	held := []byte(time.Now().UTC().Format(time.RFC3339Nano))
	stored, err := f.claims.PutIfAbsent(ctx, tenantLoginCAClaimKey("tenant-a"), held)
	require.NoError(t, err)
	require.True(t, stored)

	err = f.EnsureTenant(ctx, "tenant-a")
	require.ErrorIs(t, err, errTenantLoginCAClaimHeld)
	_, lookupErr := tenantLoginCAKeyAttrs(ctx, base, "tenant-a")
	assert.Error(t, lookupErr, "a pass without the claim generated a key")
}

// A claim older than the lease with no key behind it was left by a pass that
// stopped before generating; a later pass takes it over and provisions.
func TestTenantCAKeyFactory_TakesOverStaleClaim(t *testing.T) {
	ctx := context.Background()
	f, _ := newTenantCAKeyTestFactory(t)
	key := tenantLoginCAClaimKey("tenant-a")
	stale := []byte(time.Now().Add(-2 * tenantLoginCAClaimLease).UTC().Format(time.RFC3339Nano))
	stored, err := f.claims.PutIfAbsent(ctx, key, stale)
	require.NoError(t, err)
	require.True(t, stored)

	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	pub, cert := tenantLoginCA(t, f, "tenant-a")
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(cert.PublicKey))
	current, err := f.claims.Get(ctx, key)
	require.NoError(t, err)
	assert.NotEqual(t, stale, current, "the stale claim must be replaced by the pass that took it over")
}

// listFailBackend fails every ListKeys with err, the way a key store that is
// down or refuses the caller does, and counts what the provisioning path
// writes through it.
type listFailBackend struct {
	xkms.Backend
	err       error
	saves     atomic.Int32
	generated atomic.Int32
}

func (b *listFailBackend) ListKeys(context.Context) ([]*types.KeyAttributes, error) {
	return nil, b.err
}

func (b *listFailBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	b.saves.Add(1)
	return b.Backend.SaveCert(ctx, keyID, cert)
}

func (b *listFailBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.generated.Add(1)
	return b.Backend.GenerateECDSA(ctx, attrs)
}

// A key lookup that fails is not a missing key: the pass reports the
// failure and neither claims, records intent nor generates (Codex P1,
// review 5972263613).
func TestTenantCAKeyFactory_LookupFailureIsNotAbsence(t *testing.T) {
	ctx := context.Background()
	_, base := newTenantCAKeyTestFactory(t)
	outage := errors.New("key store unavailable")
	broken := &listFailBackend{Backend: base, err: outage}
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(broken, storage.New()))

	err := f.EnsureTenant(ctx, "tenant-a")
	require.ErrorIs(t, err, outage)
	assert.Zero(t, broken.saves.Load(), "a pass that could not look the key up recorded provisioning intent")
	assert.Zero(t, broken.generated.Load(), "a pass that could not look the key up generated a key")
	_, err = f.claims.Get(ctx, tenantLoginCAClaimKey("tenant-a"))
	assert.ErrorIs(t, err, storage.ErrNotFound, "a pass that could not look the key up took the claim")
}

// delayedProvisionerBackend stalls its provisioner after the claim: on the
// first intent record it runs pause, the way a process that is descheduled
// past the claim lease does, and it counts the keys generated through it.
type delayedProvisionerBackend struct {
	xkms.Backend
	pause     func()
	once      sync.Once
	generated atomic.Int32
}

func (b *delayedProvisionerBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	if strings.HasSuffix(keyID, tenantLoginCAIntentID) {
		b.once.Do(b.pause)
	}
	return b.Backend.SaveCert(ctx, keyID, cert)
}

func (b *delayedProvisionerBackend) GenerateECDSA(ctx context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	b.generated.Add(1)
	return b.Backend.GenerateECDSA(ctx, attrs)
}

// A claim older than the lease does not prove its owner stopped: a
// provisioner delayed past the lease, whose claim another node took over,
// must not generate once it resumes, and converges on the key the new
// owner made (Codex P1, review 5972263613).
func TestTenantCAKeyFactory_FencesDelayedProvisioner(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	claims := storage.New() // shared by the nodes, as the server's shared storage is
	key := tenantLoginCAClaimKey("tenant-a")
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(baseB, claims))
	var errB error
	delayed := &delayedProvisionerBackend{Backend: baseA}
	delayed.pause = func() {
		// A's claim ages past the lease while A is stalled.
		held, err := claims.Get(ctx, key)
		require.NoError(t, err)
		owner := ""
		if i := strings.IndexByte(string(held), ' '); i >= 0 {
			owner = string(held[i:])
		}
		aged := time.Now().Add(-2*tenantLoginCAClaimLease).UTC().Format(time.RFC3339Nano) + owner
		require.NoError(t, claims.Put(ctx, key, []byte(aged)))
		errB = b.EnsureTenant(ctx, "tenant-a")
	}
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(delayed, claims))

	require.NoError(t, a.EnsureTenant(ctx, "tenant-a"))
	require.NoError(t, errB, "the node that took over the stale claim must provision")
	assert.Zero(t, delayed.generated.Load(), "the provisioner whose claim was taken over generated a key")
	pubA, certA := tenantLoginCA(t, a, "tenant-a")
	pubB, certB := tenantLoginCA(t, b, "tenant-a")
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(pubB), "both nodes must resolve the one persisted key")
	assert.True(t, certA.Equal(certB))
}

// stalledGenerateBackend stalls its provisioner inside the generate call,
// after the claim's lease was renewed: the first GenerateECDSA runs pause
// before it generates, and it ignores its context, the way a PKCS#11
// generate waiting on the token's mutex does. It counts the keys generated
// through it.
type stalledGenerateBackend struct {
	xkms.Backend
	pause     func()
	once      sync.Once
	generated atomic.Int32
}

func (b *stalledGenerateBackend) GenerateECDSA(_ context.Context, attrs *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.pause != nil {
		b.once.Do(b.pause)
	}
	b.generated.Add(1)
	return b.Backend.GenerateECDSA(context.Background(), attrs)
}

// A pass that renewed its lease and then stalls in a generate that ignores
// its context may still make its key: however long the stall, no other node
// takes the claim over and generates a second key beside it (Codex P1,
// review 5985869980).
func TestTenantCAKeyFactory_NoTakeoverWhileGenerateInFlight(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	claims := storage.New() // shared by the nodes, as the server's shared storage is
	key := tenantLoginCAClaimKey("tenant-a")
	nodeB := &stalledGenerateBackend{Backend: baseB}
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(nodeB, claims))
	var errB error
	nodeA := &stalledGenerateBackend{Backend: baseA}
	nodeA.pause = func() {
		// A's renewed claim ages past the lease while A's generate is
		// stuck, and no key is visible yet.
		held, err := claims.Get(ctx, key)
		require.NoError(t, err)
		_, rest, _ := strings.Cut(string(held), " ")
		aged := time.Now().Add(-2*tenantLoginCAClaimLease).UTC().Format(time.RFC3339Nano) + " " + rest
		require.NoError(t, claims.Put(ctx, key, []byte(aged)))
		errB = b.EnsureTenant(ctx, "tenant-a")
	}
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(nodeA, claims))

	require.NoError(t, a.EnsureTenant(ctx, "tenant-a"))
	require.ErrorIs(t, errB, errTenantLoginCAClaimHeld, "the claim of a pass whose generate is in flight must stay held")
	assert.Zero(t, nodeB.generated.Load(), "a node took over the claim of a pass whose generate was in flight and generated a second key")
	assert.EqualValues(t, 1, nodeA.generated.Load())

	require.NoError(t, b.EnsureTenant(ctx, "tenant-a"))
	pubA, certA := tenantLoginCA(t, a, "tenant-a")
	pubB, certB := tenantLoginCA(t, b, "tenant-a")
	assert.True(t, pubA.(*ecdsa.PublicKey).Equal(pubB), "both nodes must resolve the one persisted key")
	assert.True(t, certA.Equal(certB))
}

// renewFailingClaims is a node's view of the shared claim storage that, once
// cut, refuses every compare-and-swap: the node lost access to claim storage.
type renewFailingClaims struct {
	storage.Backend
	cut atomic.Bool
}

func (s *renewFailingClaims) CompareAndSwap(ctx context.Context, key string, expected, newValue []byte) (bool, []byte, error) {
	if s.cut.Load() {
		return false, nil, errors.New("claim storage unreachable")
	}
	return s.Backend.(storage.CompareAndSwapper).CompareAndSwap(ctx, key, expected, newValue)
}

// TestTenantCAKeyFactory_NoTakeoverWhileRenewalsFailDuringGenerate: a live
// pass whose generate is in flight loses access to claim storage, so its
// renewals fail for longer than the lease. Its unchanged claim proves
// nothing about its generate, which may still make the key: another node
// must not take the claim over and generate a second key beside it.
func TestTenantCAKeyFactory_NoTakeoverWhileRenewalsFailDuringGenerate(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	claims := storage.New() // shared by the nodes, as the server's shared storage is
	key := tenantLoginCAClaimKey("tenant-a")
	nodeB := &stalledGenerateBackend{Backend: baseB}
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(nodeB, claims))
	claimsA := &renewFailingClaims{Backend: claims}
	var errB error
	nodeA := &stalledGenerateBackend{Backend: baseA}
	nodeA.pause = func() {
		// A's renewals now fail, and its claim ages past the lease while
		// its generate is still in flight.
		claimsA.cut.Store(true)
		held, err := claims.Get(ctx, key)
		require.NoError(t, err)
		_, rest, _ := strings.Cut(string(held), " ")
		aged := time.Now().Add(-2*tenantLoginCAClaimLease).UTC().Format(time.RFC3339Nano) + " " + rest
		require.NoError(t, claims.Put(ctx, key, []byte(aged)))
		errB = b.EnsureTenant(ctx, "tenant-a")
	}
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(nodeA, claimsA))

	_ = a.EnsureTenant(ctx, "tenant-a")
	require.ErrorIs(t, errB, errTenantLoginCAClaimHeld, "the claim of a pass whose generate is in flight must stay held while its renewals fail")
	assert.Zero(t, nodeB.generated.Load(), "a node took over the claim of a pass whose generate was in flight and generated a second key")
	assert.EqualValues(t, 1, nodeA.generated.Load())
}

// TestTenantLoginCAHolderStopped: only the holder's own host proves its pass
// stopped.
func TestTenantLoginCAHolderStopped(t *testing.T) {
	host, err := os.Hostname()
	require.NoError(t, err)
	assert.True(t, tenantLoginCAHolderStopped(tenantLoginCAClaimOwner("t", "earlier-process", os.Getpid(), host)), "an earlier process under this PID is gone")
	assert.False(t, tenantLoginCAHolderStopped(tenantLoginCAClaimOwner("t", "earlier-process", os.Getpid(), host+"-other")), "a holder on another host is never proven stopped")
	assert.False(t, tenantLoginCAHolderStopped("bare-token"), "an owner without process and host proves nothing")
	live := tenantLoginCAClaimOwner("t", tenantLoginCAProcess, os.Getpid(), host)
	tenantLoginCALiveOwners.Store(live, struct{}{})
	assert.False(t, tenantLoginCAHolderStopped(live), "a running pass of this process is live")
	tenantLoginCALiveOwners.Delete(live)
	assert.True(t, tenantLoginCAHolderStopped(live), "a returned pass of this process is stopped")
}

// TestTenantCAKeyFactory_ReconcilesGeneratingClaimOfGoneHolder: a pass that
// died after marking its claim generating, before its key was made, leaves a
// generating claim whose lease is never renewed again. The next provisioning
// pass (the next boot) must take it over and make the one key, not refuse it
// forever.
func TestTenantCAKeyFactory_ReconcilesGeneratingClaimOfGoneHolder(t *testing.T) {
	ctx := context.Background()
	base, _ := sharedTenantCABackends(t)
	claims := storage.New()
	key := tenantLoginCAClaimKey("tenant-a")
	// The holder ran in an earlier process on this host, which this process
	// replaced under its PID (a restarted container): it provably stopped.
	host, err := os.Hostname()
	require.NoError(t, err)
	goneHolder := tenantLoginCAClaimOwner("gone-holder", "earlier-process", os.Getpid(), host)
	gone := tenantLoginCAGeneratingClaim(goneHolder, time.Now().Add(-2*tenantLoginCAClaimLease))
	stored, err := claims.PutIfAbsent(ctx, key, gone)
	require.NoError(t, err)
	require.True(t, stored)
	node := &stalledGenerateBackend{Backend: base}
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(node, claims))

	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"), "a generating claim whose holder is gone must not block provisioning")
	assert.EqualValues(t, 1, node.generated.Load(), "the pass that took the claim over makes exactly one key")
	pub, cert := tenantLoginCA(t, f, "tenant-a")
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(cert.PublicKey))
	current, err := claims.Get(ctx, key)
	require.NoError(t, err)
	_, owner, err := parseTenantLoginCAClaim(current)
	require.NoError(t, err)
	assert.NotEqual(t, goneHolder, owner, "the gone holder's claim must be taken over")

	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	assert.EqualValues(t, 1, node.generated.Load(), "a later pass adopts the key")
}

// TestTenantCAKeyFactory_NoTakeoverOfRenewingGeneratingClaim: a generating
// claim read past its lease is not taken over while its holder still renews
// it: the holder is alive and its generate may yet make the key.
func TestTenantCAKeyFactory_NoTakeoverOfRenewingGeneratingClaim(t *testing.T) {
	ctx := context.Background()
	base, _ := sharedTenantCABackends(t)
	claims := storage.New()
	key := tenantLoginCAClaimKey("tenant-a")
	aged := tenantLoginCAGeneratingClaim("live-holder", time.Now().Add(-2*tenantLoginCAClaimLease))
	require.NoError(t, claims.Put(ctx, key, aged))
	renewed := make(chan struct{})
	go func() {
		defer close(renewed)
		// The live holder renews its generating claim, as it does while
		// its generate is in flight, within its renewal interval.
		time.Sleep(500 * time.Millisecond)
		_ = claims.Put(ctx, key, tenantLoginCAGeneratingClaim("live-holder", time.Now()))
	}()
	node := &stalledGenerateBackend{Backend: base}
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(node, claims))

	err := f.EnsureTenant(ctx, "tenant-a")
	<-renewed
	require.ErrorIs(t, err, errTenantLoginCAClaimHeld, "the claim of a live, renewing holder must stay held")
	assert.Zero(t, node.generated.Load(), "a pass took over the claim of a live holder and generated a second key")
	current, err := claims.Get(ctx, key)
	require.NoError(t, err)
	_, owner, err := parseTenantLoginCAClaim(current)
	require.NoError(t, err)
	assert.Equal(t, "live-holder", owner)
}

// Removing a tenant releases its claim, so the tenant can be provisioned
// again.
func TestTenantCAKeyFactory_RemoveTenantTombstonesClaim(t *testing.T) {
	ctx := context.Background()
	f, base := newTenantCAKeyTestFactory(t, "tenant-a")
	before, _ := tenantLoginCA(t, f, "tenant-a")

	require.NoError(t, f.RemoveTenant(ctx, "tenant-a"))
	held, err := f.claims.Get(ctx, tenantLoginCAClaimKey("tenant-a"))
	require.NoError(t, err)
	assert.True(t, tenantLoginCAClaimIsRemoved(held), "teardown leaves a tombstone, not an empty claim")
	require.NoError(t, f.RemoveTenant(ctx, "tenant-a"), "a second teardown is not an error")

	require.ErrorIs(t, f.EnsureTenant(ctx, "tenant-a"), errTenantLoginCARemoved, "a late pass must not provision a removed tenant")
	assertNoTenantLoginCA(t, base, "tenant-a")

	// A tenant created again under the ID is revived and provisioned anew.
	require.NoError(t, f.ReviveTenant(ctx, "tenant-a"))
	require.NoError(t, f.EnsureTenant(ctx, "tenant-a"))
	after, _ := tenantLoginCA(t, f, "tenant-a")
	assert.False(t, before.(*ecdsa.PublicKey).Equal(after), "a removed tenant gets a new login CA key")
}

// assertNoTenantLoginCA fails unless the tenant has no login CA key and none
// of its certificate, provenance or intent records.
func assertNoTenantLoginCA(t *testing.T, base xkms.Backend, tenantID string) {
	t.Helper()
	ctx := context.Background()
	_, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
	require.ErrorIs(t, err, errTenantLoginCAKeyNotFound, "a login CA key outlived teardown")
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	for _, certID := range []string{tenantLoginCAKeyCN, tenantLoginCAProvenanceID, tenantLoginCAIntentID} {
		exists, err := scoped.CertExists(ctx, certID)
		require.NoError(t, err)
		assert.False(t, exists, "%s outlived teardown", certID)
	}
}

// pausingProvenanceBackend runs pause once, right before the provenance
// record of a provisioning pass is saved: after the key exists, before the
// pass's last writes.
type pausingProvenanceBackend struct {
	xkms.Backend
	pause func()
	once  sync.Once
}

func (b *pausingProvenanceBackend) SaveCert(ctx context.Context, keyID string, cert *x509.Certificate) error {
	if strings.HasSuffix(keyID, tenantLoginCAProvenanceID) {
		b.once.Do(b.pause)
	}
	return b.Backend.SaveCert(ctx, keyID, cert)
}

func TestTenantCAKeyFactory_TeardownFencesLateProvisioningWrites(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	claims := storage.New() // shared by the nodes, as the server's shared storage is
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(baseB, claims))
	var removeErr error
	nodeA := &pausingProvenanceBackend{Backend: baseA}
	// Node B tears the tenant down while node A's pass has made the key and
	// is about to save its provenance and certificate.
	nodeA.pause = func() { removeErr = b.RemoveTenant(ctx, "tenant-a") }
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(nodeA, claims))

	require.ErrorIs(t, a.EnsureTenant(ctx, "tenant-a"), errTenantLoginCARemoved, "a pass that raced teardown must report the removal")
	require.NoError(t, removeErr)
	assertNoTenantLoginCA(t, baseB, "tenant-a")

	require.ErrorIs(t, b.EnsureTenant(ctx, "tenant-a"), errTenantLoginCARemoved, "no pass provisions a torn-down tenant")
	assertNoTenantLoginCA(t, baseB, "tenant-a")
}

func TestTenantCAKeyFactory_TeardownWaitsForGenerateInFlight(t *testing.T) {
	ctx := context.Background()
	baseA, baseB := sharedTenantCABackends(t)
	claims := storage.New()
	b := newTenantCAKeyFactory()
	require.NoError(t, b.Bind(baseB, claims))
	var removeErr error
	nodeA := &stalledGenerateBackend{Backend: baseA}
	nodeA.pause = func() { removeErr = b.RemoveTenant(ctx, "tenant-a") }
	a := newTenantCAKeyFactory()
	require.NoError(t, a.Bind(nodeA, claims))

	require.NoError(t, a.EnsureTenant(ctx, "tenant-a"))
	require.ErrorIs(t, removeErr, errTenantLoginCAClaimHeld, "teardown must not delete under a generate in flight")

	require.NoError(t, b.RemoveTenant(ctx, "tenant-a"), "teardown proceeds once the generate returned")
	assertNoTenantLoginCA(t, baseB, "tenant-a")
}

func TestTenantCAKeyFactory_FencedHolderReleasesLostHostClaim(t *testing.T) {
	ctx := context.Background()
	base, _ := sharedTenantCABackends(t)
	claims := storage.New()
	key := tenantLoginCAClaimKey(tenantLoginCASystemTestID)
	// A node on another host died after marking the claim generating.
	lostHolder := tenantLoginCAClaimOwner("lost-holder", "lost-process", 4242, "lost-host")
	stored, err := claims.PutIfAbsent(ctx, key, tenantLoginCAGeneratingClaim(lostHolder, time.Now().Add(-2*tenantLoginCAClaimLease)))
	require.NoError(t, err)
	require.True(t, stored)
	node := &stalledGenerateBackend{Backend: base}
	f := newTenantCAKeyFactory()
	require.NoError(t, f.Bind(node, claims))

	err = f.EnsureTenant(ctx, tenantLoginCASystemTestID)
	require.ErrorIs(t, err, errTenantLoginCAClaimHeld, "no host proves a lost host's generate stopped")
	assert.Contains(t, err.Error(), lostHolder, "the error names the holder the operator fences")
	require.ErrorIs(t, f.RemoveTenant(ctx, tenantLoginCASystemTestID), errTenantLoginCAClaimHeld)
	assert.Zero(t, node.generated.Load())

	// The operator fenced the lost host and names its holder.
	f.FenceHolders([]string{" " + lostHolder + " "})
	require.NoError(t, f.EnsureTenant(ctx, tenantLoginCASystemTestID))
	assert.EqualValues(t, 1, node.generated.Load(), "the fenced holder's claim is taken over and one key made")
	pub, cert := tenantLoginCA(t, f, tenantLoginCASystemTestID)
	assert.True(t, pub.(*ecdsa.PublicKey).Equal(cert.PublicKey))
}

// tenantLoginCASystemTestID is the system tenant, whose claim no tenant
// deletion clears.
const tenantLoginCASystemTestID = qrdbsdk.SystemTenantID

func TestTenantCAKeyFactory_BindRequiresClaimStorage(t *testing.T) {
	_, base := newTenantCAKeyTestFactory(t)
	require.Error(t, newTenantCAKeyFactory().Bind(base, nil))
}
