package server

import (
	"context"
	"crypto"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"sync"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// tenantLoginCAKeyCN is the common name of a tenant's go-qrdb login CA key
// (Key B) and of its certificate record. One key per tenant: the name is the
// same under every tenant and the tenant scope tells the keys apart, so the
// key ID is the tenant, as cakey.ProviderFactory requires.
const tenantLoginCAKeyCN = "qrdb-login-ca"

// tenantLoginCAValidity is the lifetime of a tenant login CA certificate.
const tenantLoginCAValidity = 10 * 365 * 24 * time.Hour

// errTenantCAKeyFactoryUnbound is returned while no backend is bound.
var errTenantCAKeyFactoryUnbound = errors.New("tenant login CA key factory: no backend bound")

// tenantCAKeyFactory is go-qrdb's cakey.ProviderFactory over go-xkms's
// tenant-scoped backend: every tenant's login CA (Key B) signature goes
// through that tenant's xkms key, and go-qrdb generates no software Key B.
type tenantCAKeyFactory struct {
	mu      sync.RWMutex
	base    xkms.Backend
	tenants tenantLookup
}

// tenantLookup is the part of go-qrdb's tenant service the factory uses to
// tell a tenant the node knows from an arbitrary ID.
type tenantLookup interface {
	GetTenant(ctx context.Context, tenantID string) (*qrdbsdk.ServiceTenantInfo, error)
}

// TrackTenants makes the factory provision, on first request, the login CA of
// any tenant svc knows that has none yet. Without it such a tenant is refused.
func (f *tenantCAKeyFactory) TrackTenants(svc tenantLookup) {
	f.mu.Lock()
	f.tenants = svc
	f.mu.Unlock()
}

// knownTenant reports whether the tracked tenant service has tenantID.
func (f *tenantCAKeyFactory) knownTenant(ctx context.Context, tenantID string) bool {
	f.mu.RLock()
	svc := f.tenants
	f.mu.RUnlock()
	if svc == nil {
		return false
	}
	info, err := svc.GetTenant(ctx, tenantID)
	return err == nil && info != nil
}

var _ qrdbsdk.CAKeyProviderFactory = (*tenantCAKeyFactory)(nil)

func newTenantCAKeyFactory() *tenantCAKeyFactory {
	return &tenantCAKeyFactory{}
}

// Bind makes base the backend that holds every tenant's login CA key.
func (f *tenantCAKeyFactory) Bind(base xkms.Backend) error {
	if base == nil {
		return errors.New("tenant login CA key factory: nil backend")
	}
	f.mu.Lock()
	f.base = base
	f.mu.Unlock()
	return nil
}

// backend is the bound backend. The read takes only the factory's own lock,
// which Bind holds for one assignment, so a lookup never waits on, or fails
// for, a lock the server holds.
func (f *tenantCAKeyFactory) backend() (xkms.Backend, error) {
	f.mu.RLock()
	base := f.base
	f.mu.RUnlock()
	if base == nil {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return base, nil
}

// ProviderForTenant returns the provider of tenantID's login CA: the tenant's
// own xkms key and certificate. A tenant without a login CA key is
// provisioned if the tracked tenant service knows it, and refused otherwise;
// a provider is never shared between tenants.
func (f *tenantCAKeyFactory) ProviderForTenant(tenantID string) (qrdbsdk.CAKeyProvider, error) {
	if tenantID == "" {
		return nil, errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return nil, err
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	if _, err := tenantLoginCAKeyAttrs(context.Background(), base, tenantID); err != nil {
		// go-qrdb's native onboarding creates a tenant through the node's own
		// tenant service, which go-xkms cannot wrap, and then asks for its
		// login CA: provision a tenant the node knows on that first request.
		if !f.knownTenant(context.Background(), tenantID) {
			return nil, err
		}
		if err := f.EnsureTenant(context.Background(), tenantID); err != nil {
			return nil, err
		}
	}
	return qrdbsdk.CAKeyAdapter{
		SignerFunc: func(ctx context.Context) (crypto.Signer, error) {
			attrs, err := tenantLoginCAKeyAttrs(ctx, base, tenantID)
			if err != nil {
				return nil, err
			}
			return scoped.Signer(ctx, attrs)
		},
		CertificateFunc: func(ctx context.Context) (*x509.Certificate, error) {
			return scoped.GetCert(ctx, tenantLoginCAKeyCN)
		},
	}, nil
}

// TenantIDs lists, sorted, the tenants that hold a login CA key in the backend.
func (f *tenantCAKeyFactory) TenantIDs(ctx context.Context) ([]string, error) {
	base, err := f.backend()
	if err != nil {
		return nil, err
	}
	keys, err := base.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	seen := make(map[string]struct{})
	for _, attrs := range keys {
		if attrs != nil && attrs.CN == tenantLoginCAKeyCN {
			seen[scope.TenantName(attrs.TenantID)] = struct{}{}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids, nil
}

// EnsureTenant provisions tenantID's login CA once: a P-256 signing key in the
// tenant's scope and a self-signed CA certificate over it, saved under the same
// name. An existing key is kept and its certificate validated, or issued if
// missing.
func (f *tenantCAKeyFactory) EnsureTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return err
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	if existing, err := tenantLoginCAKeyAttrs(ctx, base, tenantID); err == nil {
		// Keep the key, but a key alone is not a provisioned login CA: an
		// earlier pass may have stopped before its certificate was saved.
		return ensureTenantLoginCACert(ctx, scoped, tenantID, existing)
	}
	attrs := &types.KeyAttributes{
		CN:            tenantLoginCAKeyCN,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if _, err := scoped.GenerateECDSA(ctx, attrs); err != nil {
		if !errors.Is(err, backend.ErrKeyAlreadyExists) {
			return fmt.Errorf("tenant login CA key factory: generate key for tenant %q: %w", tenantID, err)
		}
		// Another node provisioned the key between the lookup and the
		// generate: converge on the persisted key.
		existing, lookupErr := tenantLoginCAKeyAttrs(ctx, base, tenantID)
		if lookupErr != nil {
			return fmt.Errorf("tenant login CA key factory: generate key for tenant %q: %w", tenantID, errors.Join(err, lookupErr))
		}
		attrs = existing
	}
	return ensureTenantLoginCACert(ctx, scoped, tenantID, attrs)
}

// ensureTenantLoginCACert makes sure the tenant's saved login CA certificate is
// a valid CA certificate over the key attrs names, issuing and saving one if it
// is missing or does not match. A certificate another node saved first wins.
func ensureTenantLoginCACert(ctx context.Context, scoped *xkms.TenantScopedBackend, tenantID string, attrs *types.KeyAttributes) error {
	signer, err := scoped.Signer(ctx, attrs)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: signer for tenant %q: %w", tenantID, err)
	}
	if tenantLoginCACertValid(ctx, scoped, signer.Public()) {
		return nil
	}
	cert, err := selfSignTenantLoginCA(tenantID, signer)
	if err != nil {
		return err
	}
	if err := scoped.SaveCert(ctx, tenantLoginCAKeyCN, cert); err != nil {
		if tenantLoginCACertValid(ctx, scoped, signer.Public()) {
			return nil
		}
		return fmt.Errorf("tenant login CA key factory: save certificate for tenant %q: %w", tenantID, err)
	}
	return nil
}

// tenantLoginCACertValid reports whether the tenant's saved login CA
// certificate is a CA certificate, in its validity period, over pub.
func tenantLoginCACertValid(ctx context.Context, scoped *xkms.TenantScopedBackend, pub crypto.PublicKey) bool {
	cert, err := scoped.GetCert(ctx, tenantLoginCAKeyCN)
	if err != nil || cert == nil || !cert.IsCA {
		return false
	}
	now := time.Now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return false
	}
	certPub, ok := cert.PublicKey.(interface{ Equal(crypto.PublicKey) bool })
	return ok && certPub.Equal(pub)
}

// tenantLoginCAKeyAttrs finds tenantID's login CA key among base's keys.
func tenantLoginCAKeyAttrs(ctx context.Context, base xkms.Backend, tenantID string) (*types.KeyAttributes, error) {
	keys, err := base.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	// Compare normalized scopes: a backend may report a system key with an
	// empty TenantID (tpm2 listSystemKeys) though it was made for "system".
	want := scope.TenantName(tenantID)
	for _, attrs := range keys {
		if attrs != nil && attrs.CN == tenantLoginCAKeyCN && scope.TenantName(attrs.TenantID) == want {
			return attrs, nil
		}
	}
	return nil, errors.New("tenant login CA key factory: the tenant has no login CA key")
}

// selfSignTenantLoginCA issues the tenant's self-signed login CA certificate,
// signed by the tenant's xkms key.
func selfSignTenantLoginCA(tenantID string, signer crypto.Signer) (*x509.Certificate, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: serial: %w", err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:         "qrdb login CA " + tenantID,
			OrganizationalUnit: []string{tenantID},
		},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(tenantLoginCAValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: sign certificate for tenant %q: %w", tenantID, err)
	}
	return x509.ParseCertificate(der)
}

// tenantCAKeyProviderOptions returns the node option that routes every
// tenant's login CA (Key B) through go-xkms (WithCertKeyProviderFactory),
// under the same condition as the cluster CA provider. The boot pass binds the
// factory to the server's default backend.
func (s *Server) tenantCAKeyProviderOptions() []qrdbnode.NodeOption {
	if !s.trustedCAIsClusterCA() {
		return nil
	}
	f := newTenantCAKeyFactory()
	// Left unbound here: the node starts before the key backends exist, and
	// its background trust refresh would read s.backends while New writes
	// it. provisionTenantCAKeys binds the factory once they are ready.
	s.tenantCAKeys = f
	return []qrdbnode.NodeOption{qrdbnode.WithCertKeyProviderFactory(f)}
}

// tenantCAKeyBackend is the server's default backend, the one that holds the
// tenants' login CA keys; an error before the backends are loaded. Only the
// boot pass calls it, once, to bind the factory; the lookups go-qrdb makes
// afterwards read the bound backend and never take the server's lock.
func (s *Server) tenantCAKeyBackend() (xkms.Backend, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	name := xkms.ResolveDefaultBackend(string(s.config.Default), s.backends)
	if name == "" {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return s.backends[name], nil
}
