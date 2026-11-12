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
	resolve func() (xkms.Backend, error)
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
	f.bindResolver(func() (xkms.Backend, error) { return base, nil })
	return nil
}

// bindResolver makes resolve the source of the backend, read at each call so
// a server can bind its default backend before that backend is loaded.
func (f *tenantCAKeyFactory) bindResolver(resolve func() (xkms.Backend, error)) {
	f.mu.Lock()
	f.resolve = resolve
	f.mu.Unlock()
}

func (f *tenantCAKeyFactory) backend() (xkms.Backend, error) {
	f.mu.RLock()
	resolve := f.resolve
	f.mu.RUnlock()
	if resolve == nil {
		return nil, errTenantCAKeyFactoryUnbound
	}
	base, err := resolve()
	if err != nil {
		return nil, err
	}
	if base == nil {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return base, nil
}

// ProviderForTenant returns the provider of tenantID's login CA: the tenant's
// own xkms key and certificate. A tenant without a login CA key is refused;
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
	if _, err := tenantLoginCAKeyAttrs(context.Background(), scoped); err != nil {
		return nil, err
	}
	return qrdbsdk.CAKeyAdapter{
		SignerFunc: func(ctx context.Context) (crypto.Signer, error) {
			attrs, err := tenantLoginCAKeyAttrs(ctx, scoped)
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
		if attrs != nil && attrs.TenantID != "" && attrs.CN == tenantLoginCAKeyCN {
			seen[attrs.TenantID] = struct{}{}
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
// name. An existing key is kept.
func (f *tenantCAKeyFactory) EnsureTenant(ctx context.Context, tenantID string) error {
	if tenantID == "" {
		return errors.New("tenant login CA key factory: empty tenant ID")
	}
	base, err := f.backend()
	if err != nil {
		return err
	}
	scoped := xkms.NewTenantScopedBackend(base, tenantID)
	if _, err := tenantLoginCAKeyAttrs(ctx, scoped); err == nil {
		return nil
	}
	attrs := &types.KeyAttributes{
		CN:            tenantLoginCAKeyCN,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if _, err := scoped.GenerateECDSA(ctx, attrs); err != nil {
		return fmt.Errorf("tenant login CA key factory: generate key for tenant %q: %w", tenantID, err)
	}
	signer, err := scoped.Signer(ctx, attrs)
	if err != nil {
		return fmt.Errorf("tenant login CA key factory: signer for tenant %q: %w", tenantID, err)
	}
	cert, err := selfSignTenantLoginCA(tenantID, signer)
	if err != nil {
		return err
	}
	if err := scoped.SaveCert(ctx, tenantLoginCAKeyCN, cert); err != nil {
		return fmt.Errorf("tenant login CA key factory: save certificate for tenant %q: %w", tenantID, err)
	}
	return nil
}

// tenantLoginCAKeyAttrs finds the tenant's login CA key in its scoped view.
func tenantLoginCAKeyAttrs(ctx context.Context, scoped *xkms.TenantScopedBackend) (*types.KeyAttributes, error) {
	keys, err := scoped.ListKeys(ctx)
	if err != nil {
		return nil, fmt.Errorf("tenant login CA key factory: list keys: %w", err)
	}
	for _, attrs := range keys {
		if attrs != nil && attrs.CN == tenantLoginCAKeyCN {
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
// under the same condition as the cluster CA provider. The factory reads the
// server's default backend at each call.
func (s *Server) tenantCAKeyProviderOptions() []qrdbnode.NodeOption {
	if !s.trustedCAIsClusterCA() {
		return nil
	}
	f := newTenantCAKeyFactory()
	f.bindResolver(s.tenantCAKeyBackend)
	return []qrdbnode.NodeOption{qrdbnode.WithCertKeyProviderFactory(f)}
}

// tenantCAKeyBackend is the server's default backend, the one that holds the
// tenants' login CA keys; an error before the backends are loaded. go-qrdb
// may call in while the server holds its lock to boot the node, so the lookup
// never blocks: a held lock reads as not yet loaded.
func (s *Server) tenantCAKeyBackend() (xkms.Backend, error) {
	if !s.mu.TryRLock() {
		return nil, errTenantCAKeyFactoryUnbound
	}
	defer s.mu.RUnlock()
	name := xkms.ResolveDefaultBackend(string(s.config.Default), s.backends)
	if name == "" {
		return nil, errTenantCAKeyFactoryUnbound
	}
	return s.backends[name], nil
}
