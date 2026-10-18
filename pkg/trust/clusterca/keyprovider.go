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

package clusterca

import (
	"context"
	"crypto"
	"crypto/x509"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// SigningCA is the TrustedCA surface KeyProvider signs through: the issuing
// identity's crypto.Signer and its certificate. ca.TrustedCA satisfies it.
type SigningCA interface {
	Signer(ctx context.Context) (crypto.Signer, error)
	CACertificate() (*x509.Certificate, error)
}

// KeyProvider is the TrustedCA as go-qrdb's cluster CA (Key A). Its method set
// is go-qrdb's cakey.Provider, so it is handed to the node through
// qrdbnode.WithClusterCAKeyProvider, and every Key A signature (node leaves,
// ceremony-sign-csr, the client trust pool) goes through the TrustedCA's
// crypto.Signer. No CA private-key bytes are read, returned or written
// (go-xkms#1381).
//
// The node is built before the TrustedCA, whose stores live in that node, so
// the CA is bound once it initializes. Until then Signer and Certificate
// return *ErrClusterCAUnbound. go-qrdb resolves Key A on every use, so the
// node picks the CA up on the first call after Bind.
type KeyProvider struct {
	identityCN string
	bound      atomic.Pointer[boundCA]
}

// boundCA boxes the bound SigningCA for atomic publication.
type boundCA struct {
	ca SigningCA
}

// NewKeyProvider returns an unbound KeyProvider. identityCN names the CA
// identity that signs as the cluster CA (the same ClusterCACN the node leaves
// are issued under); empty selects the TrustedCA's issuing identity.
func NewKeyProvider(identityCN string) *KeyProvider {
	return &KeyProvider{identityCN: identityCN}
}

// Bind makes trustedCA the cluster CA. A nil trustedCA returns
// *ErrMissingOption.
func (p *KeyProvider) Bind(trustedCA SigningCA) error {
	if trustedCA == nil {
		return &ErrMissingOption{Field: "TrustedCA", Mode: "cluster CA key provider"}
	}
	p.bound.Store(&boundCA{ca: trustedCA})
	return nil
}

// Signer returns the crypto.Signer of the cluster CA identity, after checking
// it holds the key its CA certificate certifies.
func (p *KeyProvider) Signer(ctx context.Context) (crypto.Signer, error) {
	signer, cert, err := p.identity(ctx)
	if err != nil {
		return nil, err
	}
	if !publicKeysEqual(signer.Public(), cert.PublicKey) {
		return nil, &ErrClusterCAKeyMismatch{Subject: cert.Subject.CommonName}
	}
	return signer, nil
}

// Certificate returns the cluster CA identity's certificate.
func (p *KeyProvider) Certificate(ctx context.Context) (*x509.Certificate, error) {
	b := p.bound.Load()
	if b == nil {
		return nil, &ErrClusterCAUnbound{}
	}
	if p.identityCN != "" {
		_, cert, err := p.namedIdentity(ctx, b.ca)
		return cert, err
	}
	cert, err := b.ca.CACertificate()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "clusterca: cluster CA certificate", Err: err}
	}
	return cert, nil
}

// identity resolves the cluster CA identity's signer and certificate from the
// bound TrustedCA.
func (p *KeyProvider) identity(ctx context.Context) (crypto.Signer, *x509.Certificate, error) {
	b := p.bound.Load()
	if b == nil {
		return nil, nil, &ErrClusterCAUnbound{}
	}
	if p.identityCN != "" {
		return p.namedIdentity(ctx, b.ca)
	}
	signer, err := b.ca.Signer(ctx)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "clusterca: cluster CA signer", Err: err}
	}
	cert, err := b.ca.CACertificate()
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "clusterca: cluster CA certificate", Err: err}
	}
	return signer, cert, nil
}

// namedIdentity resolves the identityCN identity through the TrustedCA's
// per-identity issuance.
func (p *KeyProvider) namedIdentity(ctx context.Context, trustedCA SigningCA) (crypto.Signer, *x509.Certificate, error) {
	issuer, ok := trustedCA.(ca.IdentityIssuer)
	if !ok {
		return nil, nil, &ErrMissingOption{
			Field: "TrustedCA (must support per-identity issuance for ClusterCACN)",
			Mode:  "cluster CA key provider",
		}
	}
	signer, cert, err := issuer.IssuerForIdentity(ctx, p.identityCN)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "clusterca: cluster CA identity " + p.identityCN, Err: err}
	}
	return signer, cert, nil
}
