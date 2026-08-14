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

package initialize

import (
	"context"
	"crypto/x509"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// Compile-time interface check.
var _ qrdbsdk.CeremonyCA = (*CAAdapter)(nil)

// systemTenantID is the control-plane tenant. The SO / bootstrap certificate
// is always scoped to this tenant so the control plane functions before any
// tenant barrier unseals.
const systemTenantID = "system"

// CeremonyCA is the subset of ca.TrustedCA the init ceremony depends on:
// checking that the CA is ready (ca.CALifecycle), certificate issuance
// (ca.CAIssuer), and reading the CA's own certificate and bundle
// (ca.CATrustChain). Declaring the narrow dependency here instead of the
// full 76-method ca.TrustedCA keeps the ceremony's CA surface honest about
// what it actually calls.
type CeremonyCA interface {
	ca.CALifecycle
	ca.CAIssuer
	ca.CATrustChain
}

// CAAdapter implements go-qrdb CeremonyCA using go-xkms's CeremonyCA (a
// narrow slice of ca.TrustedCA). This bridges the go-xkms CA interface to
// the go-qrdb ceremony's expected CA interface, translating types at the
// boundary.
type CAAdapter struct {
	ca CeremonyCA

	// spiffeTrustDomain, when non-empty, causes the adapter to stamp a
	// system-tenant SPIFFE SAN (spiffe://<td>/tenant/system/user/<CN>) onto
	// the SO / bootstrap certificates issued during the init ceremony. This is
	// the control-plane exception in the login tenant-derivation order: the SO
	// cert explicitly carries tenant/system so the control plane works before
	// any tenant barrier unseals.
	spiffeTrustDomain string
}

// NewCAAdapter creates a new CAAdapter wrapping the given CeremonyCA
// instance (any ca.TrustedCA satisfies CeremonyCA). trustDomain is the
// operator-configured SPIFFE trust domain; when empty no SPIFFE SAN is
// stamped (legacy behavior).
func NewCAAdapter(xkmsCA CeremonyCA, trustDomain string) *CAAdapter {
	return &CAAdapter{ca: xkmsCA, spiffeTrustDomain: trustDomain}
}

// SignCSR signs a PEM-encoded CSR using the go-xkms CA with the given options.
func (a *CAAdapter) SignCSR(ctx context.Context, csrPEM []byte, opts *qrdbsdk.SignCSROptions) (*x509.Certificate, error) {
	xkmsOpts := &ca.SignOptions{
		Profile:      opts.Profile,
		ValidityDays: opts.ValidityDays,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}
	if a.spiffeTrustDomain != "" {
		xkmsOpts.SPIFFETrustDomain = a.spiffeTrustDomain
		xkmsOpts.TenantID = systemTenantID
		xkmsOpts.SPIFFEKind = spiffe.KindUser
	}
	return a.ca.SignCSR(ctx, csrPEM, xkmsOpts)
}

// CACertificate returns the CA's own certificate.
func (a *CAAdapter) CACertificate() (*x509.Certificate, error) {
	return a.ca.CACertificate()
}

// CABundle returns the PEM-encoded CA certificate chain.
func (a *CAAdapter) CABundle() ([]byte, error) {
	return a.ca.CABundle()
}

// IssueCertificate generates a new key pair and issues a certificate using the
// go-xkms CA. The go-qrdb IssueCertRequest is mapped to go-xkms's
// CertificateRequest, and the result is mapped back to go-qrdb's IssuedCert.
func (a *CAAdapter) IssueCertificate(ctx context.Context, req *qrdbsdk.IssueCertRequest) (*qrdbsdk.IssuedCert, error) {
	xkmsReq := &ca.CertificateRequest{
		Subject: ca.Subject{
			CommonName: req.CommonName,
		},
		KeyUsage:    req.KeyUsage,
		ExtKeyUsage: req.ExtKeyUsage,
		Valid:       req.ValidityDays,
	}

	// Map SANs if provided.
	if len(req.SANs) > 0 {
		xkmsReq.SANS = &ca.SubjectAlternativeNames{
			DNS: req.SANs,
		}
	}

	// Stamp the system-tenant SPIFFE SAN onto the directly-issued SO /
	// bootstrap certificate so login derives the system tenant from it.
	// (An empty tenant resolves to the system tenant in stampSPIFFE.)
	if err := a.stampSPIFFE(xkmsReq, "", req.CommonName); err != nil {
		return nil, err
	}

	issued, err := a.ca.IssueCertificate(ctx, xkmsReq)
	if err != nil {
		return nil, err
	}

	return &qrdbsdk.IssuedCert{
		Certificate: issued.Certificate,
		CertPEM:     issued.CertificatePEM,
		KeyPEM:      issued.PrivateKeyPEM,
	}, nil
}
