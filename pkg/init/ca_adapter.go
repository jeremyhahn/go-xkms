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

// CAAdapter implements go-qrdb CeremonyCA using go-xkms ca.TrustedCA.
// This bridges the go-xkms CA interface to the go-qrdb ceremony's expected
// CA interface, translating types at the boundary.
type CAAdapter struct {
	ca ca.TrustedCA

	// spiffeTrustDomain, when non-empty, causes the adapter to stamp a
	// system-tenant SPIFFE SAN (spiffe://<td>/tenant/system/user/<CN>) onto
	// the SO / bootstrap certificates issued during the init ceremony. This is
	// the control-plane exception in the login tenant-derivation order: the SO
	// cert explicitly carries tenant/system so the control plane works before
	// any tenant barrier unseals.
	spiffeTrustDomain string
}

// NewCAAdapter creates a new CAAdapter wrapping the given TrustedCA instance.
// trustDomain is the operator-configured SPIFFE trust domain; when empty no
// SPIFFE SAN is stamped (legacy behavior).
func NewCAAdapter(xkmsCA ca.TrustedCA, trustDomain string) *CAAdapter {
	return &CAAdapter{ca: xkmsCA, spiffeTrustDomain: trustDomain}
}

// SignCSR signs a PEM-encoded CSR using the go-xkms CA with the given options.
func (a *CAAdapter) SignCSR(csrPEM []byte, opts *qrdbsdk.SignCSROptions) (*x509.Certificate, error) {
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
	return a.ca.SignCSR(csrPEM, xkmsOpts)
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
func (a *CAAdapter) IssueCertificate(req *qrdbsdk.IssueCertRequest) (*qrdbsdk.IssuedCert, error) {
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
	if a.spiffeTrustDomain != "" {
		spiffeURI, err := spiffe.BuildURI(a.spiffeTrustDomain, systemTenantID, spiffe.KindUser, req.CommonName)
		if err != nil {
			return nil, err
		}
		if xkmsReq.SANS == nil {
			xkmsReq.SANS = &ca.SubjectAlternativeNames{}
		}
		xkmsReq.SANS.URIs = append(xkmsReq.SANS.URIs, spiffeURI.String())
	}

	issued, err := a.ca.IssueCertificate(xkmsReq)
	if err != nil {
		return nil, err
	}

	return &qrdbsdk.IssuedCert{
		Certificate: issued.Certificate,
		CertPEM:     issued.CertificatePEM,
		KeyPEM:      issued.PrivateKeyPEM,
	}, nil
}
