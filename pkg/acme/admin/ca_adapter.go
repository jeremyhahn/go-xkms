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

package admin

import (
	"context"
	"crypto/x509"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Compile-time interface check.
var _ qrdbsdk.CeremonyCA = (*caAdapter)(nil)

// caAdapter implements go-qrdb CeremonyCA using go-xkms TrustedCA.
// It bridges the go-xkms CA interface to the go-qrdb ceremony's expected
// CA interface, translating types at the boundary.
type caAdapter struct {
	ca xkmssdk.TrustedCA
}

// newCAAdapter creates a new caAdapter wrapping the given TrustedCA instance.
func newCAAdapter(ca xkmssdk.TrustedCA) *caAdapter {
	return &caAdapter{ca: ca}
}

// SignCSR signs a PEM-encoded CSR using the go-xkms CA with the given options.
func (a *caAdapter) SignCSR(ctx context.Context, csrPEM []byte, opts *qrdbsdk.SignCSROptions) (*x509.Certificate, error) {
	xkmsOpts := &xkmssdk.TrustedCASignOptions{
		Profile:      opts.Profile,
		ValidityDays: opts.ValidityDays,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
	}
	return a.ca.SignCSR(ctx, csrPEM, xkmsOpts)
}

// CACertificate returns the CA's own certificate.
func (a *caAdapter) CACertificate() (*x509.Certificate, error) {
	return a.ca.CACertificate()
}

// CABundle returns the PEM-encoded CA certificate chain.
func (a *caAdapter) CABundle() ([]byte, error) {
	return a.ca.CABundle()
}

// IssueCertificate generates a new key pair and issues a certificate using the
// go-xkms CA. The go-qrdb IssueCertRequest is mapped to go-xkms's
// CertificateRequest, and the result is mapped back to go-qrdb's IssuedCert.
func (a *caAdapter) IssueCertificate(ctx context.Context, req *qrdbsdk.IssueCertRequest) (*qrdbsdk.IssuedCert, error) {
	xkmsReq := &xkmssdk.TrustedCACertificateRequest{
		Subject: xkmssdk.TrustedCASubject{
			CommonName: req.CommonName,
		},
		KeyUsage:    req.KeyUsage,
		ExtKeyUsage: req.ExtKeyUsage,
		Valid:       req.ValidityDays,
	}

	// Map SANs if provided.
	if len(req.SANs) > 0 {
		xkmsReq.SANS = &xkmssdk.TrustedCASubjectAlternativeNames{
			DNS: req.SANs,
		}
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
