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
)

// Compile-time interface check.
var _ qrdbsdk.CeremonyCA = (*CAAdapter)(nil)

// CAAdapter implements go-qrdb CeremonyCA using go-xkms ca.XKMSCA.
// This bridges the go-xkms CA interface to the go-qrdb ceremony's expected
// CA interface, translating types at the boundary.
type CAAdapter struct {
	ca ca.XKMSCA
}

// NewCAAdapter creates a new CAAdapter wrapping the given XKMSCA instance.
func NewCAAdapter(xkmsCA ca.XKMSCA) *CAAdapter {
	return &CAAdapter{ca: xkmsCA}
}

// SignCSR signs a PEM-encoded CSR using the go-xkms CA with the given options.
func (a *CAAdapter) SignCSR(csrPEM []byte, opts *qrdbsdk.SignCSROptions) (*x509.Certificate, error) {
	xkmsOpts := &ca.SignOptions{
		Profile:      opts.Profile,
		ValidityDays: opts.ValidityDays,
		KeyUsage:     opts.KeyUsage,
		ExtKeyUsage:  opts.ExtKeyUsage,
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
