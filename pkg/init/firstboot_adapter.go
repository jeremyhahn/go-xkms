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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

// Compile-time proof that CAAdapter satisfies qrdb's admin-mTLS first-boot
// seams. These are the two enrollment paths qrdb's firstboot package defines:
// Path A (CertProvider, generate-and-distribute) and Path B (CertSigner,
// CSR-sign, where the private key never leaves the admin). The stack's locked
// architecture names go-xkms as the implementation of both; before this file
// existed that claim was aspirational — nothing in go-xkms satisfied either
// interface.
var (
	_ qrdbsdk.CertProvider = (*CAAdapter)(nil)
	_ qrdbsdk.CertSigner   = (*CAAdapter)(nil)
)

// GenerateAdminCert implements qrdb firstboot Path A (generate-and-distribute):
// a fresh key pair is generated for the admin, the CA signs a CSR built from
// it, and both PEM blobs are returned for distribution. The key is generated
// HERE, outside the CA's keystore, deliberately: it is the administrator's
// personal credential, not platform key material, so it must never enter the
// platform's key custody — the CA only ever sees the CSR. tenantID becomes
// the subject's OrganizationalUnit per the seam contract; subject is the
// CommonName.
//
// When a SPIFFE trust domain is configured, the certificate carries
// spiffe://<td>/tenant/<tenantID>/user/<subject> so login derives the admin's
// tenant from the certificate. An empty tenantID falls back to the system
// tenant, matching the ceremony SO certificates.
func (a *CAAdapter) GenerateAdminCert(ctx context.Context, tenantID, subject string) ([]byte, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, &AdminKeyGenerationError{Err: err}
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:         subject,
			OrganizationalUnit: []string{tenantID},
		},
	}, key)
	if err != nil {
		return nil, nil, &AdminKeyGenerationError{Err: err}
	}
	csrPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})

	certPEM, err := a.SignAdminCSR(ctx, tenantID, subject, csrPEM)
	if err != nil {
		return nil, nil, err
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, &AdminKeyGenerationError{Err: err}
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// SignAdminCSR implements qrdb firstboot Path B (CSR-sign): the admin supplies
// a CSR, so the private key never leaves them, and the CA returns the signed
// certificate PEM. The subject and key come from the CSR — that is the point
// of Path B — so the subject parameter is used only for the SPIFFE identity,
// not to rewrite the CSR's distinguished name.
//
// The certificate shape (key usage, extended key usage) comes from the
// canonical client profile, exactly as in GenerateAdminCert.
func (a *CAAdapter) SignAdminCSR(ctx context.Context, tenantID, subject string, csrPEM []byte) ([]byte, error) {
	profile := ca.NewClientProfile()
	opts := &ca.SignOptions{
		KeyUsage:    profile.KeyUsage(),
		ExtKeyUsage: profile.ExtKeyUsage(),
	}
	if a.spiffeTrustDomain != "" {
		opts.SPIFFETrustDomain = a.spiffeTrustDomain
		opts.TenantID = tenantOrSystem(tenantID)
		opts.SPIFFEKind = spiffe.KindUser
		opts.SPIFFEName = subject
	}

	cert, err := a.ca.SignCSR(ctx, csrPEM, opts)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), nil
}

// stampSPIFFE appends the tenant-scoped SPIFFE URI SAN for cn onto req when a
// trust domain is configured. It is shared by the ceremony issuance path
// (which pins the system tenant) and the firstboot admin path (which carries
// the admin's own tenant).
func (a *CAAdapter) stampSPIFFE(req *ca.CertificateRequest, tenantID, cn string) error {
	if a.spiffeTrustDomain == "" {
		return nil
	}
	spiffeURI, err := spiffe.BuildURI(a.spiffeTrustDomain, tenantOrSystem(tenantID), spiffe.KindUser, cn)
	if err != nil {
		return err
	}
	if req.SANS == nil {
		req.SANS = &ca.SubjectAlternativeNames{}
	}
	req.SANS.URIs = append(req.SANS.URIs, spiffeURI.String())
	return nil
}

// tenantOrSystem returns the tenant to encode in a SPIFFE identity: the given
// tenant, or the system tenant when none is supplied.
func tenantOrSystem(tenantID string) string {
	if tenantID == "" {
		return systemTenantID
	}
	return tenantID
}
