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

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

// =============================================================================
// Certificate Policy Regression Suite (ACME CT issuance path)
// =============================================================================
//
// The CT-aware issuance pipeline builds its certificate template through
// pkg/ca like every other CA-issued certificate in go-xkms. This test pins the
// policy surface of the certificates it produces.

// acmeIssuancePolicyGoldens pins the policy fingerprint of the ACME issuance
// path.
//
// Re-pinned 2026-08-17: the previous fingerprint predated months of CA
// profile work and was never re-verified because the Unit Tests CI job was
// failing on unrelated environment defects the whole time. The pinned
// policy is the reviewed current shape: 90-day ECDSA-SHA256 leaf, critical
// KeyUsage digitalSignature+keyEncipherment, EKU serverAuth+clientAuth,
// AKI, DNS SAN; BasicConstraints absent (optional for subscriber
// certificates per CA/Browser Forum BRs).
//
// Re-pinned 2026-10-16 (#1557): the subject carries the tenant as its
// first organizational unit.
var acmeIssuancePolicyGoldens = map[string]string{
	"acme_leaf": "94660a754ad187a75bdad293e4f4be294e546d3c8625058fcfdea15378b7ba83",
}

// issueACMEPath drives the CT issuance pipeline with CT and linting disabled
// (neither is configured in this test) and returns the issued certificate.
func issueACMEPath(t *testing.T) *x509.Certificate {
	t.Helper()

	signer := newMockSigner(t)
	iss, err := NewIssuer(Config{
		Signer:  signer,
		Enabled: true,
	})
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "acme.example.com"},
		DNSNames: []string{"acme.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// UTC, not local: PolicyFingerprint hashes NotAfter.Sub(NotBefore), and
	// AddDate walks CALENDAR days. In a zone with a DST transition inside the
	// window the delta is 2161h or 2159h instead of 2160h, so the pinned
	// fingerprint below would only reproduce in zones that happen not to shift
	// -- it passed in CI (UTC) and failed on any America/* workstation between
	// roughly August and November. The certificate's own validity is unchanged;
	// only the arithmetic is made zone-independent.
	now := time.Now().UTC()
	result, err := iss.Issue(context.Background(), &Request{
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 90),
		SkipCT:    true,
		SkipLint:  true,
	})
	require.NoError(t, err)
	require.NotNil(t, result)
	require.NotNil(t, result.FinalCert)
	return result.FinalCert
}

// TestCertificatePolicy_ACMEIssuancePath pins the policy surface of the ACME
// CT issuance path.
func TestCertificatePolicy_ACMEIssuancePath(t *testing.T) {
	cert := issueACMEPath(t)
	got := testutil.PolicyFingerprint(cert)
	want, ok := acmeIssuancePolicyGoldens["acme_leaf"]
	if !ok || want != got {
		t.Errorf("certificate policy changed for the ACME issuance path\nwant fingerprint %s\ngot  fingerprint %s\npolicy:\n%s",
			want, got, testutil.RenderCertificatePolicy(cert))
	}
}

// TestCertificatePolicy_IssuerIdentityReachesACMEPath asserts that configuring
// revocation and Authority Information Access endpoints on the issuer identity
// reaches ACME subscriber certificates.
//
// Before the ACME pipeline built its template through pkg/ca it hard-coded one,
// so no CA configuration could put a CRL distribution point or an OCSP
// responder on an ACME-issued certificate at all.
func TestCertificatePolicy_IssuerIdentityReachesACMEPath(t *testing.T) {
	signer := newMockSigner(t)
	iss, err := NewIssuer(Config{
		Signer:  signer,
		Enabled: true,
		IssuerIdentity: &ca.Identity{
			OCSPServers:            []string{"http://ocsp.acme.example.com"},
			CRLDistributionPoints:  []string{"http://crl.acme.example.com/ca.crl"},
			IssuingCertificateURLs: []string{"http://aia.acme.example.com/ca.cer"},
		},
	})
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "reach.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// UTC, not local: PolicyFingerprint hashes NotAfter.Sub(NotBefore), and
	// AddDate walks CALENDAR days. In a zone with a DST transition inside the
	// window the delta is 2161h or 2159h instead of 2160h, so the pinned
	// fingerprint below would only reproduce in zones that happen not to shift
	// -- it passed in CI (UTC) and failed on any America/* workstation between
	// roughly August and November. The certificate's own validity is unchanged;
	// only the arithmetic is made zone-independent.
	now := time.Now().UTC()
	result, err := iss.Issue(context.Background(), &Request{
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 90),
		SkipCT:    true,
		SkipLint:  true,
	})
	require.NoError(t, err)

	require.Equal(t, []string{"http://ocsp.acme.example.com"}, result.FinalCert.OCSPServer)
	require.Equal(t, []string{"http://crl.acme.example.com/ca.crl"}, result.FinalCert.CRLDistributionPoints)
	require.Equal(t, []string{"http://aia.acme.example.com/ca.cer"}, result.FinalCert.IssuingCertificateURL)
}

// TestCertificatePolicy_CertificateProfileReachesACMEPath asserts that the
// configured pkg/ca profile decides what an ACME-issued certificate carries.
func TestCertificatePolicy_CertificateProfileReachesACMEPath(t *testing.T) {
	signer := newMockSigner(t)
	iss, err := NewIssuer(Config{
		Signer:             signer,
		Enabled:            true,
		CertificateProfile: ca.NewClientProfile(),
	})
	require.NoError(t, err)

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "client.example.com"},
	}, leafKey)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)

	// UTC, not local: PolicyFingerprint hashes NotAfter.Sub(NotBefore), and
	// AddDate walks CALENDAR days. In a zone with a DST transition inside the
	// window the delta is 2161h or 2159h instead of 2160h, so the pinned
	// fingerprint below would only reproduce in zones that happen not to shift
	// -- it passed in CI (UTC) and failed on any America/* workstation between
	// roughly August and November. The certificate's own validity is unchanged;
	// only the arithmetic is made zone-independent.
	now := time.Now().UTC()
	result, err := iss.Issue(context.Background(), &Request{
		TenantID:  testTenant,
		CSR:       csr,
		NotBefore: now,
		NotAfter:  now.AddDate(0, 0, 90),
		SkipCT:    true,
		SkipLint:  true,
	})
	require.NoError(t, err)

	require.Equal(t, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, result.FinalCert.ExtKeyUsage)
	require.True(t, result.FinalCert.BasicConstraintsValid)
}

// TestCertificatePolicy_DumpACMEIssuance writes the rendered policy of the
// ACME issuance path to the file named by XKMS_CERTPOLICY_DUMP.
func TestCertificatePolicy_DumpACMEIssuance(t *testing.T) {
	dump := os.Getenv("XKMS_CERTPOLICY_DUMP")
	cert := issueACMEPath(t)
	out := []byte("=== acme_leaf\n")
	out = append(out, []byte(testutil.RenderCertificatePolicy(cert))...)
	out = append(out, []byte("fingerprint="+testutil.PolicyFingerprint(cert)+"\n")...)
	if dump == "" {
		return
	}
	require.NoError(t, os.WriteFile(dump, out, 0o600))
}
