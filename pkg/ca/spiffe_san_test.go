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

package ca

import (
	"context"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Scenario (a): a CSR signed with a trust domain + TenantID must carry the
// canonical tenant-scoped SPIFFE URI SAN on the issued certificate.
func TestSignCSR_StampsTenantSPIFFESAN(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "alice")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{
		SPIFFETrustDomain: "example.com",
		TenantID:          "tenant-acme",
		Profile:           "client",
	})
	require.NoError(t, err)
	require.NotNil(t, cert)

	require.Len(t, cert.URIs, 1, "exactly one SPIFFE URI SAN expected")
	got := cert.URIs[0].String()
	want := "spiffe://tenant-acme/user/alice"
	assert.Equal(t, want, got, "SPIFFE SAN must use the canonical tenant path")

	// And it must round-trip through the shared parser, enforcing the pin.
	id, perr := spiffe.TenantFromURIs(cert.URIs, "example.com")
	require.NoError(t, perr)
	assert.Equal(t, "tenant-acme", id.TenantID)
	assert.Equal(t, spiffe.KindUser, id.Kind)
	assert.Equal(t, "alice", id.Name)
}

// Explicit kind + name override the defaults.
func TestSignCSR_SPIFFEKindAndNameOverride(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "ignored-cn")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{
		SPIFFETrustDomain: "trust.internal",
		TenantID:          "t1",
		SPIFFEKind:        spiffe.KindService,
		SPIFFEName:        "billing-api",
	})
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	assert.Equal(t, "spiffe://t1/svc/billing-api", cert.URIs[0].String())
}

// Without a trust domain or tenant, no SPIFFE SAN is added (legacy behavior).
func TestSignCSR_NoSPIFFEWhenTrustDomainEmpty(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "nospiffe")

	cert, err := ca.SignCSR(context.Background(), csrPEM, &SignOptions{TenantID: "t1"})
	require.NoError(t, err)
	assert.Empty(t, cert.URIs, "no SPIFFE SAN expected without a trust domain")
}

// The raw provider entrypoint behaves identically.
func TestSignCSRWithSPIFFE_Raw(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "bob")

	cert, err := ca.SignCSRWithSPIFFE(context.Background(), csrPEM, "client", 30, "example.com", "tenant-b", "", "")
	require.NoError(t, err)
	require.Len(t, cert.URIs, 1)
	assert.Equal(t, "spiffe://tenant-b/user/bob", cert.URIs[0].String())
}

// TestSignCSRWithSPIFFE_NonLoginProfiles pins the contract the xkms servicer
// relies on to request the tenant SPIFFE SAN only for login certificates:
// code-signing and server certificates, including a server CSR with an empty
// or wildcard CN, issue with no URI SAN when no trust domain is passed, and
// would be refused if the SAN were requested.
func TestSignCSRWithSPIFFE_NonLoginProfiles(t *testing.T) {
	cases := map[string]struct {
		profile string
		cn      string
	}{
		"code-signing":    {profile: "code-signing", cn: "release-signer"},
		"server empty CN": {profile: "server", cn: ""},
		"server wildcard": {profile: "server", cn: "*.example.com"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			ca := setupTestCA(t)
			csrPEM, _ := makeLeafCSR(t, tc.cn)

			cert, err := ca.SignCSRWithSPIFFE(context.Background(), csrPEM, tc.profile, 30, "", "tenant-b", "", "")
			require.NoError(t, err)
			assert.Empty(t, cert.URIs, "no SPIFFE SAN without a trust domain")

			_, err = ca.SignCSRWithSPIFFE(context.Background(), csrPEM, tc.profile, 30, "example.com", "tenant-b", "", "")
			require.Error(t, err, "a SPIFFE SAN is not due on a %s certificate", tc.profile)
		})
	}
}

// A tenant user's certificate carries its tenant in exactly the form qrdb's
// certificate-to-tenant rule reads, so the ACME admin plane, which applies
// that rule pinned to the deployment's trust domain, resolves the user in
// its own tenant (go-xkms#1240). A pin naming the certificate's own tenant
// refuses it: no tenant may be the cluster trust domain.
func TestSignCSR_TenantResolvesThroughQRDBRule(t *testing.T) {
	ca := setupTestCA(t)
	csrPEM, _ := makeLeafCSR(t, "dave")

	cert, err := ca.SignCSRWithSPIFFE(context.Background(), csrPEM, "client", 30, "kms.example.com", "tenant-a", "", "")
	require.NoError(t, err)

	tenantID, err := qrdbsdk.TenantFromClientCert(cert, "kms.example.com")
	require.NoError(t, err)
	assert.Equal(t, "tenant-a", tenantID)

	_, err = qrdbsdk.TenantFromClientCert(cert, "tenant-a")
	var refusal *qrdbsdk.ClientCertificateTenantError
	require.ErrorAs(t, err, &refusal)
	assert.ErrorIs(t, err, qrdbsdk.ErrClientCertificateTenantIsClusterTrustDomain,
		"a tenant naming the cluster trust domain must be refused")
}

// Scenario (b): the keypair-issuance path (generate-and-distribute) must stamp
// the same tenant-scoped SPIFFE URI SAN as the CSR-sign path. This proves the
// CertificateRequest.SPIFFE* fields are forwarded into the shared SignCSR
// synthesis site.
func TestIssueCertificate_StampsTenantSPIFFESAN(t *testing.T) {
	ca := setupTestCA(t)

	issued, err := ca.IssueCertificateWithProfile(context.Background(), &CertificateRequest{
		Subject:           Subject{CommonName: "carol"},
		Valid:             30,
		SPIFFETrustDomain: "example.com",
		TenantID:          "tenant-acme",
	}, "client")
	require.NoError(t, err)
	require.NotNil(t, issued)
	require.NotNil(t, issued.Certificate)

	require.Len(t, issued.Certificate.URIs, 1, "exactly one SPIFFE URI SAN expected")
	got := issued.Certificate.URIs[0].String()
	want := "spiffe://tenant-acme/user/carol"
	assert.Equal(t, want, got, "keypair path must use the canonical tenant SPIFFE path")

	// It must round-trip through the shared parser, enforcing the pin.
	id, perr := spiffe.TenantFromURIs(issued.Certificate.URIs, "example.com")
	require.NoError(t, perr)
	assert.Equal(t, "tenant-acme", id.TenantID)
	assert.Equal(t, spiffe.KindUser, id.Kind)
	assert.Equal(t, "carol", id.Name)
}

// Explicit kind + name override the defaults on the keypair-issuance path.
func TestIssueCertificate_SPIFFEKindAndNameOverride(t *testing.T) {
	ca := setupTestCA(t)

	issued, err := ca.IssueCertificateWithProfile(context.Background(), &CertificateRequest{
		Subject:           Subject{CommonName: "ignored-cn"},
		Valid:             30,
		SPIFFETrustDomain: "trust.internal",
		TenantID:          "t1",
		SPIFFEKind:        spiffe.KindService,
		SPIFFEName:        "billing-api",
	}, "client")
	require.NoError(t, err)
	require.Len(t, issued.Certificate.URIs, 1)
	assert.Equal(t, "spiffe://t1/svc/billing-api",
		issued.Certificate.URIs[0].String())
}

// Backward compatibility: zero-value SPIFFE fields produce no SPIFFE SAN on the
// keypair-issuance path (legacy behavior preserved).
func TestIssueCertificate_NoSPIFFEWhenTrustDomainEmpty(t *testing.T) {
	ca := setupTestCA(t)

	issued, err := ca.IssueCertificate(context.Background(), &CertificateRequest{
		Subject:  Subject{CommonName: "nospiffe-keypair"},
		Valid:    30,
		TenantID: "t1", // tenant set but no trust domain => no SPIFFE SAN
	})
	require.NoError(t, err)
	assert.Empty(t, issued.Certificate.URIs,
		"no SPIFFE SAN expected without a trust domain")
}
