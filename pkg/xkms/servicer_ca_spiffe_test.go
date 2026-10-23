// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/spiffe"
)

const spiffeTestTrustDomain = "kms.example.com"

// spiffeTestCSR is a PEM CSR whose subject CommonName is cn.
func spiffeTestCSR(t *testing.T, cn string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: cn},
	}, key)
	require.NoError(t, err)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der})
}

// spiffeTestService is a service with a mock CA, a trust domain, and an
// authorizer granting exactly grant, called by a tenant-a identity.
func spiffeTestService(t *testing.T, grant string) (*XKMSService, *mockCA, *recordingRBAC, context.Context) {
	t.Helper()
	ca := &mockCA{signCSRCert: createSelfSignedCert(t), cert: createSelfSignedCert(t)}
	svc := setupServiceWithCA(t, ca)
	svc.SetSPIFFETrustDomain(spiffeTestTrustDomain)
	rbac := &recordingRBAC{grant: grant}
	svc.SetAuthorizer(auth.NewAuthorizer(rbac))
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "agent-enroller", TenantID: "tenant-a"})
	return svc, ca, rbac, ctx
}

// TestSignCSR_SPIFFEKindServiceIssuedWithPermission proves a caller holding
// certs:issue_service gets the svc kind stamped for its tenant.
func TestSignCSR_SPIFFEKindServiceIssuedWithPermission(t *testing.T) {
	svc, ca, rbac, ctx := spiffeTestService(t, "certs:issue_service")

	resp, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:     spiffeTestCSR(t, "agent-01"),
		TenantID:   "tenant-a",
		SPIFFEKind: spiffe.KindService,
	})
	require.NoError(t, err)
	require.NotEmpty(t, resp.CertificatePEM)
	assert.Equal(t, spiffe.KindService, ca.signCSRKind)
	assert.Equal(t, spiffeTestTrustDomain, ca.signCSRTrustDomain)
	assert.Equal(t, "tenant-a", ca.signCSRTenant)
	assert.Equal(t, auth.ResourceCerts, rbac.resource)
	assert.Equal(t, auth.ActionIssueService, rbac.action)
}

// TestSignCSR_SPIFFEKindServiceRefusedWithoutPermission proves a caller with
// only certs:issue cannot mint a service identity, and the CA is never asked.
// Removing the gate in checkSPIFFEKind makes this test fail.
func TestSignCSR_SPIFFEKindServiceRefusedWithoutPermission(t *testing.T) {
	svc, ca, _, ctx := spiffeTestService(t, "certs:issue")

	_, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:     spiffeTestCSR(t, "agent-01"),
		TenantID:   "tenant-a",
		SPIFFEKind: spiffe.KindService,
	})
	require.ErrorIs(t, err, ErrSPIFFEKindForbidden)
	require.ErrorIs(t, err, errGrantMissing)
	var refusal *SPIFFEKindPermissionError
	require.ErrorAs(t, err, &refusal)
	assert.Equal(t, "certs:issue_service", refusal.Permission)
	assert.Equal(t, spiffe.KindService, refusal.Kind)
	assert.Empty(t, ca.signCSRTenant, "a refused CSR must never reach the CA")
}

// TestSignCSR_SPIFFEKindUserNeedsNoExtraPermission proves the user kind is
// issued under certs:issue alone.
func TestSignCSR_SPIFFEKindUserNeedsNoExtraPermission(t *testing.T) {
	svc, ca, rbac, ctx := spiffeTestService(t, "certs:issue")

	_, err := svc.SignCSR(ctx, &transport.SignCSRRequest{
		CSRPEM:     spiffeTestCSR(t, "alice"),
		TenantID:   "tenant-a",
		SPIFFEKind: spiffe.KindUser,
	})
	require.NoError(t, err)
	assert.Equal(t, spiffe.KindUser, ca.signCSRKind)
	assert.Empty(t, rbac.action, "the user kind consults no extra permission")
}

// TestSignCSR_EmptySPIFFEKindKeepsDefault proves a request without a kind is
// signed exactly as before: no kind, no extra permission, no CSR parse.
func TestSignCSR_EmptySPIFFEKindKeepsDefault(t *testing.T) {
	svc, ca, rbac, ctx := spiffeTestService(t, "")
	req := testCSRRequest()
	req.TenantID = "tenant-a"

	resp, err := svc.SignCSR(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.signCSRCert.Raw}), resp.CertificatePEM)
	assert.Empty(t, ca.signCSRKind)
	assert.Equal(t, spiffeTestTrustDomain, ca.signCSRTrustDomain)
	assert.Empty(t, rbac.action, "an empty kind consults no extra permission")
}

// TestSignCSR_SPIFFEKindRefusals proves each malformed kind request is
// refused with its typed error before the CA is asked.
func TestSignCSR_SPIFFEKindRefusals(t *testing.T) {
	tests := []struct {
		name        string
		trustDomain string
		req         *transport.SignCSRRequest
		want        error
	}{
		{
			name:        "unknown kind",
			trustDomain: spiffeTestTrustDomain,
			req:         &transport.SignCSRRequest{CSRPEM: spiffeTestCSR(t, "agent-01"), TenantID: "tenant-a", SPIFFEKind: "node"},
			want:        ErrSPIFFEKindUnknown,
		},
		{
			name:        "kind without tenant",
			trustDomain: spiffeTestTrustDomain,
			req:         &transport.SignCSRRequest{CSRPEM: spiffeTestCSR(t, "agent-01"), SPIFFEKind: spiffe.KindService},
			want:        ErrSPIFFEKindWithoutTenant,
		},
		{
			name:        "kind without trust domain",
			trustDomain: "",
			req:         &transport.SignCSRRequest{CSRPEM: spiffeTestCSR(t, "agent-01"), TenantID: "tenant-a", SPIFFEKind: spiffe.KindService},
			want:        ErrSPIFFEKindWithoutTrustDomain,
		},
		{
			name:        "name outside the segment alphabet",
			trustDomain: spiffeTestTrustDomain,
			req:         &transport.SignCSRRequest{CSRPEM: spiffeTestCSR(t, "agent 01/x"), TenantID: "tenant-a", SPIFFEKind: spiffe.KindService},
			want:        ErrSPIFFENameInvalid,
		},
		{
			name:        "empty name",
			trustDomain: spiffeTestTrustDomain,
			req:         &transport.SignCSRRequest{CSRPEM: spiffeTestCSR(t, ""), TenantID: "tenant-a", SPIFFEKind: spiffe.KindUser},
			want:        ErrSPIFFENameInvalid,
		},
		{
			name:        "malformed csr",
			trustDomain: spiffeTestTrustDomain,
			req:         &transport.SignCSRRequest{CSRPEM: testCSRRequest().CSRPEM, TenantID: "tenant-a", SPIFFEKind: spiffe.KindUser},
			want:        ErrCSRMalformed,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, ca, _, ctx := spiffeTestService(t, "certs:issue_service")
			svc.SetSPIFFETrustDomain(tt.trustDomain)

			_, err := svc.SignCSR(ctx, tt.req)
			require.ErrorIs(t, err, tt.want)
			var validation *ErrValidation
			require.ErrorAs(t, err, &validation)
			assert.Empty(t, ca.signCSRTenant, "a refused CSR must never reach the CA")
		})
	}
}
