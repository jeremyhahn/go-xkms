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

package issuance

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

// testTenant is the tenant the package's tests issue certificates for.
const testTenant = "tenant-test"

// newTenantTestIssuer returns an enabled issuer that issues without
// Certificate Transparency.
func newTenantTestIssuer(t *testing.T) Issuer {
	t.Helper()
	issuer, err := NewIssuer(Config{
		Signer:         newMockSigner(t),
		Linter:         &mockLinter{passed: true},
		CertStorage:    newMockCertStorage(),
		SerialStorage:  newMockSerialStorage(),
		AuditLogger:    &mockAuditLogger{},
		Enabled:        true,
		Profiles:       map[string]Profile{"internal": InternalProfile()},
		DefaultProfile: "internal",
	})
	require.NoError(t, err)
	return issuer
}

// tenantClaimingRequest returns a request for tenantID whose CSR asserts an
// organizational unit of its own.
func tenantClaimingRequest(t *testing.T, tenantID string) *Request {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: "test.example.com", OrganizationalUnit: []string{"another-tenant"}},
		DNSNames: []string{"test.example.com"},
	}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return &Request{
		TenantID:  tenantID,
		CSR:       csr,
		NotBefore: time.Now(),
		NotAfter:  time.Now().AddDate(0, 0, 90),
		Profile:   "internal",
		SkipCT:    true,
	}
}

func TestIssuer_Issue_StampsTheTenantOverTheCSRsOrganizationalUnit(t *testing.T) {
	result, err := newTenantTestIssuer(t).Issue(context.Background(), tenantClaimingRequest(t, testTenant))
	require.NoError(t, err)

	assert.Equal(t, []string{testTenant}, result.FinalCert.Subject.OrganizationalUnit)
}

func TestIssuer_Issue_RefusesARequestWithoutATenant(t *testing.T) {
	_, err := newTenantTestIssuer(t).Issue(context.Background(), tenantClaimingRequest(t, ""))
	require.ErrorIs(t, err, ca.ErrTenantRequired)
}
