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

package rest

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

const pivTenantTrustDomain = "xkms.test"

var errNoTenantBinding = errors.New("test: no certificate binding in the context tenant")

// tenantAuthUserStore resolves a thumbprint only inside the tenant bound to
// the context, the way qrdb's QRDBUserStore does (go-qrdb pkg/user).
type tenantAuthUserStore struct {
	bindings map[string]map[string]auth.MTLSUser // tenant -> thumbprint -> user
	lookedUp []string
}

func (s *tenantAuthUserStore) GetByCertFingerprint(ctx context.Context, thumbprint string) (auth.MTLSUser, error) {
	bound, _ := qrdbsdk.TenantFromContext(ctx)
	tenantID := qrdbsdk.NormalizeTenantID(bound)
	s.lookedUp = append(s.lookedUp, tenantID)
	user, ok := s.bindings[tenantID][thumbprint]
	if !ok {
		return auth.MTLSUser{}, errNoTenantBinding
	}
	return user, nil
}

// pivTenantCert issues a self-signed login certificate for key that names
// the given SPIFFE URI SAN (none when empty) and Subject OUs.
func pivTenantCert(t *testing.T, key *ecdsa.PrivateKey, spiffeID string, ous ...string) *x509.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "admin", OrganizationalUnit: ous},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	if spiffeID != "" {
		uri, err := url.Parse(spiffeID)
		require.NoError(t, err)
		template.URIs = []*url.URL{uri}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// pivTenantServer wires a PIV login pinned to pivTenantTrustDomain with an
// "acme" tenant user and a system admin, both bound to their own keys.
func pivTenantServer(t *testing.T, store auth.UserStore) (*Server, *mockAuthAuditLogger) {
	t.Helper()
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true, TrustDomain: pivTenantTrustDomain}
		c.AuthUserStore = store
		c.AuditLogger = auditLog
	})
	return server, auditLog
}

type pivTenantFixture struct {
	store     *tenantAuthUserStore
	tenantKey *ecdsa.PrivateKey
	systemKey *ecdsa.PrivateKey
}

func newPIVTenantFixture(t *testing.T) *pivTenantFixture {
	t.Helper()
	tenantKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	systemKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tenantThumb := qrdbsdk.ComputeSPKIThumbprint(pivTenantCert(t, tenantKey, ""))
	systemThumb := qrdbsdk.ComputeSPKIThumbprint(pivTenantCert(t, systemKey, ""))
	return &pivTenantFixture{
		store: &tenantAuthUserStore{bindings: map[string]map[string]auth.MTLSUser{
			"acme": {tenantThumb: {Username: "admin", Roles: []string{"admin"}, TenantID: "acme", Enabled: true}},
			qrdbsdk.SystemTenantID: {systemThumb: {
				Username: "root", Roles: []string{"admin"}, TenantID: qrdbsdk.SystemTenantID, Enabled: true,
			}},
		}},
		tenantKey: tenantKey,
		systemKey: systemKey,
	}
}

func lastPIVAudit(t *testing.T, auditLog *mockAuthAuditLogger) *audit.Event {
	t.Helper()
	events := auditLog.Events()
	require.NotEmpty(t, events)
	last := events[len(events)-1]
	assert.Equal(t, "auth.login.piv", last.Action)
	return last
}

func TestPIVLogin_TenantUserLogsInWithinTheCertificateTenant(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, auditLog := pivTenantServer(t, f.store)

	cert := pivTenantCert(t, f.tenantKey, "spiffe://"+pivTenantTrustDomain+"/tenant/acme/user/admin")
	w := doAuthRequest(t, server, pivRequest(cert))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{"acme"}, f.store.lookedUp, "the thumbprint is looked up in the certificate's tenant only")
	assert.Equal(t, audit.OutcomeAllow, lastPIVAudit(t, auditLog).Outcome)
}

func TestPIVLogin_TenantFromSubjectOU(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, _ := pivTenantServer(t, f.store)

	w := doAuthRequest(t, server, pivRequest(pivTenantCert(t, f.tenantKey, "", "acme")))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{"acme"}, f.store.lookedUp)
}

func TestPIVLogin_CertificateNamingAnotherTenantIsRefused(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, auditLog := pivTenantServer(t, f.store)

	cert := pivTenantCert(t, f.tenantKey, "spiffe://"+pivTenantTrustDomain+"/tenant/globex/user/admin")
	w := doAuthRequest(t, server, pivRequest(cert))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication failed")
	assert.Equal(t, []string{"globex"}, f.store.lookedUp, "acme's binding is never searched")
	last := lastPIVAudit(t, auditLog)
	assert.Equal(t, audit.OutcomeDeny, last.Outcome)
	assert.Equal(t, "no user binding", last.Details["reason"])
}

func TestPIVLogin_ForeignTrustDomainIsRefused(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, auditLog := pivTenantServer(t, f.store)

	cert := pivTenantCert(t, f.tenantKey, "spiffe://other.example.com/tenant/acme/user/admin", "acme")
	w := doAuthRequest(t, server, pivRequest(cert))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication failed")
	assert.Empty(t, f.store.lookedUp, "a refused certificate tenant never reaches the user store")
	last := lastPIVAudit(t, auditLog)
	assert.Equal(t, audit.OutcomeDeny, last.Outcome)
	assert.Equal(t, "certificate tenant refused", last.Details["reason"])
}

func TestPIVLogin_ResolvedUserInAnotherTenantIsRefused(t *testing.T) {
	// A store that answers outside the bound tenant must not mint a token
	// for the certificate's tenant: the resolved user's tenant is checked.
	auditLog := &mockAuthAuditLogger{}
	server := newAuthTestServer(t, func(c *Config) {
		c.PIVLogin = &PIVLoginOptions{Enabled: true, AllowUnattested: true, TrustDomain: pivTenantTrustDomain}
		c.AuthUserStore = &fakeAuthUserStore{user: auth.MTLSUser{
			Username: "root", Roles: []string{"admin"}, TenantID: qrdbsdk.SystemTenantID, Enabled: true,
		}}
		c.AuditLogger = auditLog
	})
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	cert := pivTenantCert(t, key, "spiffe://"+pivTenantTrustDomain+"/tenant/acme/user/admin")
	w := doAuthRequest(t, server, pivRequest(cert))

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Contains(t, w.Body.String(), "authentication failed")
	last := lastPIVAudit(t, auditLog)
	assert.Equal(t, audit.OutcomeDeny, last.Outcome)
	assert.Equal(t, "certificate tenant mismatch", last.Details["reason"])
}

func TestPIVLogin_CertificateWithoutTenantUsesSystemTenant(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, _ := pivTenantServer(t, f.store)

	w := doAuthRequest(t, server, pivRequest(pivTenantCert(t, f.systemKey, "")))

	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	assert.Equal(t, []string{qrdbsdk.SystemTenantID}, f.store.lookedUp)
}

func TestPIVLogin_IgnoresTenantInHeaderAndBody(t *testing.T) {
	f := newPIVTenantFixture(t)
	server, _ := pivTenantServer(t, f.store)

	// The acme user's key with a certificate naming no tenant: a request
	// that names acme in a header and the body is still looked up in the
	// system tenant, so it finds no binding.
	req := pivRequest(pivTenantCert(t, f.tenantKey, ""))
	req.Header.Set("X-Tenant-ID", "acme")
	req.Header.Set("X-Tenant", "acme")
	req.Header.Set("Content-Type", "application/json")
	req.Body = io.NopCloser(strings.NewReader(`{"tenant_id":"acme","tenant":"acme"}`))
	w := doAuthRequest(t, server, req)

	assert.Equal(t, http.StatusUnauthorized, w.Code)
	assert.Equal(t, []string{qrdbsdk.SystemTenantID}, f.store.lookedUp)
}
