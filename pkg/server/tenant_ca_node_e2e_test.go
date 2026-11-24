package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbauth "github.com/jeremyhahn/go-qrdb/pkg/auth"
	"github.com/jeremyhahn/go-qrdb/pkg/permission"
	qrdbtenant "github.com/jeremyhahn/go-qrdb/pkg/tenant"
	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/require"
)

// tenantLoginCADER returns the login CA certificate the server's factory
// serves for tenantID.
func tenantLoginCADER(t *testing.T, s *Server, tenantID string) []byte {
	t.Helper()
	require.NotNil(t, s.tenantCAKeys, "WithTenantLoginCAKeys must install the factory")
	p, err := s.tenantCAKeys.ProviderForTenant(tenantID)
	require.NoError(t, err)
	cert, err := p.Certificate(context.Background())
	require.NoError(t, err)
	signer, err := p.Signer(context.Background())
	require.NoError(t, err)
	require.True(t, tenantLoginCACertFor(cert, signer.Public()), "the served login CA must be over the live key")
	return cert.Raw
}

// authenticateCert runs the node's own authentication of an HTTP request
// whose TLS peer presented cert.
func authenticateCert(t *testing.T, s *Server, cert *x509.Certificate) (*qrdbauth.Identity, error) {
	t.Helper()
	r := httptest.NewRequest(http.MethodGet, "/v1/health", nil)
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{cert}}
	ctx := qrdbauth.WithTLSState(r.Context(), r.TLS)
	_, id, err := s.qrdbNode.AuthMiddleware().AuthenticateHTTP(ctx, httptest.NewRecorder(), r.WithContext(ctx))
	return id, err
}

// The tenant login CA seam end to end through a real embedded go-qrdb node:
// a tenant onboarded through xkms gets its login CA from the xkms key
// factory, go-qrdb issues an account certificate under it, the certificate
// authenticates, and after a restart on the same data the same CA is served
// and the same credential still authenticates.
func TestServer_TenantLoginCANodeE2E_OnboardLoginRestart(t *testing.T) {
	xkms.Reset()
	defer xkms.Reset()

	cfg := qrdbBarrierConfig(t)
	cfg.Barrier = config.BarrierConfig{Enabled: true, Strategy: "none"}

	s, err := New(cfg, WithTenantLoginCAKeys())
	require.NoError(t, err)
	stopped := false
	defer func() {
		if !stopped {
			_ = s.Shutdown()
		}
	}()
	require.NotNil(t, s.qrdbNode, "the embedded node must run")

	ctx := context.Background()
	const tenantID = "e2e-tenant"
	_, err = s.xkmsService.CreateTenant(ctx, &transport.CreateTenantRequest{ID: tenantID, Name: "E2E Tenant"})
	require.NoError(t, err)
	caDER := tenantLoginCADER(t, s, tenantID)

	// A tenant administrator of the new tenant: go-qrdb scopes account and
	// certificate administration to the caller's own tenant.
	adminCtx := qrdbauth.WithIdentity(qrdbtenant.WithTenantID(ctx, tenantID), qrdbauth.NewServicePrincipal("xkms-e2e-tenant-admin", tenantID, []string{
		string(permission.UsersCreate), string(permission.UsersRead), string(permission.UsersUpdate), string(permission.CertsIssue),
	}))
	account, err := s.qrdbNode.UserService().CreateUser(adminCtx, &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@e2e-tenant.example",
		TenantID: tenantID,
	})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "alice"}}, key)
	require.NoError(t, err)
	enrolled, err := s.qrdbNode.Client().Certs().IssueCert(adminCtx, &qrdbtransport.IssueCertRequest{
		Username: "alice",
		CSRPEM:   string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})),
	})
	require.NoError(t, err)
	require.Equal(t, account.ID, enrolled.UserID)
	block, _ := pem.Decode([]byte(enrolled.CertPEM))
	require.NotNil(t, block)
	leaf, err := x509.ParseCertificate(block.Bytes)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)
	require.NoError(t, leaf.CheckSignatureFrom(caCert), "the account certificate must be issued under the xkms login CA")

	id, err := authenticateCert(t, s, leaf)
	require.NoError(t, err, "the issued certificate must authenticate")
	require.Equal(t, tenantID, id.TenantID)
	require.Equal(t, account.ID, id.UserID)

	stopped = true
	require.NoError(t, s.Shutdown())
	xkms.Reset()

	restarted, err := New(cfg, WithTenantLoginCAKeys())
	require.NoError(t, err)
	defer func() { _ = restarted.Shutdown() }()
	require.Equal(t, caDER, tenantLoginCADER(t, restarted, tenantID), "a restart must keep the tenant's login CA")
	id, err = authenticateCert(t, restarted, leaf)
	require.NoError(t, err, "the credential must still authenticate after a restart")
	require.Equal(t, tenantID, id.TenantID)
	require.Equal(t, account.ID, id.UserID)
}
