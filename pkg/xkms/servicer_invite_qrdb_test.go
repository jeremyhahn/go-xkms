package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"log/slog"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbauth "github.com/jeremyhahn/go-qrdb/pkg/auth"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"

	xkmstransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
)

const (
	qrdbInviteTenant = qrdbsdk.SystemTenantID
	qrdbInviteEmail  = "invitee@invite-qrdb.example.com"
)

// hookedUserClient is the real qrdb user client with test hooks run before
// the service's reads and writes reach it.
type hookedUserClient struct {
	qrdbtransport.UserClient

	beforeGetUser    func()
	beforeBind       func()
	beforeActivate   func()
	beforeBindOnce   sync.Once
	beforeActiveOnce sync.Once
}

func (h *hookedUserClient) GetUser(ctx context.Context, id uint64) (*qrdbtransport.User, error) {
	u, err := h.UserClient.GetUser(ctx, id)
	if h.beforeGetUser != nil {
		h.beforeGetUser()
	}
	return u, err
}

func (h *hookedUserClient) AddCertBinding(ctx context.Context, userID uint64, thumbprint string, notAfterUnix int64) (*qrdbtransport.User, error) {
	if h.beforeBind != nil {
		h.beforeBindOnce.Do(h.beforeBind)
	}
	return h.UserClient.AddCertBinding(ctx, userID, thumbprint, notAfterUnix)
}

func (h *hookedUserClient) UpdateUser(ctx context.Context, req *qrdbtransport.UpdateUserRequest) (*qrdbtransport.User, error) {
	if h.beforeActivate != nil && req != nil && req.Lifecycle == string(qrdbsdk.LifecycleActive) {
		h.beforeActiveOnce.Do(h.beforeActivate)
	}
	return h.UserClient.UpdateUser(ctx, req)
}

type qrdbInviteFixture struct {
	*inviteFixture
	ctx    context.Context
	real   qrdbtransport.UserClient
	hooked *hookedUserClient
	userID uint64
	token  string
	store  *invitetest.Store
}

// newQRDBInviteFixture wires the invite flow to a real standalone qrdb node
// holding one pending invitee and one minted invitation.
func newQRDBInviteFixture(t *testing.T) *qrdbInviteFixture {
	t.Helper()
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	n := newInviteQRDBNode(t)
	ctx, err := n.ServiceContext(context.Background())
	require.NoError(t, err)
	real := n.Client().Users()

	u, err := real.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: qrdbInviteEmail, Email: qrdbInviteEmail, Name: "Invitee",
		TenantID: qrdbInviteTenant, Pending: true,
	})
	require.NoError(t, err)
	require.Equal(t, string(qrdbsdk.LifecyclePending), u.Lifecycle)

	hooked := &hookedUserClient{UserClient: real}
	svc.SetUserClients(hooked, n.Client().Roles())

	waStores := webauthntest.NewStoresFor(t, hooked)
	cfg := &webauthn.Config{
		RPID:          "example.com",
		RPDisplayName: "xkms test",
		RPOrigins:     []string{"https://example.com"},
	}
	waSvc, err := webauthn.NewService(webauthn.ServiceParams{
		Config:          cfg,
		UserStore:       waStores.Users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: waStores.Credentials,
	})
	require.NoError(t, err)
	svc.SetWebAuthn(waSvc)

	store, err := invitetest.New(singleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	svc.SetInviteStore(store)

	base := &inviteFixture{svc: svc, inviteTTL: time.Hour}
	base.rp.Name, base.rp.ID, base.rp.Origin = cfg.RPDisplayName, cfg.RPID, cfg.RPOrigins[0]

	info, err := svc.createInvite(ctx, qrdbInviteTenant, u.ID, time.Hour)
	require.NoError(t, err)
	return &qrdbInviteFixture{inviteFixture: base, ctx: ctx, real: real, hooked: hooked, userID: u.ID, token: info.Token, store: store}
}

func (f *qrdbInviteFixture) account(t *testing.T) *qrdbtransport.User {
	t.Helper()
	u, err := f.real.GetUser(f.ctx, f.userID)
	require.NoError(t, err)
	return u
}

func (f *qrdbInviteFixture) disable(t *testing.T) func() {
	return func() { require.NoError(t, f.real.DisableUser(f.ctx, f.userID)) }
}

// usersAdminAuthorizer grants every action on users, so the test caller acts
// as both the service and the administrator; other resources defer to inner.
type usersAdminAuthorizer struct{ inner qrdbauth.Authorizer }

func (a usersAdminAuthorizer) Authorize(ctx context.Context, identity *qrdbauth.Identity, resource, action string) error {
	if resource == "users" {
		return nil
	}
	return a.inner.Authorize(ctx, identity, resource, action)
}

func (f *qrdbInviteFixture) redeemPIV(cert *x509.Certificate) error {
	_, err := f.svc.ActivateInvitePIV(f.ctx, &xkmstransport.ActivateInvitePIVRequest{TenantID: qrdbInviteTenant, Token: f.token, CertPEM: string(pemEncodeCert(cert))})
	return err
}

// newInviteQRDBNode starts a standalone qrdb node holding the system\n// tenant, callable as the xkms service principal.
func newInviteQRDBNode(t *testing.T) *qrdbnode.Node {
	t.Helper()
	ctx := context.Background()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false

	node, err := qrdbnode.NewStandaloneNode(ctx, cfg, nil, serviceprincipal.Option(),
		qrdbnode.WithAuthorizerWrapper(func(inner qrdbauth.Authorizer) qrdbauth.Authorizer {
			return usersAdminAuthorizer{inner: inner}
		}))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	svcs := node.Services()
	require.NotNil(t, svcs)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err = qrdbsdk.FirstBootInitialize(ctx, qrdbsdk.FirstBootDependencies{
		Tenants: svcs.Tenant, Users: svcs.User, Roles: svcs.Role, Logger: logger,
	})
	require.NoError(t, err)
	return node
}

func (f *qrdbInviteFixture) requireNotRedeemed(t *testing.T) {
	t.Helper()
	_, err := f.store.Lookup(context.Background(), qrdbInviteTenant, f.token)
	require.NoError(t, err, "the invitation must not be redeemed")
}

// issueInviteLeaves returns n distinct client certificates chained to one CA.
func issueInviteLeaves(t *testing.T, n int) (*x509.Certificate, []*x509.Certificate) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "xkms test invite CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	leaves := make([]*x509.Certificate, 0, n)
	for i := 0; i < n; i++ {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		leafTemplate := &x509.Certificate{
			SerialNumber: big.NewInt(int64(i + 2)),
			Subject:      pkix.Name{CommonName: "invitee PIV cert"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(24 * time.Hour),
			KeyUsage:     x509.KeyUsageDigitalSignature,
			ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caTemplate, &leafKey.PublicKey, caKey)
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(leafDER)
		require.NoError(t, err)
		leaves = append(leaves, leaf)
	}
	return caCert, leaves
}

// TestActivateInvitePIV_QRDB_ConcurrentRedemptionBindsOnce proves that of N
// concurrent redemptions of one invitation exactly one activates the account,
// and no losing certificate stays bound.
func TestActivateInvitePIV_QRDB_ConcurrentRedemptionBindsOnce(t *testing.T) {
	const n = 8
	f := newQRDBInviteFixture(t)
	caCert, leaves := issueInviteLeaves(t, n)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	// Every redemption reads the account before any of them writes, so all
	// of them pass a read-side pending check.
	var arrived sync.WaitGroup
	arrived.Add(n)
	allRead := make(chan struct{})
	go func() { arrived.Wait(); close(allRead) }()
	f.hooked.beforeGetUser = func() {
		arrived.Done()
		select {
		case <-allRead:
		case <-time.After(5 * time.Second):
		}
	}

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = f.redeemPIV(leaves[i])
		}(i)
	}
	wg.Wait()

	winners := 0
	for i, err := range errs {
		if err == nil {
			winners++
			continue
		}
		assert.ErrorIs(t, err, ErrInviteUnusable, "redemption %d: %v", i, err)
	}
	assert.Equal(t, 1, winners, "exactly one redemption succeeds")

	u := f.account(t)
	assert.Equal(t, string(qrdbsdk.LifecycleActive), u.Lifecycle)
	require.Len(t, u.CertBindings, 1, "only the winning certificate is bound")
	var winner int = -1
	for i, err := range errs {
		if err == nil {
			winner = i
		}
	}
	if winner >= 0 {
		assert.Equal(t, qrdbsdk.ComputeSPKIThumbprint(leaves[winner]), u.CertBindings[0].Thumbprint)
	}
}

// TestActivateInvitePIV_QRDB_AdminDisableBeforeWriteWins proves an
// administrator's disable that lands after the pending check is not
// overwritten by the redemption.
func TestActivateInvitePIV_QRDB_AdminDisableBeforeWriteWins(t *testing.T) {
	f := newQRDBInviteFixture(t)
	caCert, leaves := issueInviteLeaves(t, 1)
	f.svc.SetCA(&mockCA{bundlePEM: pemEncodeCert(caCert)})

	disable := f.disable(t)
	f.hooked.beforeBind = disable
	f.hooked.beforeActivate = disable

	err := f.redeemPIV(leaves[0])
	require.ErrorIs(t, err, ErrInviteUnusable)

	u := f.account(t)
	assert.Equal(t, string(qrdbsdk.LifecycleDisabled), u.Lifecycle)
	assert.Empty(t, u.CertBindings, "no certificate is bound to the disabled account")
	f.requireNotRedeemed(t)
}

// TestFinishInviteRegistration_QRDB_AdminDisableBeforeActivateWins proves an
// administrator's disable that lands during the WebAuthn ceremony is not
// overwritten by the activation.
func TestFinishInviteRegistration_QRDB_AdminDisableBeforeActivateWins(t *testing.T) {
	f := newQRDBInviteFixture(t)

	begin, err := f.svc.BeginInviteRegistration(f.ctx, &xkmstransport.BeginInviteRegistrationRequest{TenantID: qrdbInviteTenant, Token: f.token})
	require.NoError(t, err)
	attestation := f.attestInvite(t, begin.OptionsJSON, newInviteEC2Credential(t))

	f.hooked.beforeActivate = f.disable(t)

	_, err = f.svc.FinishInviteRegistration(f.ctx, &xkmstransport.FinishInviteRegistrationRequest{
		TenantID: qrdbInviteTenant, Token: f.token, SessionID: begin.SessionID, AttestationJSON: attestation,
	})
	require.ErrorIs(t, err, ErrInviteUnusable)

	assert.Equal(t, string(qrdbsdk.LifecycleDisabled), f.account(t).Lifecycle)
	f.requireNotRedeemed(t)
}
