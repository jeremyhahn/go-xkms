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

package rest

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"

	qrdbauth "github.com/jeremyhahn/go-qrdb/pkg/auth"
	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newEnforcingNode boots a real in-memory standalone qrdb node that enforces
// authentication and carries xkms's service principal, as xkmsd's embedded
// node does.
func newEnforcingNode(t *testing.T) *qrdbnode.Node {
	t.Helper()
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })
	return node
}

// newEnforcingHostServer builds the host REST surface over an
// authentication-enforcing node, bound to its ServiceContext the way xkmsd
// wires it.
func newEnforcingHostServer(t *testing.T, node *qrdbnode.Node) *Server {
	t.Helper()
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	// As xkmsd does when it builds WebAuthn over its embedded node: the
	// principal gains the user store's users grant.
	serviceprincipal.RegisterWebAuthnGrant()
	allow := true
	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService: svc,
		QRDBClient:  node.Client(),
		DAOFactory:  testutil.NewMemoryDAOFactory(),
		WebAuthn: WebAuthnConfigFromXKMS(&config.WebAuthnConfig{
			RPID:                    "example.com",
			AllowPublicRegistration: &allow,
		}),
		WebAuthnCallContext: node.ServiceContext,
		UserLookup:          node.UserService(),
	})
	require.NoError(t, err)
	require.NotNil(t, srv.tokenIssuer, "the host must mount a token issuer")
	return srv
}

// TestNewHostServer_TokenIssuerRunsOnTheCallContext is the regression test
// for #2541 P1 (1): the refresh-token record a ceremony's Finish writes runs
// on the host's bound context, so an anonymous login completes on a node
// that enforces authentication instead of failing unauthenticated (a 500).
func TestNewHostServer_TokenIssuerRunsOnTheCallContext(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: "default",
	})
	require.NoError(t, err, "minting on an anonymous context must run as the service principal")
	require.NotNil(t, pair)
}

// TestNewHostServer_RefreshResolvesOnTheCallContext is the regression test
// for #2541 P1 (2): POST /api/v1/auth/refresh is public, so the resolver's
// current-account lookup runs on the host's bound context. A valid refresh
// token for a live account rotates (200) on a node that enforces
// authentication instead of failing unauthenticated (401).
func TestNewHostServer_RefreshResolvesOnTheCallContext(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	// The account exists before the login: seed it below the RBAC layer, as
	// an operator's earlier sign-up would have.
	_, err := node.UserService().CreateUser(context.Background(), &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice",
	})
	require.NoError(t, err)

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: DefaultWebAuthnTenant,
		Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
	})
	require.NoError(t, err)

	body, err := json.Marshal(map[string]string{"refresh_token": pair.RefreshToken})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
}

// refreshWithoutWebAuthnChild marks the child process
// TestBuildTokenIssuer_RefreshWithoutWebAuthn re-executes itself in.
const refreshWithoutWebAuthnChild = "GO_XKMS_TEST_REFRESH_WITHOUT_WEBAUTHN"

// TestBuildTokenIssuer_RefreshWithoutWebAuthn proves a PIV/mTLS-only daemon
// (no WebAuthn service, so no WebAuthn grant) refreshes a session it minted
// over an enforcing embedded node: the bound user resolver's recheck runs as
// the service principal and needs users:read on its own. The principal's
// grants are process-wide and cannot be withdrawn, so the test runs in a
// fresh child process in which nothing registered the WebAuthn grant.
func TestBuildTokenIssuer_RefreshWithoutWebAuthn(t *testing.T) {
	if os.Getenv(refreshWithoutWebAuthnChild) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBuildTokenIssuer_RefreshWithoutWebAuthn$", "-test.count=1")
		cmd.Env = append(os.Environ(), refreshWithoutWebAuthnChild+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "child process:\n%s", out)
		require.Contains(t, string(out), "PASS", "child process:\n%s", out)
		return
	}

	node := newEnforcingNode(t)
	require.False(t, qrdbsdk.HasPermissionRoleGrant(serviceprincipal.Name, "users:create"),
		"the WebAuthn grant must not be registered in this process")

	_, err := node.UserService().CreateUser(context.Background(), &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@example.com",
		Name:     "Alice",
	})
	require.NoError(t, err)

	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
		QRDBClient:  node.Client(),
		CallContext: node.ServiceContext,
	})
	require.NoError(t, err)

	pair, err := issuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: DefaultWebAuthnTenant,
		Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
	})
	require.NoError(t, err)

	refreshed, err := issuer.Refresh(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	require.NotEmpty(t, refreshed.AccessToken)
}

const refreshTenantAccountChild = "GO_XKMS_TEST_REFRESH_TENANT_ACCOUNT"

// TestBuildTokenIssuer_RefreshResolvesTheAccountInItsTenant: over an
// enforcing node whose service principal belongs to the system tenant, a
// refresh re-checks the account in the tenant the refresh token carries, by
// username and by WebAuthn user handle, for a system-tenant account and for
// one in a provisioned tenant alike. Refresh records stay the principal's.
// It re-executes itself in a child process because the refresh grant
// BuildTokenIssuer registers is process-wide.
func TestBuildTokenIssuer_RefreshResolvesTheAccountInItsTenant(t *testing.T) {
	if os.Getenv(refreshTenantAccountChild) != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestBuildTokenIssuer_RefreshResolvesTheAccountInItsTenant$", "-test.count=1")
		cmd.Env = append(os.Environ(), refreshTenantAccountChild+"=1")
		out, err := cmd.CombinedOutput()
		require.NoError(t, err, "child process:\n%s", out)
		require.Contains(t, string(out), "PASS", "child process:\n%s", out)
		return
	}

	node := newEnforcingNode(t)
	const tenantID = "acme"
	provisionTenant(t, node, tenantID)

	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
		QRDBClient:  node.Client(),
		CallContext: node.ServiceContext,
		UserLookup:  node.UserService(),
	})
	require.NoError(t, err)

	for _, tenant := range []string{DefaultWebAuthnTenant, tenantID} {
		created, err := node.UserService().CreateUser(qrdbsdk.ContextWithTenant(context.Background(), tenant), &qrdbuser.CreateUserRequest{
			Username: "alice",
			Email:    "alice@" + tenant + ".example",
			Name:     "Alice of " + tenant,
			TenantID: tenant,
		})
		require.NoError(t, err, "tenant %s", tenant)
		require.Equal(t, tenant, created.TenantID)

		handle := make([]byte, 8)
		binary.BigEndian.PutUint64(handle, created.ID)
		for kind, subject := range map[string]string{
			auth.SubjectKindUsername:   "alice",
			auth.SubjectKindUserHandle: base64.RawURLEncoding.EncodeToString(handle),
		} {
			pair, err := issuer.Mint(context.Background(), &auth.Identity{
				Subject:  subject,
				TenantID: tenant,
				Metadata: map[string]string{auth.SubjectKindMetadataKey: kind},
			})
			require.NoError(t, err, "mint, tenant %s, %s", tenant, kind)

			refreshed, err := issuer.Refresh(context.Background(), pair.RefreshToken)
			require.NoError(t, err, "refresh, tenant %s, %s", tenant, kind)
			require.NotEmpty(t, refreshed.AccessToken)
			parts := strings.Split(refreshed.AccessToken, ".")
			require.Len(t, parts, 3, "the access token is a compact JWS")
			payload, err := base64.RawURLEncoding.DecodeString(parts[1])
			require.NoError(t, err)
			var claims map[string]any
			require.NoError(t, json.Unmarshal(payload, &claims))
			require.Equal(t, tenant, claims["tenant_id"], "the refreshed session stays in tenant %s (%s)", tenant, kind)
			require.Equal(t, "Alice of "+tenant, claims["name"], "the account re-read is the one in tenant %s (%s)", tenant, kind)
		}
	}
}

// provisionTenant provisions tenantID on node's identity plane, with its
// admin enrollment deferred.
func provisionTenant(t *testing.T, node *qrdbnode.Node, tenantID string) {
	t.Helper()
	svcs := node.Services()
	require.NotNil(t, svcs)
	factors, ok := svcs.UserAuthFactor.(qrdbsdk.ActiveFactorChecker)
	require.True(t, ok, "the node's auth-factor service checks active factors")
	_, err := qrdbsdk.ProvisionTenant(context.Background(), qrdbsdk.BootstrapTenantProvisionConfig{
		TenantID:        tenantID,
		Isolation:       qrdbsdk.TenantIsolationPrefix,
		AdminEnrollment: qrdbsdk.BootstrapAdminEnrollDeferred,
	}, qrdbsdk.BootstrapDependencies{
		Tenants:      svcs.Tenant,
		Users:        svcs.User,
		Roles:        svcs.Role,
		AdminFactors: factors,
		Logger:       slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
}

// A logout (and a lifecycle revocation) runs on a context that carries the
// session's own tenant. The refresh records are the service principal's in
// the system tenant, so the store must reach them there whatever tenant the
// caller's context names.
func TestBuildTokenIssuer_LogoutFromATenantRevokesTheFamily(t *testing.T) {
	node := newEnforcingNode(t)
	const tenantID = "acme"
	provisionTenant(t, node, tenantID)
	tenantCtx := qrdbsdk.ContextWithTenant(context.Background(), tenantID)
	_, err := node.UserService().CreateUser(tenantCtx, &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@acme.example",
		Name:     "Alice of acme",
		TenantID: tenantID,
	})
	require.NoError(t, err)

	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     xkmsmocks.NewMockKeyStore(),
		BackendName: "test",
		QRDBClient:  node.Client(),
		CallContext: node.ServiceContext,
		UserLookup:  node.UserService(),
	})
	require.NoError(t, err)

	alice := &auth.Identity{
		Subject:  "alice",
		TenantID: tenantID,
		Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
	}
	pair, err := issuer.Mint(context.Background(), alice)
	require.NoError(t, err, "an anonymous login mints the session")
	require.NoError(t, issuer.Revoke(tenantCtx, pair.RefreshToken), "a logout in tenant %s revokes its session", tenantID)
	_, err = issuer.Refresh(context.Background(), pair.RefreshToken)
	var revoked *token.RefreshRevokedError
	require.ErrorAs(t, err, &revoked, "the logged-out family no longer refreshes")

	pair, err = issuer.Mint(context.Background(), alice)
	require.NoError(t, err)
	require.NoError(t, issuer.RevokeBySubject(tenantCtx, tenantID, "alice"), "a lifecycle revocation in tenant %s revokes its sessions", tenantID)
	_, err = issuer.Refresh(context.Background(), pair.RefreshToken)
	require.ErrorAs(t, err, &revoked, "the revoked account's family no longer refreshes")
}

// The shared host constructor mounts the same refresh recheck the daemon
// does: an account in a provisioned tenant refreshes through NewHostServer.
func TestNewHostServer_RefreshResolvesTheAccountInItsTenant(t *testing.T) {
	node := newEnforcingNode(t)
	const tenantID = "acme"
	provisionTenant(t, node, tenantID)
	_, err := node.UserService().CreateUser(qrdbsdk.ContextWithTenant(context.Background(), tenantID), &qrdbuser.CreateUserRequest{
		Username: "alice",
		Email:    "alice@acme.example",
		Name:     "Alice of acme",
		TenantID: tenantID,
	})
	require.NoError(t, err)
	srv := newEnforcingHostServer(t, node)

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{
		Subject:  "alice",
		TenantID: tenantID,
		Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
	})
	require.NoError(t, err)
	refreshed, err := srv.tokenIssuer.Refresh(context.Background(), pair.RefreshToken)
	require.NoError(t, err, "an account in tenant %s refreshes through the host server", tenantID)
	require.NotEmpty(t, refreshed.AccessToken)
}

// TestNewHostServer_PasskeyAccessTokenNamesTheAccount covers Codex P1 (3):
// a passkey login mints an access token whose subject is the account's
// base64 WebAuthn handle (sub_kind=user_handle). Bearer authentication must
// bind that handle back to the account (UserID, Username, Subject =
// UserSubject), or the RBAC layer finds no account behind the identity and
// refuses an account holding keys:read.
func TestNewHostServer_PasskeyAccessTokenNamesTheAccount(t *testing.T) {
	// As apimodule.RegisterRoleGrants does: a role may hold only a
	// registered permission, and the authorizer resolves its scope first.
	qrdbsdk.RegisterPermissions(qrdbsdk.Permission("keys:read"))
	qrdbsdk.RegisterPermissionScope(qrdbsdk.PermissionScopeSelf, qrdbsdk.Permission("keys:read"))
	probe := &keysProbeModule{}
	node, get := newEnforcingRESTNode(t, probe)
	srv := newEnforcingHostServer(t, node)
	probe.srv.Store(srv)

	ctx := context.Background()
	reader, err := node.Services().Role.CreateRole(ctx, &qrdbsdk.CreateRoleRequest{
		Name:        "keys-reader",
		Permissions: []qrdbsdk.Permission{qrdbsdk.Permission("keys:read")},
	})
	require.NoError(t, err)

	newAccount := func(name string, roleIDs ...string) (*qrdbuser.User, string) {
		u, err := node.UserService().CreateUser(ctx, &qrdbuser.CreateUserRequest{
			Username: name,
			Email:    name + "@example.com",
			Name:     name,
			RoleIDs:  roleIDs,
		})
		require.NoError(t, err)
		var raw [8]byte
		binary.BigEndian.PutUint64(raw[:], u.ID)
		pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{
			Subject:  base64.RawURLEncoding.EncodeToString(raw[:]),
			TenantID: DefaultWebAuthnTenant,
			Metadata: map[string]string{
				auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
				"username":                  name,
			},
		})
		require.NoError(t, err)
		return u, pair.AccessToken
	}
	alice, aliceToken := newAccount("alice", reader.ID)
	_, bobToken := newAccount("bob")

	// The token decodes to the account the handle encodes.
	jwtAuth, err := auth.NewJWTAuthenticator(&auth.JWTConfig{
		PublicKey:  srv.tokenIssuer.PublicKey(),
		Issuer:     srv.tokenIssuer.IssuerName(),
		Audience:   srv.tokenIssuer.Audience(),
		HeaderName: "Authorization",
	})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/keys", nil)
	req.Header.Set("Authorization", "Bearer "+aliceToken)
	id, err := jwtAuth.AuthenticateHTTP(req)
	require.NoError(t, err)
	require.Equal(t, alice.ID, id.UserID, "the identity must name the account the handle encodes")
	require.Equal(t, "alice", id.Username)
	require.Equal(t, qrdbauth.UserSubject(alice.ID), id.Subject)

	// Through the unified server: JWT via the module fallback, go-qrdb
	// account enrichment, and the authorizer. The granted account is served,
	// the ungranted one is denied.
	require.Equal(t, http.StatusOK, get(aliceToken), "an account holding keys:read must be served")
	require.Equal(t, http.StatusForbidden, get(bobToken), "an account without keys:read must be denied")
}

// keysProbeModule mounts GET /api/v1/keys under keys:read on the unified
// server and authenticates through the host server's own fallback, as
// apimodule.Module does (apimodule imports this package, so it cannot be
// used here).
type keysProbeModule struct {
	qrdbserver.BaseModule
	srv atomic.Pointer[Server]
}

func (*keysProbeModule) Name() string { return "xkms-keys-probe" }

func (p *keysProbeModule) RegisterHTTP(r *qrdbserver.ModuleHTTPRegistrar) {
	r.Handle(http.MethodGet, "/api/v1/keys", qrdbsdk.Permission("keys:read"),
		func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
}

func (p *keysProbeModule) AuthenticateHTTP(r *http.Request) (*qrdbsdk.Identity, error) {
	srv := p.srv.Load()
	if srv == nil {
		return nil, errors.New("host server not built yet")
	}
	return srv.AuthenticateHTTP(r)
}

// newEnforcingRESTNode is newEnforcingNode serving REST over TLS with mod
// mounted; get sends GET /api/v1/keys with a bearer and returns the status.
func newEnforcingRESTNode(t *testing.T, mod qrdbserver.ServiceModule) (*qrdbnode.Node, func(bearer string) int) {
	t.Helper()
	certDir := t.TempDir()
	ca, err := qrdbdharness.NewCA(certDir)
	require.NoError(t, err)
	serverKP, err := ca.Issue(certDir, qrdbdharness.WithSubject("node", ""), qrdbdharness.WithServerAuth())
	require.NoError(t, err)
	serverCert, err := serverKP.TLSCertificate()
	require.NoError(t, err)
	ports, err := qrdbdharness.ReserveTCPPorts(1)
	require.NoError(t, err)

	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = true
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	cfg.Server.Host = "127.0.0.1"
	cfg.Server.AdminPort = ports[0]

	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, []qrdbserver.ServerOption{
		qrdbserver.WithServerTLS(&tls.Config{
			Certificates: []tls.Certificate{serverCert},
			MinVersion:   tls.VersionTLS13,
		}),
		qrdbserver.WithModule(mod),
	}, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		RootCAs:    ca.Pool,
		MinVersion: tls.VersionTLS13,
	}}}
	get := func(bearer string) int {
		req, err := http.NewRequest(http.MethodGet, "https://"+node.Server().RESTAddr()+"/api/v1/keys", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+bearer)
		resp, err := client.Do(req)
		require.NoError(t, err)
		_ = resp.Body.Close()
		return resp.StatusCode
	}
	return node, get
}
