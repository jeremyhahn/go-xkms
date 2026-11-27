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
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"
	"github.com/jeremyhahn/go-qrdb/sdk/go/testutil/qrdbdharness"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	webauthnhttp "github.com/jeremyhahn/go-xkms/pkg/webauthn/http"
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
		ServiceCallContext: node.ServiceContext,
		NodeUsers:          node,
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

// TestNewHostServer_AnonymousRefreshOverEnforcingNode pins that POST
// /api/v1/auth/refresh, which arrives anonymous, re-checks the account on
// the same binder the refresh store runs on: over an enforcing embedded node
// a valid refresh token minted by Mint is exchanged for a new pair, and a
// disabled account's refresh is still refused (go-xkms#1297).
func TestNewHostServer_AnonymousRefreshOverEnforcingNode(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)
	ctx := context.Background()

	mint := func(name string) (uint64, string) {
		u, err := node.UserService().CreateUser(ctx, &qrdbuser.CreateUserRequest{
			Username: name,
			Email:    name + "@example.com",
			Name:     name,
		})
		require.NoError(t, err)
		pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{
			Subject:  base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, u.ID)),
			TenantID: DefaultWebAuthnTenant,
			Metadata: map[string]string{
				auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
				"username":                  name,
			},
		})
		require.NoError(t, err)
		return u.ID, pair.RefreshToken
	}
	refresh := func(refreshToken string) *httptest.ResponseRecorder {
		body, err := json.Marshal(map[string]string{"refresh_token": refreshToken})
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		srv.handleAuthRefresh(rec, req)
		return rec
	}

	_, aliceRefresh := mint("alice")
	rec := refresh(aliceRefresh)
	require.Equal(t, http.StatusOK, rec.Code, "a valid anonymous refresh must succeed: %s", rec.Body.String())
	var pair struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pair))
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	bobID, bobRefresh := mint("bob")
	require.NoError(t, node.UserService().DisableUser(ctx, bobID))
	rec = refresh(bobRefresh)
	require.Equal(t, http.StatusUnauthorized, rec.Code, "a disabled account's refresh must be refused")
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
	require.Equal(t, base64.RawURLEncoding.EncodeToString(binary.BigEndian.AppendUint64(nil, alice.ID)), id.Subject,
		"the subject stays the handle every persisted principal reference names")

	// Through the unified server: JWT via the module fallback, go-qrdb
	// account enrichment, and the authorizer. The granted account is served,
	// the ungranted one is denied.
	require.Equal(t, http.StatusOK, get(aliceToken), "an account holding keys:read must be served")
	require.Equal(t, http.StatusForbidden, get(bobToken), "an account without keys:read must be denied")
}

// TestNewHostServer_AddPasskeyBeginOverEnforcingNode proves refusing
// anonymous registration leaves the authenticated add-a-passkey flow
// working over an enforcing node: an account's own session begins a
// ceremony for that account's handle.
func TestNewHostServer_AddPasskeyBeginOverEnforcingNode(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	ctx := context.Background()
	u, err := node.UserService().CreateUser(ctx, &qrdbuser.CreateUserRequest{
		Username: "carol@example.com",
		Email:    "carol@example.com",
		Name:     "Carol",
	})
	require.NoError(t, err)
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], u.ID)
	handle := base64.RawURLEncoding.EncodeToString(raw[:])
	pair, err := srv.tokenIssuer.Mint(ctx, &auth.Identity{
		Subject:  handle,
		TenantID: DefaultWebAuthnTenant,
		Metadata: map[string]string{
			auth.SubjectKindMetadataKey: auth.SubjectKindUserHandle,
			"username":                  "carol@example.com",
			"email":                     "carol@example.com",
		},
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/credentials/begin", nil)
	req.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code, "body: %s", w.Body.String())
	require.NotEmpty(t, w.Header().Get(webauthnhttp.HeaderSessionID))
	var options struct {
		PublicKey struct {
			User struct {
				ID string `json:"id"`
			} `json:"user"`
		} `json:"publicKey"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &options))
	require.Equal(t, handle, options.PublicKey.User.ID, "the ceremony enrols the session's own account")
}

// TestNewHostServer_PublicRegistrationBeginRefusedOverEnforcingNode is the
// Codex P1 on BuildWebAuthnService: with the node user adapter the user
// store's Create ran on the node's routing user service, which checks no
// users:create, so anonymous registration/begin persisted an active account
// before any credential was verified. The service principal holds no
// users:create (CA ruling 602), so even with public registration allowed the
// begin is refused and no account exists afterwards.
func TestNewHostServer_PublicRegistrationBeginRefusedOverEnforcingNode(t *testing.T) {
	node := newEnforcingNode(t)
	srv := newEnforcingHostServer(t, node)

	const email = "anonymous-signup@example.com"
	body, err := json.Marshal(map[string]string{"email": email, "display_name": "Anonymous"})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/webauthn/registration/begin", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	require.Equal(t, http.StatusForbidden, w.Code, "body: %s", w.Body.String())
	require.Empty(t, w.Header().Get(webauthnhttp.HeaderSessionID), "a refused begin opens no ceremony")
	// The browser fixture (passkeyAccount.ts expectAnonymousSignUpRefused)
	// relies on this code on the enforcing node as on the default tier.
	var refused map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &refused))
	require.Equal(t, webauthnhttp.ErrorCodeRegistrationRefused, refused["error"], "body: %s", w.Body.String())

	u, err := auth.NewNodeUserClient(node).GetUserByEmail(context.Background(), DefaultWebAuthnTenant, email)
	require.Error(t, err, "the refused begin must leave no account, found %+v", u)
	var notFound *qrdbsdk.UserNotFoundError
	require.True(t, errors.As(err, &notFound), "lookup after the refusal: %v", err)
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
