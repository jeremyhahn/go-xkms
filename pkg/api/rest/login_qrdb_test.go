package rest

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newLoginQRDBNode starts an embedded go-qrdb node that enforces
// authentication and carries xkms's service principal, as xkmsd runs one.
func newLoginQRDBNode(t *testing.T) *qrdbnode.Node {
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

// TestPIVLogin_QRDB_AnonymousContext is go-xkms#2287: on a qrdb-backed
// host the PIV login route is public, so Mint runs under a context with no
// identity. The refresh store must write as the node's service principal;
// before the fix the login answered 500 with "refresh store put failed:
// qrdb/auth: unauthenticated".
//
// On this node the certificate lookup (auth.NewQRDBUserStore under the
// anonymous request context) is refused first, so the login answers 401;
// the service principal's grant holds no users read either (see
// docs/plans/2287.md, Blocked). The test stays red until that is decided.
func TestPIVLogin_QRDB_AnonymousContext(t *testing.T) {
	node := newLoginQRDBNode(t)
	client := node.Client()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	cert := generateTestCertificate(t, key)

	// Enrol the admin and bind the certificate as the operator would, through
	// the node's user service (the enrolment seam, not the request path).
	svcCtx := context.Background()
	user, err := node.UserService().CreateUser(svcCtx, &qrdbuser.CreateUserRequest{
		Username:             "alice",
		Name:                 "Alice Admin",
		WithoutEmailLoginKey: true,
	})
	require.NoError(t, err)
	_, err = node.UserService().AddCertBinding(svcCtx, user.ID, qrdbsdk.ComputeSPKIThumbprint(cert), 0)
	require.NoError(t, err)

	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:     newMockKeyStore(),
		BackendName: "test",
		QRDBClient:  client,
	})
	require.NoError(t, err)
	authenticator, err := BuildAuthenticator(AuthenticatorParams{TokenIssuer: issuer, QRDBClient: client})
	require.NoError(t, err)

	server, err := NewServer(&Config{
		Authenticator: authenticator,
		Backends:      map[string]xkms.Backend{"test": newMockKeyStore()},
		Logger:        testLogger(),
		TokenIssuer:   issuer,
		PIVLogin:      &PIVLoginOptions{Enabled: true, AllowUnattested: true},
		AuthUserStore: auth.NewQRDBUserStore(client.Users()),
	})
	require.NoError(t, err)

	// (1) login: 200 with a token pair.
	w := doAuthRequest(t, server, pivRequest(cert))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var pair authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &pair))
	require.NotEmpty(t, pair.AccessToken)
	require.NotEmpty(t, pair.RefreshToken)

	// (2) the access token authenticates /auth/me.
	me := httptest.NewRequest(http.MethodGet, "/api/v1/auth/me", nil)
	me.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	w = doAuthRequest(t, server, me)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())

	// (3) refresh rotates the refresh token.
	body, err := json.Marshal(map[string]string{"refresh_token": pair.RefreshToken})
	require.NoError(t, err)
	refresh := httptest.NewRequest(http.MethodPost, "/api/v1/auth/refresh", bytes.NewReader(body))
	refresh.Header.Set("Content-Type", "application/json")
	w = doAuthRequest(t, server, refresh)
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var rotated authTokenResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &rotated))
	require.NotEmpty(t, rotated.RefreshToken)
	assert.NotEqual(t, pair.RefreshToken, rotated.RefreshToken, "refresh must rotate the refresh token")
}
