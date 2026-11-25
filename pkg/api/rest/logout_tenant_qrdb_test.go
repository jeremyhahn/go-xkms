package rest

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

// refreshFamilyAndJTI reads the fam and jti claims of a refresh token
// without verifying it: the test only needs the store key the issuer
// recorded at mint time.
func refreshFamilyAndJTI(t *testing.T, refreshToken string) (string, string) {
	t.Helper()
	parts := strings.Split(refreshToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims struct {
		Family string `json:"fam"`
		JTI    string `json:"jti"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.NotEmpty(t, claims.Family)
	require.NotEmpty(t, claims.JTI)
	return claims.Family, claims.JTI
}

// A logout from a non-system tenant reaches the refresh store with that
// tenant bound to its request context. On the xkmsd wiring over the embedded
// node that enforces authentication, the revoke must run in the store's
// system-tenant scope: logout succeeds and the family is revoked
// (go-xkms#2287, Tenant Agent ruling 971).
func TestAuthLogout_FromNonSystemTenant_RevokesOnTheEmbeddedNode(t *testing.T) {
	node := barriertest.NewPrincipalNode(t)
	issuer, err := BuildTokenIssuer(context.Background(), TokenIssuerParams{
		Backend:        newMockKeyStore(),
		BackendName:    "test",
		QRDBClient:     node.Client(),
		CallContext:    node.ServiceContext,
	})
	require.NoError(t, err)
	server := newAuthTestServer(t, func(cfg *Config) { cfg.TokenIssuer = issuer })

	pair, err := issuer.Mint(context.Background(), &auth.Identity{Subject: "alice", TenantID: "t1"})
	require.NoError(t, err)

	tenantCtx := qrdbsdk.ContextWithTenant(context.Background(), "t1")
	post := func(path, refresh string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(authRefreshRequest{RefreshToken: refresh})
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)).WithContext(tenantCtx)
		return doAuthRequest(t, server, req)
	}

	// Read the minted record straight from the node's refresh store, so the
	// assertion depends on logout's Revoke and not on the refresh-time user
	// re-check (which refuses this unregistered subject either way).
	store, err := token.NewQRDBRefreshStore(node.Client().KV(), token.WithCallContext(node.ServiceContext))
	require.NoError(t, err)
	family, jti := refreshFamilyAndJTI(t, pair.RefreshToken)
	rec, err := store.Get(context.Background(), family, jti)
	require.NoError(t, err)
	require.NotNil(t, rec, "the minted refresh record must be on the node before logout")

	require.Equal(t, http.StatusNoContent, post("/api/v1/auth/logout", pair.RefreshToken).Code)

	rec, err = store.Get(context.Background(), family, jti)
	require.NoError(t, err)
	assert.Nil(t, rec, "logout must remove the family's refresh record from the node")
	assert.Equal(t, http.StatusUnauthorized, post("/api/v1/auth/refresh", pair.RefreshToken).Code,
		"the logged-out family must be revoked")
}
