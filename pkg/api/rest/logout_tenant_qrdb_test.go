package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
)

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
		ServiceContext: node.ServiceContext,
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

	require.Equal(t, http.StatusNoContent, post("/api/v1/auth/logout", pair.RefreshToken).Code)
	assert.Equal(t, http.StatusUnauthorized, post("/api/v1/auth/refresh", pair.RefreshToken).Code,
		"the logged-out family must be revoked")
}
