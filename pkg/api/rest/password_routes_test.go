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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// allowAllRBACClient grants every permission.
type allowAllRBACClient struct{}

func (allowAllRBACClient) Authorize(context.Context, *qrdbtransport.Identity, string, string) error {
	return nil
}

func (allowAllRBACClient) ListPermissions(context.Context, *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, nil
}

// newPasswordRouteServer is the real REST server with every password route
// mounted, a permissive RBAC client and an anonymous caller, who is served
// from the unscoped system store.
func newPasswordRouteServer(t *testing.T) *Server {
	t.Helper()
	server := newGatedRouteServer(t, allowAllRBACClient{}, auth.NewNoOpAuthenticator(), &mockTCGCAServicer{}, "")
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetPasswordStore(newTestPasswordStore(t))
	return server
}

// TestPasswordRoutes_EveryEntryNameIsFetchable proves the entries namespace
// holds entries only: an entry may be named after any former vault or
// session verb and is still fetched, through the real route table, by its
// name. The vault and its session live under /api/v1/password-vault.
func TestPasswordRoutes_EveryEntryNameIsFetchable(t *testing.T) {
	server := newPasswordRouteServer(t)

	for _, name := range []string{"vault", "status", "unlock", "lock", "generate", "access-mode", "session"} {
		t.Run(name, func(t *testing.T) {
			body := `{"name":"` + name + `","password":"s3cret-` + name + `"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/passwords/", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			server.server.Handler.ServeHTTP(w, req)
			require.Equal(t, http.StatusCreated, w.Code, w.Body.String())

			w = serveRoute(server, http.MethodGet, "/api/v1/passwords/"+name)
			require.Equal(t, http.StatusOK, w.Code, w.Body.String())
			var got map[string]any
			require.NoError(t, json.Unmarshal(w.Body.Bytes(), &got))
			assert.Equal(t, name, got["name"])
			assert.Equal(t, "s3cret-"+name, got["password"])
		})
	}
}

// TestPasswordRoutes_VaultLivesOutsideTheEntries proves the vault and session
// verbs are served from /api/v1/password-vault, and that their former paths
// under /api/v1/passwords no longer reach them.
func TestPasswordRoutes_VaultLivesOutsideTheEntries(t *testing.T) {
	server := newPasswordRouteServer(t)

	w := serveRoute(server, http.MethodGet, "/api/v1/password-vault/session")
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	var status map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &status))
	assert.Contains(t, status, "is_locked")

	// The anonymous caller has no personal vault: the vault verbs answer
	// not supported, which proves the route reached the vault handler.
	w = serveRoute(server, http.MethodGet, "/api/v1/password-vault")
	assert.Equal(t, http.StatusNotImplemented, w.Code, w.Body.String())

	for _, old := range []string{"/api/v1/passwords/vault/factors", "/api/v1/passwords/vault/recover", "/api/v1/passwords/unlock", "/api/v1/passwords/lock"} {
		w = serveRoute(server, http.MethodPost, old)
		assert.Contains(t, []int{http.StatusNotFound, http.StatusMethodNotAllowed}, w.Code, old)
	}
}
