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

// server_bootstrap_authz_test.go proves GET /api/v1/bootstrap/keys is behind
// the bootstrap:read RequirePermission decorator end to end, through the real
// chi router (go-xkms#632) — the route-table counterpart of
// server_barrier_authz_test.go for the barrier routes.
package rest

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newBootstrapAuthzTestService builds a real *xkms.XKMSService so the route's
// Enabled guard (hasBootstrapHandlers) mounts the handler, mirroring
// pkg/api/grpc's newBootstrapTestService for the REST server construction
// path.
func newBootstrapAuthzTestService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	}))

	svc, err := xkms.Get()
	require.NoError(t, err)
	return svc
}

// TestBootstrapKeysRoute_RBACDenied proves a caller whose bootstrap:read
// check is refused is denied by the middleware before the handler runs.
func TestBootstrapKeysRoute_RBACDenied(t *testing.T) {
	svc := newBootstrapAuthzTestService(t)

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		XKMSService:    svc,
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(denyingRBACClient{}),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/keys", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}

// bootstrapRecordingRBACClient records the resource:action pair it was asked
// to authorize and allows exactly one configured pair.
type bootstrapRecordingRBACClient struct {
	allowResource string
	allowAction   string

	gotResource string
	gotAction   string
}

func (c *bootstrapRecordingRBACClient) Authorize(_ context.Context, _ *qrdbtransport.Identity, resource, action string) error {
	c.gotResource = resource
	c.gotAction = action
	if resource == c.allowResource && action == c.allowAction {
		return nil
	}
	return errors.New("permission denied")
}

func (c *bootstrapRecordingRBACClient) ListPermissions(_ context.Context, _ *qrdbtransport.Identity) ([]qrdbtransport.PermissionInfo, error) {
	return nil, errors.New("not implemented")
}

// TestBootstrapKeysRoute_RequiresBootstrapRead proves the route demands
// exactly bootstrap:read — the same pair pkg/api/mcp's rpcMethods and
// pkg/api/grpc's proto option declare for the equivalent call — and that a
// caller holding that grant passes the gate.
func TestBootstrapKeysRoute_RequiresBootstrapRead(t *testing.T) {
	svc := newBootstrapAuthzTestService(t)
	rbac := &bootstrapRecordingRBACClient{allowResource: "bootstrap", allowAction: "read"}

	server, err := NewServer(&Config{
		Authenticator:  auth.NewNoOpAuthenticator(),
		Backends:       map[string]xkms.Backend{"test": newMockKeyStore()},
		XKMSService:    svc,
		EnableRBAC:     true,
		RBACAuthorizer: auth.NewAuthorizer(rbac),
	})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/bootstrap/keys", nil)
	w := httptest.NewRecorder()
	server.server.Handler.ServeHTTP(w, req)

	assert.Equal(t, "bootstrap", rbac.gotResource, "decorator asked for wrong resource")
	assert.Equal(t, "read", rbac.gotAction, "decorator asked for wrong action")

	// The right grant passes the gate; the listener isn't started in this
	// test so the handler itself answers 503, never the middleware's 401/403.
	assert.NotEqual(t, http.StatusUnauthorized, w.Code)
	assert.NotEqual(t, http.StatusForbidden, w.Code)
	assert.Equal(t, http.StatusServiceUnavailable, w.Code)
}
