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

package main

// The ACME admin plane's /admin/barrier/* routes as xkmsd composes them
// (go-xkms#1244): finalizeAdminModule hands them the server's XKMSService, so
// the service's platform-scope check refuses a tenant-scoped caller on every
// route, and the platform administrator still operates the system barrier.

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// adminBarrierRoute is one /admin/barrier/* route with a body that passes the
// handler's own validation.
type adminBarrierRoute struct {
	method string
	path   string
	body   any
}

// adminBarrierRoutes is every route pkg/acme/admin's BarrierHandlers
// registers.
var adminBarrierRoutes = map[string]adminBarrierRoute{
	"status":              {http.MethodGet, "/admin/barrier/status", nil},
	"initialize":          {http.MethodPost, "/admin/barrier/initialize", map[string]any{"secret": "attacker-secret"}},
	"seal":                {http.MethodPost, "/admin/barrier/seal", nil},
	"unseal":              {http.MethodPost, "/admin/barrier/unseal", map[string]any{"secret": "attacker-secret"}},
	"shamir initialize":   {http.MethodPost, "/admin/barrier/shamir/initialize", map[string]any{"secret": "attacker-secret", "threshold": 2, "total_shares": 3}},
	"shamir unseal share": {http.MethodPost, "/admin/barrier/shamir/unseal-share", map[string]any{"share": "s"}},
	"rekey":               {http.MethodPost, "/admin/barrier/rekey", map[string]any{"threshold": 2, "total": 3}},
	"recovery generate":   {http.MethodPost, "/admin/barrier/recovery/generate", map[string]any{"threshold": 2, "total": 3}},
	"recovery recover":    {http.MethodPost, "/admin/barrier/recovery/recover", map[string]any{"keys": []string{"a", "b"}}},
	"recovery status":     {http.MethodGet, "/admin/barrier/recovery/status", nil},
	"root token":          {http.MethodPost, "/admin/barrier/root-token", map[string]any{"shares": []string{"a", "b"}}},
}

// TestAdminPlane_TenantCallerCannotOperateSystemBarrier: tenant-a's Admin/SO
// is refused on every barrier route exactly as a caller lacking the grant,
// and the node's system barrier keeps its state.
func TestAdminPlane_TenantCallerCannotOperateSystemBarrier(t *testing.T) {
	f := newTenantBindingFixture(t)
	barrier := f.srv.Barrier()
	require.NotNil(t, barrier, "fixture: the node barrier must be engaged")
	sealed := barrier.IsSealed()

	for name, route := range adminBarrierRoutes {
		t.Run(name, func(t *testing.T) {
			rec := f.do(t, f.callerA, route.method, route.path, route.body)
			assert.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Equal(t, "Access denied: insufficient permissions", problemDetail(t, rec))
			assert.Equal(t, sealed, barrier.IsSealed(), "a tenant caller changed the system barrier's seal state")
		})
	}
}

// TestAdminPlane_PlatformAdminOperatesSystemBarrier: the first-boot platform
// administrator reaches the system barrier through the same routes.
func TestAdminPlane_PlatformAdminOperatesSystemBarrier(t *testing.T) {
	f := newTenantBindingFixture(t)

	rec := f.do(t, f.platform, http.MethodGet, "/admin/barrier/status", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"enabled":true`)
	assert.Contains(t, rec.Body.String(), `"sealed":false`)

	rec = f.do(t, f.platform, http.MethodGet, "/admin/barrier/recovery/status", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// A seal/unseal round trip on the node's system barrier. The fixture's
	// barrier uses the "none" strategy, whose unseal takes no key material,
	// but the handler still requires a non-empty secret.
	rec = f.do(t, f.platform, http.MethodPost, "/admin/barrier/seal", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.True(t, f.srv.Barrier().IsSealed())

	rec = f.do(t, f.platform, http.MethodGet, "/admin/barrier/status", nil)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), `"sealed":true`)

	rec = f.do(t, f.platform, http.MethodPost, "/admin/barrier/unseal", map[string]any{"secret": "none-strategy"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.False(t, f.srv.Barrier().IsSealed())
}
