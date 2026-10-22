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

package admin

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
)

// authzSeams are the authorization gates this package exposes: the route
// constructors of routes.go, which bind every ACME admin route to the one
// permission both hosts enforce — the PermissionGate on a standalone host,
// qrdb's chain on the unified server.
//
//   - adminRoute(method, path, resource, action, serve)
//   - tenantRoute(method, path, resource, action, serve)
//   - tenantCrossRoute(method, path, permission, serve)
//   - tenantReachRoute(method, path, resource, action, cross, serve)
//
// The tenant-reach routes are pinned by their cross-scope grant; the
// self-scoped pair they take on the caller's own tenant is pinned by the
// "own tenant" cases of tenantRouteCases in routes_authz_test.go.
//
// The last argument is always the handler method expression being
// registered (e.g. (*Handlers).ListCertificates), which is the stable,
// human-readable identity grpc's own golden keys by, so it is each seam's
// label argument; keying by enclosing function would collapse every route
// into one "adminRoutes#N" series.
var authzSeams = []authzscan.Seam{
	{Method: "adminRoute", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{4}},
	{Method: "tenantRoute", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{4}},
	{Method: "tenantCrossRoute", Args: 4, ResourceArg: 2, Permission: true, Bare: true, LabelArgs: []int{3}},
	{Method: "tenantReachRoute", Args: 6, ResourceArg: 4, Permission: true, Bare: true, LabelArgs: []int{5}},
}

// goldenAdminPermissions is the complete, literal resource:action pair every
// gated ACME admin route requires, keyed by the handler method it registers.
//
// The strings are spelled out here rather than built from the
// auth.Resource*/auth.Action* constants on purpose: this table is the wire
// contract go-qrdb decides against, so it must fail if a constant is
// retyped, repointed, or swapped for a different one. It is the ACME admin
// counterpart of pkg/api/grpc's goldenRPCPermissions.
var goldenAdminPermissions = map[string]string{
	"CreateTenantEAB":                  "acme_eab:create",
	"CreateTenantIntermediateCA":       "ca:create",
	"CreateTenantRole":                 "roles:create",
	"CreateTenantRootCA":               "ca:create",
	"CreateTenantUser":                 "users:create",
	"DeleteTenantEAB":                  "acme_eab:delete",
	"DeleteTenantRole":                 "roles:delete",
	"DeleteTenantUser":                 "users:delete",
	"DisableAccount":                   "acme_accounts:disable",
	"GetAccount":                       "acme_accounts:read",
	"GetAlgorithms":                    "admin:capabilities",
	"GetCertificate":                   "certs:read",
	"GetOrder":                         "acme_orders:read",
	"GetStats":                         "admin:status",
	"GetStatus":                        "admin:status",
	"GetTenantCAStatus":                "ca:read",
	"GetTenantEAB":                     "acme_eab:read",
	"GetTenantIntermediateCA":          "ca:read",
	"GetTenantRole":                    "roles:read",
	"GetTenantUser":                    "users:read",
	"ListAccounts":                     "acme_accounts:list",
	"ListAuditLogs":                    "audit:read",
	"ListCertificates":                 "certs:list",
	"ListExpiringCertificates":         "certs:list",
	"ListOrders":                       "acme_orders:list",
	"ListTenantEABs":                   "acme_eab:list",
	"ListTenantIntermediateCAs":        "ca:list",
	"ListTenantRoles":                  "roles:list",
	"ListTenantUsers":                  "users:list",
	"RevokeCertificate":                "certs:revoke",
	"SetTenantDefaultIntermediateCA":   "ca:update",
	"UpdateTenant":                     "tenants:update:cross",
	"UpdateTenantIntermediateCAStatus": "ca:update",
	"UpdateTenantRole":                 "roles:update",
	"UpdateTenantStatus":               "tenants:update:cross",
	"UpdateTenantUser":                 "users:update",
}

// TestAdminPermissions_MatchWireContract pins the resource:action pair of
// EVERY gated ACME admin route against the literal wire contract. The scan
// reads this package's own source, so a route that loses its gate, gains
// one, or has its resource/action swapped fails here. The check runs in
// both directions and asserts the count, so neither a changed pair nor an
// added or dropped gate can slip through.
func TestAdminPermissions_MatchWireContract(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "scanning this package for authorization gates must succeed")

	require.Len(t, sites, len(goldenAdminPermissions),
		"a gate.Wrap route was added to or removed from this package without updating the wire contract")

	found := make(map[string]string, len(sites))
	for _, site := range sites {
		_, dup := found[site.Key]
		require.False(t, dup, "duplicate gate key %q at %s", site.Key, site.Pos)
		found[site.Key] = site.Pair()
	}

	for handler, want := range goldenAdminPermissions {
		got, ok := found[handler]
		require.True(t, ok, "handler %q lost its authorization gate", handler)
		assert.Equal(t, want, got, "handler %q", handler)
	}

	for handler, got := range found {
		want, ok := goldenAdminPermissions[handler]
		require.True(t, ok, "handler %q gained an authorization gate without a wire-contract entry", handler)
		assert.Equal(t, want, got, "handler %q", handler)
	}
}

// TestAdminPermissions_NoRawLiterals proves no gate.Wrap call in this package
// spells its resource or action as a string literal. authzscan.Scan returns
// a *authzscan.RawLiteralError the moment it sees one, so a successful scan
// is the proof.
func TestAdminPermissions_NoRawLiterals(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "every gate.Wrap call must name a pkg/auth constant, never a string literal")
	require.NotEmpty(t, sites)
}
