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

package rest

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/internal/authzscan"
)

// authzSeams are the authorization gates this package's route table
// (routes.go) exposes. Every RouteAuthPermission route is registered through
// one of five local closures scoped inside Routes(): perm, permBulk, and
// permIf for the /api/v1 mount, user for /api/v1/users, and ssh for
// /xkms/v1/ssh. Each closure takes the literal HTTP method and path pattern
// as its first two arguments, so those two are also this seam's label
// arguments: the golden table below is keyed by the full route
// ("METHOD /mounted/path"), not by the enclosing Routes function, because
// every route in the table is registered from that single function.
var authzSeams = []authzscan.Seam{
	{Method: "perm", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "permBulk", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "permIf", Args: 6, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1"},
	{Method: "user", Args: 5, ResourceArg: 2, ActionArg: 3, Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/api/v1/users"},
	{Method: "ssh", Args: 4, ResourceArg: -1, ActionArg: 2, FixedResource: "ResourceSSH", Bare: true, LabelArgs: []int{0, 1}, LabelPrefix: "/xkms/v1/ssh"},
}

// goldenRESTPermissions is the complete, literal resource:action pair every
// RouteAuthPermission REST route requires, keyed by "METHOD path". Two
// entries share the "GET /api/v1/ca/bundle" route (disambiguated #0/#1 by
// authzscan because both a hasCA and noCA variant register it), and both
// require the identical certs:read pair by construction: the unified-server
// module registers a multi-variant route once under its first variant's
// permission (routes.go's own comment on the CA block).
//
// The strings are spelled out here rather than built from the
// auth.Resource*/auth.Action* constants on purpose: this table is the wire
// contract go-qrdb decides against, so it must fail if a constant is
// retyped, repointed, or swapped for a different one. It is the REST
// counterpart of pkg/api/grpc's goldenRPCPermissions and
// pkg/api/mcp's goldenMethodPermissions, and pins the same vocabulary.
var goldenRESTPermissions = map[string]string{
	"DELETE /api/v1/barrier/recovery/keys":                       "seal:generate_recovery",
	"DELETE /api/v1/certs/{id}":                                  "certs:revoke",
	"DELETE /api/v1/custodian/groups/{id}":                       "ceremony:revoke_custodian",
	"DELETE /api/v1/custodian/groups/{id}/members/{userID}":      "ceremony:revoke_custodian",
	"DELETE /api/v1/factors/{factorID}":                          "users:update",
	"DELETE /api/v1/frost/keys/{id}":                             "keys:delete",
	"DELETE /api/v1/keys/{id}":                                   "keys:delete",
	"DELETE /api/v1/passwords/{id}":                              "passwords:delete",
	"DELETE /api/v1/piv/slots/{slot}/certificate":                "piv:delete",
	"DELETE /api/v1/platform/secrets/{name}":                     "keys:delete",
	"DELETE /api/v1/shares/{serverURL}/{groupID}/{shareIndex}":   "barrier:unseal-share",
	"DELETE /api/v1/tenants/{tenantID}":                          "tenants:delete",
	"DELETE /api/v1/users/{username}":                            "users:delete",
	"DELETE /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}": "ssh:delete",
	"DELETE /xkms/v1/ssh/keys/{scope}/{owner}/{name}":            "ssh:delete",
	"DELETE /xkms/v1/ssh/known-hosts/{host}":                     "ssh:delete",
	"GET /api/v1/audit/":                                         "audit:read",
	"GET /api/v1/backends":                                       "backends:list",
	"GET /api/v1/backends/{id}":                                  "backends:read",
	"GET /api/v1/barrier/status":                                 "seal:status",
	"GET /api/v1/bootstrap/keys":                                 "bootstrap:read",
	"GET /api/v1/ca/bundle#0":                                    "certs:read",
	"GET /api/v1/ca/bundle#1":                                    "certs:read",
	"GET /api/v1/ca/certificate":                                 "certs:read",
	"GET /api/v1/ca/revoked/{serial}":                            "certs:read",
	"GET /api/v1/certs":                                          "certs:list",
	"GET /api/v1/certs/{id}":                                     "certs:read",
	"GET /api/v1/certs/{id}/chain":                               "certs:read",
	"GET /api/v1/cluster/members":                                "admin:peers",
	"GET /api/v1/cluster/status":                                 "admin:status",
	"GET /api/v1/credentials/strategy":                           "credentials:strategy",
	"GET /api/v1/custodian/groups/":                              "ceremony:status",
	"GET /api/v1/custodian/groups/{id}":                          "ceremony:status",
	"GET /api/v1/factors/":                                       "users:read",
	"GET /api/v1/factors/{factorID}":                             "users:read",
	"GET /api/v1/frost/keys":                                     "keys:list",
	"GET /api/v1/frost/keys/{id}":                                "keys:get",
	"GET /api/v1/keys":                                           "keys:list",
	"GET /api/v1/keys/{id}":                                      "keys:get",
	"GET /api/v1/passwords/":                                     "passwords:read",
	"GET /api/v1/passwords/status":                               "passwords:read",
	"GET /api/v1/passwords/{id}":                                 "passwords:read",
	"GET /api/v1/pin/lockout":                                    "pin:read",
	"GET /api/v1/piv/slots":                                      "piv:read",
	"GET /api/v1/piv/slots/{slot}/certificate":                   "piv:read",
	"GET /api/v1/piv/slots/{slot}/export":                        "piv:read",
	"GET /api/v1/platform/secrets":                               "keys:list",
	"GET /api/v1/platform/secrets/{name}":                        "keys:read",
	"GET /api/v1/platform/status":                                "keys:read",
	"GET /api/v1/seal/capability":                                "keys:get",
	"GET /api/v1/shares/":                                        "ceremony:status",
	"GET /api/v1/shares/status/{groupID}":                        "ceremony:status",
	"GET /api/v1/shares/{serverURL}/{groupID}/{shareIndex}":      "ceremony:status",
	"GET /api/v1/tenants/":                                       "tenants:list",
	"GET /api/v1/tenants/{tenantID}":                             "tenants:read",
	"GET /api/v1/tenants/{tenantID}/barrier/status":              "tenant_barrier:status",
	"GET /api/v1/tls/{id}":                                       "certs:read",
	"GET /api/v1/users/":                                         "users:list",
	"GET /api/v1/users/{username}":                               "users:read",
	"GET /api/v1/users/{username}/credentials":                   "users:read",
	"GET /xkms/v1/ssh/authorized-keys":                           "ssh:read",
	"GET /xkms/v1/ssh/authorized-keys/{scope}/{owner}/{name}":    "ssh:read",
	"GET /xkms/v1/ssh/keys":                                      "ssh:read",
	"GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}":               "ssh:read",
	"GET /xkms/v1/ssh/keys/{scope}/{owner}/{name}/public":        "ssh:read",
	"GET /xkms/v1/ssh/known-hosts":                               "ssh:read",
	"HEAD /api/v1/certs/{id}":                                    "certs:read",
	"PATCH /api/v1/factors/{factorID}":                           "users:update",
	"POST /api/v1/attest":                                        "keys:get",
	"POST /api/v1/barrier/enable-encryption":                     "seal:enable_encryption",
	"POST /api/v1/barrier/initialize":                            "seal:bootstrap",
	"POST /api/v1/barrier/recovery/generate":                     "seal:generate_recovery",
	"POST /api/v1/barrier/recovery/recover":                      "seal:recover_with_keys",
	"POST /api/v1/barrier/recovery/root-token":                   "seal:rotate_root_key",
	"POST /api/v1/barrier/rekey":                                 "seal:rekey",
	"POST /api/v1/barrier/seal":                                  "seal:seal",
	"POST /api/v1/barrier/shamir/initialize":                     "seal:initialize_shamir",
	"POST /api/v1/barrier/shamir/unseal-share":                   "barrier:unseal-share",
	"POST /api/v1/barrier/shamir/unseal-shares":                  "seal:unseal",
	"POST /api/v1/barrier/unseal":                                "seal:unseal",
	"POST /api/v1/ca/crl":                                        "certs:read",
	"POST /api/v1/ca/issue":                                      "certs:generate",
	"POST /api/v1/ca/revoke":                                     "certs:revoke",
	"POST /api/v1/ca/sign-csr":                                   "certs:generate",
	"POST /api/v1/ca/tcg/ak":                                     "certs:generate",
	"POST /api/v1/ca/tcg/ek":                                     "certs:generate",
	"POST /api/v1/ca/tcg/enroll":                                 "certs:generate",
	"POST /api/v1/ca/tcg/sign-csr":                               "certs:generate",
	"POST /api/v1/certs":                                         "certs:generate",
	"POST /api/v1/certs/{id}/chain":                              "certs:generate",
	"POST /api/v1/credentials/submit":                            "credentials:submit",
	"POST /api/v1/custodian/groups/":                             "ceremony:enroll_custodian",
	"POST /api/v1/custodian/groups/{id}/distribute":              "ceremony:claim_share_begin",
	"POST /api/v1/custodian/groups/{id}/members":                 "ceremony:enroll_custodian",
	"POST /api/v1/factors/":                                      "users:update",
	"POST /api/v1/factors/login":                                 "users:read",
	"POST /api/v1/factors/{factorID}/rotate":                     "users:update",
	"POST /api/v1/frost/aggregate":                               "keys:sign",
	"POST /api/v1/frost/keys":                                    "keys:create",
	"POST /api/v1/frost/keys/import":                             "keys:import",
	"POST /api/v1/frost/keys/{id}/nonces":                        "keys:sign",
	"POST /api/v1/frost/keys/{id}/sign":                          "keys:sign",
	"POST /api/v1/frost/verify":                                  "keys:verify",
	"POST /api/v1/init/enroll-external-officer":                  "ceremony:sign_csr",
	"POST /api/v1/init/officer/register":                         "ceremony:sign_csr",
	"POST /api/v1/init/sign-csr":                                 "ceremony:sign_csr",
	"POST /api/v1/keys":                                          "keys:create",
	"POST /api/v1/keys/copy":                                     "keys:create",
	"POST /api/v1/keys/derive-ecdh":                              "keys:derive",
	"POST /api/v1/keys/import":                                   "keys:import",
	"POST /api/v1/keys/import-params":                            "keys:import",
	"POST /api/v1/keys/unwrap":                                   "keys:unwrap",
	"POST /api/v1/keys/unwrap-by-id":                             "keys:unwrap",
	"POST /api/v1/keys/wrap":                                     "keys:wrap",
	"POST /api/v1/keys/wrap-by-id":                               "keys:wrap",
	"POST /api/v1/keys/{id}/decrypt":                             "keys:decrypt",
	"POST /api/v1/keys/{id}/encrypt":                             "keys:encrypt",
	"POST /api/v1/keys/{id}/encrypt-asym":                        "keys:encrypt",
	"POST /api/v1/keys/{id}/export":                              "keys:export",
	"POST /api/v1/keys/{id}/export-material":                     "keys:export",
	"POST /api/v1/keys/{id}/rotate":                              "keys:rotate",
	"GET /api/v1/keys/{id}/versions":                             "keys:list",
	"POST /api/v1/keys/{id}/versions/enable-all":                 "keys:rotate",
	"POST /api/v1/keys/{id}/versions/disable-all":                "keys:rotate",
	"POST /api/v1/keys/{id}/versions/{version}/enable":           "keys:rotate",
	"POST /api/v1/keys/{id}/versions/{version}/disable":          "keys:rotate",
	"POST /api/v1/keys/{id}/versions/{version}/retire":           "keys:delete",
	"POST /api/v1/keys/rotate-all":                               "keys:rotate",
	"POST /api/v1/keys/{id}/sign":                                "keys:sign",
	"POST /api/v1/keys/{id}/verify":                              "keys:verify",
	"POST /api/v1/passwords/":                                    "passwords:write",
	"POST /api/v1/passwords/generate":                            "passwords:generate",
	"POST /api/v1/passwords/lock":                                "passwords:lock",
	"POST /api/v1/passwords/unlock":                              "passwords:unlock",
	"POST /api/v1/pin/lockout/reset":                             "pin:write",
	"POST /api/v1/pin/so/change":                                 "pin:write",
	"POST /api/v1/pin/so/set":                                    "pin:write",
	"POST /api/v1/pin/so/verify":                                 "pin:read",
	"POST /api/v1/pin/user/change":                               "pin:write",
	"POST /api/v1/pin/user/set":                                  "pin:write",
	"POST /api/v1/pin/user/verify":                               "pin:read",
	"POST /api/v1/piv/slots/{slot}/certificate":                  "piv:write",
	"POST /api/v1/piv/slots/{slot}/csr":                          "piv:use",
	"POST /api/v1/piv/slots/{slot}/generate":                     "piv:write",
	"POST /api/v1/piv/slots/{slot}/import":                       "piv:write",
	"POST /api/v1/pkcs11state/compare-and-delete":                "keys:delete",
	"POST /api/v1/pkcs11state/compare-and-swap":                  "keys:update",
	"POST /api/v1/pkcs11state/delete":                            "keys:delete",
	"POST /api/v1/pkcs11state/get":                               "keys:get",
	"POST /api/v1/pkcs11state/list":                              "keys:list",
	"POST /api/v1/pkcs11state/put":                               "keys:create",
	"POST /api/v1/pkcs11state/put-if-absent":                     "keys:create",
	"POST /api/v1/platform/secrets/{name}/reseal":                "keys:write",
	"POST /api/v1/seal":                                          "keys:encrypt",
	"POST /api/v1/shares/submit":                                 "barrier:unseal-share",
	"POST /api/v1/tenants/":                                      "tenants:create",
	"POST /api/v1/tenants/{tenantID}/barrier/init":               "tenant_barrier:init",
	"POST /api/v1/tenants/{tenantID}/barrier/unseal":             "tenant_barrier:unseal",
	"POST /api/v1/unseal":                                        "keys:decrypt",
	"POST /api/v1/users/":                                        "users:create",
	"POST /api/v1/users/{username}/cert-bindings":                "users:update",
	"POST /xkms/v1/ssh/authorized-keys":                          "ssh:write",
	"POST /xkms/v1/ssh/authorized-keys/emit":                     "ssh:read",
	"POST /xkms/v1/ssh/authorized-keys/verify":                   "ssh:read",
	"POST /xkms/v1/ssh/keys":                                     "ssh:write",
	"POST /xkms/v1/ssh/keys/import":                              "ssh:write",
	"POST /xkms/v1/ssh/keys/{scope}/{owner}/{name}/sign":         "ssh:write",
	"POST /xkms/v1/ssh/known-hosts":                              "ssh:write",
	"POST /xkms/v1/ssh/known-hosts/{host}/verify":                "ssh:read",
	"PUT /api/v1/passwords/{id}":                                 "passwords:write",
	"PUT /api/v1/platform/secrets/{name}":                        "keys:write",
	"PUT /api/v1/tenants/{tenantID}/entitlements":                "tenants:set_entitlements",
	"PUT /api/v1/tenants/{tenantID}/quotas":                      "tenants:set_quotas",
	"POST /api/v1/tpm/policies":                                  "tpm_policy:create",
	"GET /api/v1/tpm/policies":                                   "tpm_policy:list",
	"GET /api/v1/tpm/policies/{name}":                            "tpm_policy:get",
	"DELETE /api/v1/tpm/policies/{name}":                         "tpm_policy:delete",
	"POST /api/v1/tpm/policies/{name}/update":                    "tpm_policy:update",
	"POST /api/v1/tpm/policies/{name}/revoke":                    "tpm_policy:revoke",
	"POST /api/v1/tpm/policies/{name}/verify":                    "tpm_policy:verify",
	"GET /api/v1/tpm/policies/{name}/objects":                    "tpm_policy:get",
	"POST /api/v1/tpm/policies/{name}/auto-unseal":               "tpm_policy:update",
	"POST /api/v1/tpm/authority/rotate":                          "tpm_policy:rotate",
	"GET /api/v1/keys/{id}/tpm-policy":                           "tpm_policy:get",
	"GET /api/v1/tenants/{tenantID}/tpm":                         "tenants:read",
	"PUT /api/v1/tenants/{tenantID}/tpm":                         "tenants:set_tpm_mode",
	"GET /api/v1/tenants/{tenantID}/tpm/vtpm":                    "tenants:read",
	"POST /api/v1/tenants/{tenantID}/tpm/vtpm/start":             "tenants:set_tpm_mode",
	"POST /api/v1/tenants/{tenantID}/tpm/vtpm/stop":              "tenants:set_tpm_mode",
	"PUT /api/v1/users/{username}":                               "users:update",
}

// TestRESTPermissions_MatchWireContract pins the resource:action pair of
// EVERY RouteAuthPermission REST route against the literal wire contract.
// The scan reads this package's own source (routes.go), so a route that
// loses its gate, gains one, or has its resource/action swapped fails here.
// The check runs in both directions and asserts the count, so neither a
// changed pair nor an added or dropped gate can slip through.
func TestRESTPermissions_MatchWireContract(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "scanning this package for authorization gates must succeed")

	require.Len(t, sites, len(goldenRESTPermissions),
		"a permission-gated route was added to or removed from routes.go without updating the wire contract")

	found := make(map[string]string, len(sites))
	for _, site := range sites {
		_, dup := found[site.Key]
		require.False(t, dup, "duplicate gate key %q at %s", site.Key, site.Pos)
		found[site.Key] = site.Pair()
	}

	for route, want := range goldenRESTPermissions {
		got, ok := found[route]
		require.True(t, ok, "route %q lost its authorization gate", route)
		assert.Equal(t, want, got, "route %q", route)
	}

	for route, got := range found {
		want, ok := goldenRESTPermissions[route]
		require.True(t, ok, "route %q gained an authorization gate without a wire-contract entry", route)
		assert.Equal(t, want, got, "route %q", route)
	}
}

// TestRESTPermissions_NoRawLiterals proves no permission-gated route in
// routes.go spells its resource or action as a string literal.
// authzscan.Scan returns a *authzscan.RawLiteralError the moment it sees one,
// so a successful scan is the proof. This is the regression guard for
// go-xkms#1232: routes.go previously passed the raw literals "derive",
// "wrap", and "unwrap" to auth.ResourceKeys' derive-ecdh, wrap-by-id, and
// unwrap-by-id routes instead of auth.ActionDerive/ActionWrap/ActionUnwrap.
func TestRESTPermissions_NoRawLiterals(t *testing.T) {
	sites, err := authzscan.Scan(".", authzSeams)
	require.NoError(t, err, "every permission-gated route must name a pkg/auth constant, never a string literal")
	require.NotEmpty(t, sites)
}
