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

package apimodule

import (
	"sort"
	"strings"
	"testing"

	qrdbgrpcv1 "github.com/jeremyhahn/go-qrdb/pkg/api/grpc/proto/qrdbv1"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbv1 "github.com/jeremyhahn/go-qrdb/sdk/go/proto/qrdb/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	xkmsrest "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// restOnlyPermissions are the pairs the REST route table gates on that no
// other transport declares. Each is scoped by module_scopes.go because qrdb
// does not declare it. The set is closed: a REST route that starts asking for
// a pair gRPC and MCP do not know is a new permission name nobody granted or
// scoped, and fails TestRESTPermissionsAreCrossTransportVocabulary.
//
// Empty since go-xkms#1249: keys:update (PKCS#11 compare-and-swap and
// platform-sealed-store reseal-in-place) used to be REST-only because gRPC
// and MCP collapsed both operations into the coarser keys:write. All three
// transports now gate them on keys:update, so it is no longer REST-only —
// grpcAndMCPPermissionPairs below finds it too.
var restOnlyPermissions = map[string]struct{}{}

// restPermissionPairs returns every resource:action pair the REST route table
// gates on, sorted and de-duplicated.
func restPermissionPairs() []string {
	set := map[string]struct{}{}
	for _, spec := range xkmsrest.Routes() {
		if spec.Auth == xkmsrest.RouteAuthPermission {
			set[spec.Resource+":"+spec.Action] = struct{}{}
		}
	}
	pairs := make([]string, 0, len(set))
	for p := range set {
		pairs = append(pairs, p)
	}
	sort.Strings(pairs)
	return pairs
}

// grpcAndMCPPermissionPairs returns every pair the gRPC proto options and the
// MCP method specs declare.
func grpcAndMCPPermissionPairs(t *testing.T) map[string]struct{} {
	t.Helper()

	set := map[string]struct{}{}
	for _, spec := range xkmsmcp.ModuleMethods() {
		if !spec.Public {
			set[string(spec.Permission)] = struct{}{}
		}
	}

	addServicePermissions(t, set, pb.File_pkg_api_grpc_proto_xkmsv1_xkms_proto.Services())

	// xkmsd also serves go-qrdb's admin surface on its control plane
	// (pkg/server/qrdb_control_plane.go), and the ACME admin routes gate on
	// its admin:status pair. qrdb declares its admin:* pairs on
	// qrdb.v1.QRDBService, which also carries the KV surface xkms does not
	// expose, so only its admin:* pairs are added.
	qrdbService := qrdbgrpcv1.File_pkg_api_grpc_proto_qrdbv1_qrdb_proto.Services().ByName("QRDBService")
	require.NotNil(t, qrdbService, "qrdb.v1.QRDBService descriptor not found")
	qrdbPairs := map[string]struct{}{}
	addMethodPermissions(t, qrdbPairs, qrdbService.Methods())
	for pair := range qrdbPairs {
		if strings.HasPrefix(pair, "admin:") {
			set[pair] = struct{}{}
		}
	}
	return set
}

// addServicePermissions adds the permission option of every method of every
// service in services to set.
func addServicePermissions(t *testing.T, set map[string]struct{}, services protoreflect.ServiceDescriptors) {
	t.Helper()
	for i := 0; i < services.Len(); i++ {
		addMethodPermissions(t, set, services.Get(i).Methods())
	}
}

// addMethodPermissions adds the qrdb.v1.permission option of each method in
// methods to set; methods without the option are skipped.
func addMethodPermissions(t *testing.T, set map[string]struct{}, methods protoreflect.MethodDescriptors) {
	t.Helper()
	for j := 0; j < methods.Len(); j++ {
		opts, ok := methods.Get(j).Options().(*descriptorpb.MethodOptions)
		if !ok || !proto.HasExtension(opts, qrdbv1.E_Permission) {
			continue
		}
		perm, ok := proto.GetExtension(opts, qrdbv1.E_Permission).(string)
		require.True(t, ok, "permission option is not a string")
		set[perm] = struct{}{}
	}
}

// TestRESTPermissionsAreCrossTransportVocabulary proves the REST route table
// mints no permission name of its own: every pair a REST route gates on is
// one gRPC or MCP already declares for an operation, apart from the closed
// restOnlyPermissions set. go-xkms#780 moved the PIN, PIV, CA, custodian,
// share, tenant, password and credential routes onto exactly such pairs, so
// they needed no new registration or scope.
func TestRESTPermissionsAreCrossTransportVocabulary(t *testing.T) {
	declared := grpcAndMCPPermissionPairs(t)

	var strays []string
	for _, pair := range restPermissionPairs() {
		if _, ok := declared[pair]; ok {
			continue
		}
		if _, ok := restOnlyPermissions[pair]; ok {
			continue
		}
		strays = append(strays, pair)
	}
	assert.Empty(t, strays, "REST gates on permissions no other transport declares")
}

// TestRESTOnlyPermissionsAreStillRESTOnly keeps restOnlyPermissions honest: an
// entry that gRPC or MCP now declares, or that no REST route uses any more, is
// stale and must be removed.
func TestRESTOnlyPermissionsAreStillRESTOnly(t *testing.T) {
	declared := grpcAndMCPPermissionPairs(t)
	used := map[string]struct{}{}
	for _, pair := range restPermissionPairs() {
		used[pair] = struct{}{}
	}

	for pair := range restOnlyPermissions {
		_, elsewhere := declared[pair]
		assert.False(t, elsewhere, "%s is declared by gRPC or MCP; drop it from restOnlyPermissions", pair)
		_, inUse := used[pair]
		assert.True(t, inUse, "%s is no longer gated by any REST route; drop it from restOnlyPermissions", pair)
	}
}

// TestNewModule_AdminAndOwnerHoldEveryRESTPermission proves the default role
// grants cover every permission-gated REST route, so moving a route off the
// session-only tier never locks the Admin or Owner out of it.
func TestNewModule_AdminAndOwnerHoldEveryRESTPermission(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	pairs := restPermissionPairs()
	require.NotEmpty(t, pairs)
	for _, pair := range pairs {
		perm := qrdbsdk.Permission(pair)
		assert.True(t, qrdbsdk.IsPermissionRegistered(perm), "%s must be registered", pair)
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perm), "admin must hold %s", pair)
		assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.RoleNameOwner, perm), "owner must not carry an xkms grant for %s", pair)
		assert.Contains(t, qrdbsdk.AllPermissions(), perm, "owner must hold %s through go-qrdb", pair)
	}
}

// TestNewModule_UserRoleStoresPasswords proves the built-in User role can
// store entries in the password vault -- the store is for users -- while
// changing another user's shared entry stays with its owner or an
// administrator (XKMSService.checkSharedPasswordOwnership).
func TestNewModule_UserRoleStoresPasswords(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, action := range []string{auth.ActionWrite, auth.ActionDelete} {
		perm := qrdbsdk.Permission(auth.ResourcePasswords + ":" + action)
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleUser, perm), "user must hold %s", perm)
	}
	assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleUser,
		qrdbsdk.Permission(auth.ResourceOIDCCredentials+":"+auth.ActionCreate)), "the user role gains nothing else")
}

// TestNewModule_PeerAttestationRoles proves the roles callers run as --
// User and Operator -- can answer the attested-caller gate's challenge, while
// the roles that run no workload -- SO and Auditor -- cannot.
func TestNewModule_PeerAttestationRoles(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, action := range []string{auth.ActionChallenge, auth.ActionSubmit} {
		perm := qrdbsdk.Permission(auth.ResourcePeerAttestation + ":" + action)
		for _, role := range []string{qrdbsdk.PermissionRoleUser, qrdbsdk.PermissionRoleOperator} {
			assert.True(t, qrdbsdk.HasPermissionRoleGrant(role, perm), "%s must hold %s", role, perm)
		}
		for _, role := range []string{qrdbsdk.PermissionRoleSO, qrdbsdk.PermissionRoleAuditor} {
			assert.False(t, qrdbsdk.HasPermissionRoleGrant(role, perm), "%s must not hold %s", role, perm)
		}
	}
}

// TestNewModule_AuditorHoldsOnlyReads pins the Auditor slice: every read of
// xkms-owned state, and nothing else xkms owns. An Auditor that can change
// state is no longer an independent observer (FIPS 140-3 AS10.10).
func TestNewModule_AuditorHoldsOnlyReads(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	reads := map[qrdbsdk.Permission]bool{}
	for _, p := range auditorPermissions() {
		reads[p] = true
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, p), "Auditor must hold %s", p)
	}
	for _, p := range ownedScopedPermissions() {
		if !reads[p] {
			assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, p), "Auditor must not hold %s", p)
		}
	}
}

// TestNewModule_OperatorGrants pins the Operator slice: the reads, service
// SSH assets and credential use, but no administration of TPM policies,
// trust roots, tenants or the key store.
func TestNewModule_OperatorGrants(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, p := range []string{"tpm_policy:get", "tpm_policy:verify", "trust_roots:list", "bootstrap:read", "ssh:service", "oidc_credentials:token"} {
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleOperator, qrdbsdk.Permission(p)), "Operator must hold %s", p)
	}
	for _, p := range []string{"tpm_policy:create", "tpm_policy:delete", "trust_roots:import", "tenants:set_tpm_mode", "keys:update", "oidc_credentials:create"} {
		assert.False(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.PermissionRoleOperator, qrdbsdk.Permission(p)), "Operator must not hold %s", p)
	}
}

// TestNewModule_DeclaresGovernanceDutyForOwnedPermissions checks that every
// governance declaration names a permission xkms owns -- qrdb declares the
// duty of its own, and a conflicting declaration panics at startup -- and
// that the declarations are in force once the module is built.
func TestNewModule_DeclaresGovernanceDutyForOwnedPermissions(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	owned := map[qrdbsdk.Permission]bool{}
	for _, p := range ownedScopedPermissions() {
		owned[p] = true
	}
	for _, p := range governancePermissions() {
		assert.True(t, owned[p], "%s is not an xkms-owned permission; go-qrdb declares its duty", p)
		assert.Equal(t, qrdbsdk.PermissionDutyGovernance, qrdbsdk.LookupPermissionDuty(p), "duty of %s", p)
	}
}

// TestNewModule_DataPlanePermissionsStayUndeclared checks the other side:
// the xkms-owned data-plane verbs carry no duty, so the Security Officer
// role can never be granted them.
func TestNewModule_DataPlanePermissionsStayUndeclared(t *testing.T) {
	_, err := NewModule(func() *xkms.XKMSService { return nil })
	require.NoError(t, err)

	for _, p := range []string{"oidc_credentials:token", "peer_attestation:submit", "ssh:service"} {
		assert.Equal(t, qrdbsdk.PermissionDutyUndeclared, qrdbsdk.LookupPermissionDuty(qrdbsdk.Permission(p)), "duty of %s", p)
	}
}
