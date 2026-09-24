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
	"testing"

	qrdbv1 "github.com/jeremyhahn/go-qrdb/pkg/api/grpc/proto/qrdbv1"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	xkmsrest "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// restOnlyPermissions are the pairs the REST route table gates on that no
// other transport declares. Each is scoped by module_scopes.go because qrdb
// does not declare it. The set is closed: a REST route that starts asking for
// a pair gRPC and MCP do not know is a new permission name nobody granted or
// scoped, and fails TestRESTPermissionsAreCrossTransportVocabulary.
var restOnlyPermissions = map[string]struct{}{
	"keys:update": {}, // PKCS#11 remote-state compare-and-swap
	"ssh:use":     {}, // blanket gate on the /xkms/v1/ssh route group
}

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
		if spec.Resource != "" && spec.Action != "" {
			set[spec.Resource+":"+spec.Action] = struct{}{}
		}
	}

	services := pb.File_pkg_api_grpc_proto_xkmsv1_xkms_proto.Services()
	for i := 0; i < services.Len(); i++ {
		methods := services.Get(i).Methods()
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
	return set
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
		assert.True(t, qrdbsdk.HasPermissionRoleGrant(qrdbsdk.RoleNameOwner, perm), "owner must hold %s", pair)
	}
}
