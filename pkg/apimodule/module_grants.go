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

package apimodule

import (
	"sort"
	"sync"

	qrdbv1 "github.com/jeremyhahn/go-qrdb/pkg/api/grpc/proto/qrdbv1"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	xkmsrest "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
)

// roleGrantOnce guards the one-time contribution of the module's permission
// set into qrdb's role-grant registry.
var roleGrantOnce sync.Once

// registerRoleGrants contributes every permission the xkms module declares —
// across its gRPC proto options, its REST route table, and its MCP method
// specs — into go-qrdb's built-in role-grant registry, granting the full set
// to the Admin and Owner roles. qrdb materializes built-in role grants live
// at role-seed time (permission.RolePermissions), so this must run before
// the embedded node seeds roles; NewModule is constructed before the node,
// which satisfies that ordering.
//
// Without this contribution, qrdb's authorizer — which enforces every module
// route on the unified server — would deny ALL xkms operations to every
// built-in role, locking out even the first-boot administrator: qrdb's own
// grant lists know nothing about xkms resources.
//
// The set is DERIVED from the three declaration surfaces rather than
// hand-copied so a new RPC/route/tool is granted the moment it is declared.
// The Security Officer role deliberately receives nothing here: xkms's
// surface is overwhelmingly cryptographic and qrdb's SoD invariant
// (FIPS 140-3 AS10.03) forbids crypto grants to SO.
func registerRoleGrants() {
	roleGrantOnce.Do(func() {
		set := map[string]struct{}{}

		for _, spec := range xkmsrest.Routes() {
			if spec.Auth == xkmsrest.RouteAuthPermission && spec.Resource != "" && spec.Action != "" {
				set[spec.Resource+":"+spec.Action] = struct{}{}
			}
		}

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
				if perm, ok := proto.GetExtension(opts, qrdbv1.E_Permission).(string); ok && perm != "" {
					set[perm] = struct{}{}
				}
			}
		}

		perms := make([]qrdbsdk.Permission, 0, len(set))
		for p := range set {
			perms = append(perms, qrdbsdk.Permission(p))
		}
		sort.Slice(perms, func(i, j int) bool { return perms[i] < perms[j] })

		// The permissions must exist in qrdb's global registry before any
		// role may hold them: role creation validates every granted
		// permission, so an unregistered grant fails first boot.
		qrdbsdk.RegisterPermissions(perms...)
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perms...)
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.RoleNameOwner, perms...)
	})
}
