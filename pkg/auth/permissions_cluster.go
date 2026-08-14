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

package auth

import qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

// Raft membership mutation is privileged. go-qrdb already enforces
// "admin:add_member" / "admin:remove_member" on its own AddMember/RemoveMember
// control-plane RPCs on every transport, and its role store already grants
// them, so xkms gates the identical operation with the identical permission
// rather than minting a parallel vocabulary entry.
//
// The resource and action are derived from the qrdb permission strings instead
// of being retyped, so the two can never drift apart.
var (
	// ResourceClusterAdmin is the resource component of the canonical qrdb
	// membership permissions ("admin").
	ResourceClusterAdmin = qrdbsdk.PermissionResource(qrdbsdk.PermissionAdminAddMember)

	// ActionAddMember is the action component of "admin:add_member".
	ActionAddMember = qrdbsdk.PermissionAction(qrdbsdk.PermissionAdminAddMember)

	// ActionRemoveMember is the action component of "admin:remove_member".
	ActionRemoveMember = qrdbsdk.PermissionAction(qrdbsdk.PermissionAdminRemoveMember)

	// ActionClusterStatus is the action component of "admin:status", the
	// canonical permission for reading cluster leadership. The cluster reads
	// were gated on "backends:read", which is both looser than necessary and
	// unrelated to the operation: a principal granted access to read key
	// backends does not thereby need cluster topology. qrdb models the read
	// side of its own control plane with admin:status / admin:peers, so a
	// grant that covers qrdb's status endpoint now covers the xkms one.
	ActionClusterStatus = qrdbsdk.PermissionAction(qrdbsdk.PermissionAdminStatus)

	// ActionClusterPeers is the action component of "admin:peers", the
	// canonical permission for listing a shard's replicas.
	ActionClusterPeers = qrdbsdk.PermissionAction(qrdbsdk.PermissionAdminPeers)
)
