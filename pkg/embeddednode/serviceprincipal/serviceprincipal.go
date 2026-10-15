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

// Package serviceprincipal defines go-xkms's node-sanctioned service
// principal (go-qrdb node.WithServicePrincipal) and its least-privilege
// grant. embeddednode.NewNode configures it on every node it builds; xkms's
// own in-process calls into the node run as it through Node.ServiceContext.
// It is a leaf package so test helpers can build a node configured exactly
// as production's without importing embeddednode's dependency tree.
package serviceprincipal

import (
	"sync"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
)

// Name is the service principal's name. xkms's own calls into the embedded
// node run as it: persisting through its storage backend (keys, CA state,
// signing keys) and taking the leases that serialize its OIDC credential
// refreshes. go-qrdb audits it as "qrdb-service:xkms" in the system tenant.
// A call made on behalf of an authenticated request never runs as it.
const Name = "xkms"

// grant is the principal's whole authority: exactly the permissions xkms's
// own calls exercise, never a wildcard.
//
//   - kv:get, kv:put, kv:delete, kv:list, kv:exists -- the storage backend
//     (pkg/storage/qrdb.Backend) every xkms subsystem persists through.
//   - lease:grant, lease:revoke, lease:keepalive -- the OIDC credential
//     locker takes and releases a refresh lease, and the refresh scheduler
//     renews its leadership lease (pkg/oidc/credential).
//   - transaction:execute -- go-qrdb takes a lease with a compare-and-swap
//     transaction, and the storage backend's guarded writes fall back to
//     one where the transport lacks the guarded verbs.
//   - databases:create -- the datastore ensures each feature's named
//     database exists before serving its DAOs (datastore.DatabaseKVStore).
//   - index:create, index:query -- a feature DAO registers the indexes its
//     entity declares and looks entities up through them.
//   - kv:range -- a feature DAO's paged listing (ForEachPage) scans its
//     entity type's keys, as pkcs11state.Store.List does.
//   - admin:shard_state -- a clustered xkmsd waits for its shard's leader
//     before serving (Server.waitForClusterLeader); the leader query is a
//     shard-state read.
var grant = []qrdbsdk.Permission{
	"kv:get",
	"kv:put",
	"kv:delete",
	"kv:list",
	"kv:range",
	"kv:exists",
	"lease:grant",
	"lease:revoke",
	"lease:keepalive",
	"transaction:execute",
	"databases:create",
	"index:create",
	"index:query",
	"admin:shard_state",
}

var registerOnce sync.Once

// Grant returns a copy of the permissions granted to the principal.
func Grant() []qrdbsdk.Permission {
	return append([]qrdbsdk.Permission(nil), grant...)
}

// Option returns the node option that configures the principal, registering
// its grant with go-qrdb first. The grant is process-wide and registered
// once, however many nodes the process builds.
func Option() qrdbnode.NodeOption {
	registerOnce.Do(func() {
		qrdbsdk.RegisterPermissionRoleGrant(Name, grant...)
	})
	return qrdbnode.WithServicePrincipal(Name)
}
