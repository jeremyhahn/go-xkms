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

// ceremonyGrant is what the principal additionally holds during `xkmsd init`,
// whose admin enrollment is xkms's own work with no end user behind it yet:
//
//   - users:get_by_cert_thumbprint -- resolving the administrator first-boot
//     just created from its certificate's SPKI thumbprint.
//   - user_authfactors:add -- persisting the administrator's enrolled login
//     factors.
//
// It is registered only by the init process (RegisterCeremonyGrant), so a
// running xkmsd's principal never holds it.
var ceremonyGrant = []qrdbsdk.Permission{
	"users:get_by_cert_thumbprint",
	"user_authfactors:add",
}

var registerCeremonyOnce sync.Once

// CeremonyGrant returns a copy of the permissions RegisterCeremonyGrant adds.
func CeremonyGrant() []qrdbsdk.Permission {
	return append([]qrdbsdk.Permission(nil), ceremonyGrant...)
}

// RegisterCeremonyGrant adds the init ceremony's permissions to the
// principal, once per process. Only `xkmsd init` calls it; go-qrdb honours
// the grant from the next Node.ServiceContext on.
func RegisterCeremonyGrant() {
	registerCeremonyOnce.Do(func() {
		qrdbsdk.RegisterPermissionRoleGrant(Name, ceremonyGrant...)
	})
}

// webauthnGrant is what the principal additionally holds when xkmsd builds
// its WebAuthn relying party over the embedded node: the relying party's
// user store (pkg/webauthn qrdbUserStore) runs as the principal, since a
// login is anonymous (#2541).
//
//   - users:read -- the GetByEmail probe at registration begin and the
//     user lookups of login, add-a-passkey and registration finish.
//   - users:update -- recording the user's WebAuthn identity.
//   - users:delete -- rolling a failed registration back.
//
// It deliberately holds no users:create (CA ruling 602): an anonymous
// public registration/begin would create a durable account before any
// credential is verified, so over an enforcing node the store's create is
// refused and the begin answers ErrRegistrationRefused (HTTP 403). Anonymous
// public registration stays refused pending the owner's decision on a
// pending-account lifecycle (go-xkms #2202); accounts are provisioned by an
// administrator and add passkeys from their own session.
//
// It is registered only by RegisterWebAuthnGrant, so a node without the
// WebAuthn service never holds it.
var webauthnGrant = []qrdbsdk.Permission{
	"users:read",
	"users:update",
	"users:delete",
}

var registerWebAuthnOnce sync.Once

// WebAuthnGrant returns a copy of the permissions RegisterWebAuthnGrant adds.
func WebAuthnGrant() []qrdbsdk.Permission {
	return append([]qrdbsdk.Permission(nil), webauthnGrant...)
}

// RegisterWebAuthnGrant adds the WebAuthn user store's permissions to the
// principal, once per process. The server calls it when it builds the
// WebAuthn service over the embedded node; go-qrdb honours the grant from
// the next Node.ServiceContext on.
func RegisterWebAuthnGrant() {
	registerWebAuthnOnce.Do(func() {
		qrdbsdk.RegisterPermissionRoleGrant(Name, webauthnGrant...)
	})
}

// refreshGrant is what the principal additionally holds when the session
// token issuer re-checks a refresh token's subject over the embedded node
// (rest.BuildTokenIssuer binds auth.QRDBUserResolver to the principal's
// call context): the recheck runs as the principal for every login flow
// that mints a session, PIV/mTLS as well as WebAuthn.
//
//   - users:read -- the GetUserByUsername recheck of Issuer.Refresh.
//
// It is registered only by RegisterRefreshGrant, so a node without a bound
// refresh resolver never holds it.
var refreshGrant = []qrdbsdk.Permission{
	"users:read",
}

var registerRefreshOnce sync.Once

// RefreshGrant returns a copy of the permissions RegisterRefreshGrant adds.
func RefreshGrant() []qrdbsdk.Permission {
	return append([]qrdbsdk.Permission(nil), refreshGrant...)
}

// RegisterRefreshGrant adds the session refresh recheck's permissions to the
// principal, once per process. The token issuer calls it when it binds its
// user resolver to the principal; go-qrdb honours the grant from the next
// Node.ServiceContext on.
func RegisterRefreshGrant() {
	registerRefreshOnce.Do(func() {
		qrdbsdk.RegisterPermissionRoleGrant(Name, refreshGrant...)
	})
}
