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
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// ---------------------------------------------------------------------------
// Tenancy scope of the permissions xkms OWNS
//
// go-qrdb#504 removed the implicit self-scope: a permission with no declared
// scope is no longer admitted as ScopeSelf, it is refused, and rbac's
// ListPermissions fails on the first unscoped permission an identity holds —
// which fails token issuance, not just the one call. Under go-qrdb
// v0.19.0-alpha a go-quicbaas login for any role carrying keys:read was
// rejected with "permission: no scope declared for keys:read" (keys:read has
// since been retired: go-xkms#1249 replaced it and keys:write with the
// ordinary per-verb keys:create/get/list/update/delete CRUD actions qrdb
// already declares scope for).
//
// pkg/auth/permissions.go states that most of xkms's resource:action pairs
// mirror qrdb's canonical registry, so qrdb's own self_scope.go /
// tenant_scope.go declare the scope of nearly all of them. The ten below are
// the exceptions — names qrdb does not declare, so xkms owns them and must
// declare their reach itself.
//
// PIN EACH MEMBER, NOT THE FAMILY — go-qrdb self_scope.go's rule. Every
// permission is named individually rather than swept in through a family
// helper, because a helper that later gains a member would tag that member
// silently, and the gate would stay green over a decision nobody made.
//
// DECLARE ONLY WHAT XKMS OWNS. RegisterPermissionScope overwrites, and it is
// called after qrdb's package init(). Re-declaring a name qrdb already
// declares would let xkms silently widen an upstream decision — if qrdb
// later narrowed certs:revoke to tenant-only, an xkms re-declaration would
// put it back. TestModuleDeclaresOnlyItsOwnScopes fails on any such entry.
// ---------------------------------------------------------------------------

// selfScopedPermissions returns the permissions xkms declares ScopeSelf: the
// permission acts on the identity's own tenant, lifted across all tenants for
// a system-tenant identity. That is the reach all four had before go-qrdb#504
// removed the implicit default, so declaring it changes no deployment's
// authorization outcome — it restores the one the omission used to supply,
// as a decision a reader can see.
//
// Each is ScopeSelf for the same reason: its siblings are. A scope narrower
// than the family it belongs to would deny reach the family's more powerful
// members still have, which is incoherent rather than safe.
func selfScopedPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		// keys:update gates the compare-and-swap routes on the PKCS#11 state
		// store and the platform-sealed store's reseal-in-place operation
		// (PKCS11StateCAS, SealStoreReseal). go-xkms#1249 retired the coarse
		// keys:read/keys:write pair those two stores used to share with
		// every other keys:* mutation and read: PKCS11StatePut/PutIfAbsent,
		// PKCS11StateGet/List, and SealStorePut/Get/List/Status now carry
		// the ordinary per-verb keys:create/get/list/delete actions qrdb
		// itself declares ScopeSelf for, leaving keys:update as the one name
		// in this family qrdb does not declare (qrdb's keys:* vocabulary has
		// no update member; see pkg/auth/permissions.go). It holds the same
		// SYSTEM-barrier-state reach keys:read/write held: strictly less
		// than keys:delete and keys:import, both ScopeSelf in qrdb.
		qrdbsdk.Permission(auth.ResourceKeys + ":" + auth.ActionUpdate),

		// bootstrap:read reports the trust-bootstrap listener's own public
		// keys (go-xkms#632). The listener is process-wide, not per-tenant,
		// so it holds the same reach as seal:status: a tenant-local Admin
		// sees it for its own tenant, and the system-tenant rule lifts that
		// to every tenant for a system member. qrdb does not declare this
		// name; xkms owns it.
		qrdbsdk.Permission(auth.ResourceBootstrap + ":" + auth.ActionRead),

		// tpm_policy:* is named TPM policy management (pkg/tpmpolicy):
		// the policies a tenant's TPM keys and sealed objects are bound to,
		// and the tenant's policy authority. Every call acts on the
		// identity's own tenant -- XKMSService binds it -- and a
		// system-tenant identity may address any tenant, which is ScopeSelf.
		// qrdb does not declare this name; xkms owns it. PIN EACH MEMBER: a
		// family helper here would tag a future action nobody reviewed.
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionCreate),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionUpdate),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionRevoke),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionVerify),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionDelete),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionRotate),

		// oidc_credentials:* is server-side OIDC credential management
		// (pkg/oidc/credential). Every call acts in the identity's own
		// tenant, and a system-tenant identity may address any tenant's
		// SHARED credentials -- never a personal one, which the credential
		// service refuses to everyone but its owner -- which is ScopeSelf.
		// qrdb does not declare this name; xkms owns it.
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionCreate),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionUpdate),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionDelete),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionToken),

		// ssh:service admits a caller to service-scoped SSH assets, which no
		// user owns (pkg/scope Service; checked in pkg/ssh/tenancy). It is
		// ScopeSelf like its siblings ssh:read/write/delete, which qrdb
		// declares: a tenant identity reaches its own tenant's service
		// assets, a system-tenant identity any tenant's. qrdb does not
		// declare this name; xkms owns it.
		qrdbsdk.Permission(auth.ResourceSSH + ":" + auth.ActionService),
	}
}

// crossScopedPermissions returns the permissions xkms declares ScopeCross:
// exercisable only by a system-tenant identity.
//
// tenants:set_tpm_mode changes a tenant's TPM mode and starts or stops its
// vTPM. The physical TPM belongs to the system tenant, and a tenant cannot
// be allowed to move its own objects onto -- or off -- it, so only a
// platform operator may hold it. qrdb does not declare this name; xkms owns
// it.
func crossScopedPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourceTenants + ":" + auth.ActionSetTPMMode),
	}
}
