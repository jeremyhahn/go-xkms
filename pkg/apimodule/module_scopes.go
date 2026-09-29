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
// rejected with "permission: no scope declared for keys:read".
//
// pkg/auth/permissions.go states that most of xkms's resource:action pairs
// mirror qrdb's canonical registry, so qrdb's own self_scope.go /
// tenant_scope.go declare the scope of nearly all of them. That claim holds
// for 69 of the 81 permissions this module contributes. The twelve below are
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
		// keys:read gates the read surface of the PKCS#11 object-state store
		// (PKCS11StateGet, PKCS11StateList) and the seal store (SealStoreGet,
		// SealStoreStatus). Both hold SYSTEM-barrier state, not per-tenant key
		// material: qrdb declares the whole seal:* family — seal:unseal,
		// seal:rekey, seal:rotate_root_key — ScopeSelf and reserves
		// ScopeTenantOnly for tenant_barrier:*, the per-tenant custody a
		// platform operator must not hold. keys:read reads strictly less than
		// keys:get and keys:export, which qrdb declares ScopeSelf.
		qrdbsdk.Permission(auth.ResourceKeys + ":" + auth.ActionRead),

		// keys:write gates the mutating half of the same two stores
		// (PKCS11StatePut/PutIfAbsent/CAS/CAD/Delete, SealStorePut/Reseal).
		// Same material, same reach, and strictly less than keys:delete and
		// keys:import — both ScopeSelf in qrdb.
		qrdbsdk.Permission(auth.ResourceKeys + ":" + auth.ActionWrite),

		// keys:update gates the single compare-and-swap route on the PKCS#11
		// state store. It is keys:write narrowed to one conditional mutation,
		// so it cannot warrant a wider or narrower tenancy reach than the
		// permission it refines.
		qrdbsdk.Permission(auth.ResourceKeys + ":" + auth.ActionUpdate),

		// bootstrap:read reports the trust-bootstrap listener's own public
		// keys (go-xkms#632). The listener is process-wide, not per-tenant,
		// so it holds the same reach as seal:status: a tenant-local Admin
		// sees it for its own tenant, and the system-tenant rule lifts that
		// to every tenant for a system member. qrdb does not declare this
		// name; xkms owns it.
		qrdbsdk.Permission(auth.ResourceBootstrap + ":" + auth.ActionRead),

		// policy:* (go-xkms#691) is TPM 2.0 PCR-bank sealed-secret
		// authorization policy management (pkg/seal/policy): capturing,
		// reading, refreshing, verifying, and exporting the PCR-value
		// snapshots sealed secrets bind to. It is platform/hardware state,
		// not per-tenant key material -- the same reasoning keys:read/write
		// above give for the PKCS#11 remote-state and seal stores -- so it
		// takes the same ScopeSelf reach. qrdb does not declare this name;
		// xkms owns it. PIN EACH MEMBER: a family helper here would tag a
		// future policy action nobody reviewed.
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionCreate),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionDelete),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionRefresh),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionVerify),
		qrdbsdk.Permission(auth.ResourcePolicy + ":" + auth.ActionExport),
	}
}
