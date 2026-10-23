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

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbv1 "github.com/jeremyhahn/go-qrdb/sdk/go/proto/qrdb/v1"
	xkmsmcp "github.com/jeremyhahn/go-xkms/pkg/api/mcp"
	xkmsrest "github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/descriptorpb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// roleGrantOnce guards the one-time contribution of the module's permission
// set into qrdb's role-grant registry.
var roleGrantOnce sync.Once

// RegisterRoleGrants contributes every permission the xkms module declares —
// across its gRPC proto options, its REST route table, and its MCP method
// specs — into go-qrdb's built-in role-grant registry. Admin holds the full
// set and Owner holds it as every registered permission; Operator, User and
// Auditor each hold their slice of the permissions xkms owns
// (operatorPermissions, userPermissions, auditorPermissions). qrdb materializes built-in role grants live
// at role-seed time (permission.RolePermissions), so this must run before
// the embedded node seeds roles or go-qrdb's ReconcileBuiltInRoles converges
// them; NewModule is constructed before the node, which satisfies that
// ordering.
//
// Without this contribution, qrdb's authorizer — which enforces every module
// route on the unified server — would deny ALL xkms operations to every
// built-in role, locking out even the first-boot administrator: qrdb's own
// grant lists know nothing about xkms resources.
//
// The set is DERIVED from the three declaration surfaces (modulePermissions)
// rather than hand-copied so a new RPC/route/tool is granted the moment it is
// declared. It also declares the tenancy scope and the duty of the
// permissions xkms owns;
// since go-qrdb#504 a permission with no scope is refused rather than
// admitted as ScopeSelf, so an undeclared one fails token issuance for every
// identity holding it.
//
// The Security Officer role deliberately receives nothing here: xkms's
// surface is overwhelmingly cryptographic and qrdb's SoD invariant
// (FIPS 140-3 AS10.03) forbids crypto grants to SO.
//
// RegisterRoleGrants is exported for a first boot that runs on a node built
// without this module (`xkmsd init`): the roles it seeds must carry the same
// grants `xkmsd run` seeds after mounting the module, or run's first boot
// refuses the stored built-in roles as conflicting (go-xkms#794).
func RegisterRoleGrants() {
	roleGrantOnce.Do(func() {
		perms := modulePermissions()

		// ORDER: permissions, then scope, then role grants. qrdb's authorizer
		// resolves a permission's scope before it consults the grant, and
		// rbac.ListPermissions — the token-issuance path — fails outright on
		// the first permission an identity holds that has no scope. A grant
		// registered ahead of its scope is therefore a grant that cannot be
		// exercised and, worse, one that breaks login for every identity
		// holding it (go-qrdb#504).

		// The permissions must exist in qrdb's global registry before any
		// role may hold them: role creation validates every granted
		// permission, so an unregistered grant fails first boot.
		qrdbsdk.RegisterPermissions(perms...)

		// Only the permissions xkms OWNS are scoped here; qrdb declares the
		// rest itself and re-declaring one would overwrite its decision. See
		// module_scopes.go for the four and the reasoning behind each.
		qrdbsdk.RegisterPermissionScope(qrdbsdk.PermissionScopeSelf, selfScopedPermissions()...)
		qrdbsdk.RegisterPermissionScope(qrdbsdk.PermissionScopeCross, crossScopedPermissions()...)

		// Duty, like scope, is declared only for the permissions xkms owns:
		// qrdb has declared its own, and declaring a different duty for one
		// of them panics. See governancePermissions.
		qrdbsdk.RegisterPermissionDuty(qrdbsdk.PermissionDutyGovernance, governancePermissions()...)

		// Owner is not granted here: go-qrdb gives Owner every registered
		// permission, so registering the permissions above is its grant.
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.PermissionRoleAdmin, perms...)
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.PermissionRoleOperator, operatorPermissions()...)
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.PermissionRoleUser, userPermissions()...)
		qrdbsdk.RegisterPermissionRoleGrant(qrdbsdk.PermissionRoleAuditor, auditorPermissions()...)
	})
}

// userPermissions returns the xkms-owned permissions the built-in User role
// holds: the consuming slice of oidc_credentials -- a tenant's shared
// credentials are visible to every user of the tenant, who reads their
// metadata and current access tokens, while creating, changing and deleting
// them stays with Admin and Owner -- and passwords:write and
// passwords:delete -- the password manager is a store for users, who create,
// change and delete their personal entries and share entries with the
// tenant. Changing or deleting a shared entry stays with its owner or an
// administrator, which the service enforces
// (XKMSService.checkSharedPasswordOwnership); without passwords:delete an
// owner could not delete even their own entry. It also holds the
// peer_attestation pair, peerAttestationPermissions.
func userPermissions() []qrdbsdk.Permission {
	perms := []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourcePasswords + ":" + auth.ActionWrite),
		qrdbsdk.Permission(auth.ResourcePasswords + ":" + auth.ActionDelete),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionToken),
	}
	return append(perms, peerAttestationPermissions()...)
}

// peerAttestationPermissions returns the attested-caller verbs' permissions
// (pkg/attestation/peergate): asking for a challenge and answering it with
// a TPM quote, both for the caller's own connection only.
func peerAttestationPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourcePeerAttestation + ":" + auth.ActionChallenge),
		qrdbsdk.Permission(auth.ResourcePeerAttestation + ":" + auth.ActionSubmit),
	}
}

// operatorPermissions returns the xkms-owned permissions the built-in
// Operator role holds. qrdb's Operator performs routine crypto and
// maintenance without creating keys or managing tenants, so it gets the
// reads Auditor has, the User's consuming slice of oidc_credentials, and
// ssh:service: Operators hold qrdb's ssh:read/write/delete to administer
// hosts, and the host keys they administer are service-scoped assets. It
// also holds the peer_attestation pair, since a workload running as
// Operator may be asked for evidence.
func operatorPermissions() []qrdbsdk.Permission {
	perms := []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceOIDCCredentials + ":" + auth.ActionToken),
		qrdbsdk.Permission(auth.ResourceSSH + ":" + auth.ActionService),
	}
	perms = append(perms, auditorPermissions()...)
	return append(perms, peerAttestationPermissions()...)
}

// auditorPermissions returns the xkms-owned permissions the built-in Auditor
// role holds: the read-only views of state xkms owns -- the trust-bootstrap
// listener's public keys, TPM policies (including comparing one with the
// live PCRs, which changes nothing) and the platform trust roots. They are
// state visibility, which qrdb also gives Auditor for its own resources
// (seal:status, ca:read, keys:get). oidc_credentials:get stays off Auditor:
// it returns an in-flight device login's user code, which completes that
// login.
func auditorPermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourceBootstrap + ":" + auth.ActionRead),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionVerify),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionGet),
	}
}

// governancePermissions returns the xkms-owned permissions of the governance
// duty: key-store state, TPM policy and trust-root administration, the
// tenant TPM mode, and the reads of that state, which qrdb also files under
// governance (seal:status, ca:read, keys:get). None of them uses a key. The
// rest xkms owns -- oidc_credentials, peer_attestation and ssh:service --
// stay undeclared, like qrdb's own password, SSH and credential verbs.
func governancePermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourceKeys + ":" + auth.ActionUpdate),
		qrdbsdk.Permission(auth.ResourceBootstrap + ":" + auth.ActionRead),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionCreate),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionUpdate),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionRevoke),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionVerify),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionDelete),
		qrdbsdk.Permission(auth.ResourceTPMPolicy + ":" + auth.ActionRotate),
		qrdbsdk.Permission(auth.ResourceTenants + ":" + auth.ActionSetTPMMode),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionList),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionGet),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionImport),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionUpdate),
		qrdbsdk.Permission(auth.ResourceTrustRoots + ":" + auth.ActionDelete),
	}
}

// belowGatePermissions returns the permissions xkms checks below the
// transport gate, which no route, MCP method or RPC names because only the
// request's content reveals they are needed: ssh:service, required to address
// a service-scoped SSH asset (pkg/ssh/tenancy); certs:issue_service, required
// to sign a CSR for the svc SPIFFE kind (pkg/xkms SignCSR). Admin holds both
// through modulePermissions and Owner through registration;
// certs:issue_service, which mints workload identities, is granted to no
// other role by default.
func belowGatePermissions() []qrdbsdk.Permission {
	return []qrdbsdk.Permission{
		qrdbsdk.Permission(auth.ResourceSSH + ":" + auth.ActionService),
		qrdbsdk.Permission(auth.ResourceCerts + ":" + auth.ActionIssueService),
	}
}

// modulePermissions returns, sorted and de-duplicated, every permission the
// xkms module declares across its three declaration surfaces: the REST route
// table, the MCP method specs, and the qrdb.v1.permission options on its gRPC
// method descriptors; plus the permissions it checks below the gate
// (belowGatePermissions).
//
// It is DERIVED rather than hand-copied so a new RPC, route, or tool is
// granted — and scope-checked — the moment it is declared, and so the
// registration path and the scope gate that guards it read the same list.
func modulePermissions() []qrdbsdk.Permission {
	set := map[string]struct{}{}

	for _, spec := range xkmsrest.Routes() {
		gated := spec.Auth == xkmsrest.RouteAuthPermission || spec.Auth == xkmsrest.RouteAuthTenant
		if gated && spec.Resource != "" && spec.Action != "" {
			set[spec.Resource+":"+spec.Action] = struct{}{}
		}
	}

	for _, spec := range xkmsmcp.ModuleMethods() {
		if !spec.Public {
			set[string(spec.Permission)] = struct{}{}
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

	for _, p := range belowGatePermissions() {
		set[string(p)] = struct{}{}
	}

	perms := make([]qrdbsdk.Permission, 0, len(set))
	for p := range set {
		perms = append(perms, qrdbsdk.Permission(p))
	}
	sort.Slice(perms, func(i, j int) bool { return perms[i] < perms[j] })
	return perms
}
