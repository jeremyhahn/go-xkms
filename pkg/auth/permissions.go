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

// Resource and action identifiers for the xkms API authorization surface.
// These mirror the canonical go-qrdb permission vocabulary
// (pkg/permission/constants.go, broker_scope.go, acme_admin_scope.go) so a
// route decorator's resource:action pair maps directly onto a qrdb role grant.
// xkms registers no parallel vocabulary; the genuinely xkms-domain permissions
// (backends:*, keys:import/export, certs:read, piv:*, ssh:*, passwords:*, the
// ACME administration family, and the CA hierarchy family) are all part of
// qrdb's canonical registry and are granted by qrdb's built-in roles.
//
// This file is the ONLY authorization vocabulary in the xkms process. A
// transport must never declare its own resource or action string: two tables
// expressing the same vocabulary drift silently, because a retyped pair simply
// stops matching the grant with no compile error and no test failure.
const (
	// Resources.
	ResourceKeys     = "keys"
	ResourceCerts    = "certs"
	ResourceBackends = "backends"
	ResourceUsers    = "users"
	ResourceRoles    = "roles"
	ResourceTenants  = "tenants"
	ResourceAudit    = "audit"
	ResourceAdmin    = "admin"
	ResourceSeal     = "seal"
	ResourceBarrier  = "barrier"

	// Hardware and vault resources. Each is its own qrdb resource family so a
	// deployment can mint a role that reaches, for example, the PIV slots
	// without also reaching the password vault.
	ResourcePIV       = "piv"
	ResourceSSH       = "ssh"
	ResourcePasswords = "passwords"

	// ResourcePIN is the token PIN surface of a hardware-backed barrier: the
	// SO and user PINs plus their lockout counters. qrdb models it separately
	// from seal:* so an operator role can verify or reset a PIN without also
	// holding authority to seal, unseal, or rekey the barrier itself.
	// Mirrors qrdb permission.PINRead / permission.PINWrite.
	ResourcePIN = "pin"

	// ResourceTenantBarrier is a single tenant's own barrier, distinct from
	// the system barrier (seal:*). Mirrors the qrdb
	// permission.TenantBarrier* family.
	ResourceTenantBarrier = "tenant_barrier"

	// ResourceCeremony is the first-boot initialization ceremony: officer
	// enrollment, certificate and Shamir-share claims, and CSR signing.
	ResourceCeremony = "ceremony"

	// ResourceCredentials is the credential-submission surface used during the
	// ceremony and barrier unseal (strategy discovery plus factor submission).
	ResourceCredentials = "credentials"

	// ResourceBootstrap is the trust-bootstrap listener's own public
	// identity: the Noise_NK and P-256 static public keys
	// (pkg/server/bootstrap_key_custody.go), reported read-only so an
	// administrator can distribute them to first-contact clients. It is
	// distinct from ResourceCeremony/ResourceCredentials, which gate the
	// unseal/enrollment ceremony rather than this always-on listener.
	ResourceBootstrap = "bootstrap"

	// ACME administration resources. RFC 8555 registration objects are
	// neither certificates (certs:*) nor platform users (users:*); qrdb
	// models each object family as its own resource so a deployment can mint
	// a narrow role that holds, for example, only acme_eab:create.
	ResourceACMEAccounts = "acme_accounts"
	ResourceACMEOrders   = "acme_orders"
	ResourceACMEEAB      = "acme_eab"

	// ResourceCA is certificate-authority hierarchy lifecycle: creating a
	// root or intermediate CA, reading and listing the hierarchy, changing a
	// CA's status, and selecting the default issuing CA. It is deliberately
	// distinct from ResourceCerts, which is *leaf* certificate lifecycle —
	// holding certs:generate must not imply authority to mint a signing CA.
	ResourceCA = "ca"

	// Key actions.
	ActionSign    = "sign"
	ActionVerify  = "verify"
	ActionEncrypt = "encrypt"
	ActionDecrypt = "decrypt"
	ActionCreate  = "create"
	ActionRotate  = "rotate"
	ActionDelete  = "delete"
	ActionList    = "list"
	ActionGet     = "get"
	ActionImport  = "import"
	ActionExport  = "export"

	// Key-transport and key-agreement actions. Wrapping and unwrapping move
	// key material under a wrapping key; deriving produces new key material
	// from an existing one (ECDH / KDF). None of them is implied by
	// encrypt/decrypt, which act on caller data rather than on key material.
	ActionWrap   = "wrap"
	ActionUnwrap = "unwrap"
	ActionDerive = "derive"

	// Certificate actions (qrdb uses generate/revoke/read/list).
	ActionGenerate = "generate"
	ActionRevoke   = "revoke"

	// Shared read/update actions for certs, backends, and users.
	ActionRead   = "read"
	ActionUpdate = "update"

	// ActionWrite is the coarse mutating action of the resource families that
	// do not model create/update separately (piv:write, ssh:write,
	// passwords:write).
	ActionWrite = "write"

	// ActionUse authorizes a cryptographic operation with a slot key whose
	// material never leaves the card (piv:use). It is deliberately distinct
	// from piv:read, which returns only slot metadata and certificates.
	ActionUse = "use"

	// ActionDisable deactivates a principal or registration (users:disable,
	// acme_accounts:disable).
	ActionDisable = "disable"

	// Admin service actions. ActionPeers mirrors go-qrdb's AdminPeers
	// permission (pkg/permission/constants.go) exactly: the REST cluster
	// routes (admin:status, admin:peers) drive the same AdminService the
	// embedded qrdb node registers on the control-plane gRPC surface
	// (pkg/server/qrdb_control_plane.go), so the grant must match verbatim.
	// There are no xkms actions for AdminAddMember/AdminRemoveMember: Raft
	// membership mutation is never exposed over REST (docs/cluster/api.md),
	// only through go-qrdb's own control plane directly.
	ActionStatus       = "status"
	ActionCapabilities = "capabilities"
	ActionPeers        = "peers"

	// Barrier / seal lifecycle actions.
	ActionBootstrap        = "bootstrap"
	ActionSeal             = "seal"
	ActionUnseal           = "unseal"
	ActionRekey            = "rekey"
	ActionRotateRootKey    = "rotate_root_key"
	ActionGenerateRecovery = "generate_recovery"
	ActionRecoverWithKeys  = "recover_with_keys"
	ActionInitializeShamir = "initialize_shamir"
	ActionUnsealShare      = "unseal-share"
	ActionEnableEncryption = "enable_encryption"

	// ActionInit is the one-shot provisioning of a resource that already
	// exists as a shell (tenant_barrier:init). Mirrors qrdb
	// permission.TenantBarrierInit. It is distinct from ActionCreate, which
	// brings the enclosing object into existence.
	ActionInit = "init"

	// Init ceremony actions.
	ActionClaimCert          = "claim_cert"
	ActionClaimShareBegin    = "claim_share_begin"
	ActionClaimShareComplete = "claim_share_complete"
	ActionSignCSR            = "sign_csr"

	// Custodian roster actions. Adding or removing a custodian changes who can
	// contribute an unseal share, so qrdb grants it separately from the
	// ceremony's read surface (ceremony:status). Mirrors qrdb
	// permission.CeremonyEnrollCustodian / permission.CeremonyRevokeCustodian.
	ActionEnrollCustodian = "enroll_custodian"
	ActionRevokeCustodian = "revoke_custodian"

	// Credential submission actions.
	ActionSubmit   = "submit"
	ActionStrategy = "strategy"

	// Password vault actions.
	ActionLock   = "lock"
	ActionUnlock = "unlock"
)
