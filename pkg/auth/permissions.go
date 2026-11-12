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
// Most of these mirror the canonical go-qrdb permission vocabulary
// (pkg/permission/constants.go, broker_scope.go, acme_admin_scope.go) so a
// route decorator's resource:action pair maps directly onto a qrdb role
// grant: the genuinely xkms-domain permissions (backends:*,
// keys:import/export, certs:read, piv:*, ssh:*, passwords:*, the ACME
// administration family, and the CA hierarchy family) are all part of
// qrdb's canonical registry and are granted by qrdb's built-in roles.
//
// A small number of resources have no qrdb counterpart at all — qrdb's
// registry simply does not know the name — so xkms both mints and scopes
// them itself: bootstrap (the trust-bootstrap listener's own public keys,
// go-xkms#632), tpm_policy (named TPM policies), peer_attestation (the
// attested-caller gate's evidence collection) and tenants:set_tpm_mode.
// pkg/apimodule/module_scopes.go registers each one's tenancy scope
// explicitly for the same reason it does for the four
// keys/ssh exceptions documented there: go-qrdb#504 refuses to admit an
// unscoped permission at all, rather than default it to ScopeSelf.
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

	// ResourceTPMPolicy is named TPM policy management (pkg/tpmpolicy):
	// creating, reading, updating, revoking, verifying and deleting the
	// policies a tenant's TPM keys and sealed objects are bound to, and
	// rotating the tenant's policy authority. go-qrdb's canonical registry
	// has no permission family for it, so xkms owns the name and declares
	// its tenancy scope (pkg/apimodule/module_scopes.go).
	ResourceTPMPolicy = "tpm_policy"

	// ResourceOIDCCredentials is server-side OIDC credential management
	// (pkg/oidc/credential): named OAuth/OIDC logins the server holds and
	// refreshes. Its token action (oidc_credentials:token) serves a current
	// access token, so it is granted apart from reading a credential's
	// metadata. go-qrdb's canonical registry has no permission family for
	// it, so xkms owns the name and declares its tenancy scope
	// (pkg/apimodule/module_scopes.go).
	ResourceOIDCCredentials = "oidc_credentials"

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

	// ResourcePeerAttestation is the attested-caller gate's evidence
	// collection (pkg/attestation/peergate): a peer asks for a challenge
	// nonce and submits a TPM quote over it, bound to its own connection.
	// It acts only on the calling peer's own evidence. go-qrdb's canonical
	// registry has no permission family for it, so xkms owns the name and
	// declares its tenancy scope (pkg/apimodule/module_scopes.go).
	ResourcePeerAttestation = "peer_attestation"

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
	// holding certs:issue must not imply authority to mint a signing CA.
	ResourceCA = "ca"

	// ResourceTrustRoots is the platform's purpose-classified trust-root
	// store (pkg/attestation/truststore): listing and reading the roots,
	// importing them, quarantining one and removing one. The store is
	// process-wide, so every member is cross-scoped: only a system-tenant
	// identity may exercise it.
	ResourceTrustRoots = "trust_roots"

	// ResourceAttestationEndorsements is the attestation Verifier's
	// trust anchors (pkg/attestation/appraisal): storing, listing and
	// removing the attestation-key roots and reference-value signers of
	// the caller's tenant.
	ResourceAttestationEndorsements = "attestation_endorsements"

	// ResourceAttestationReferenceValues is the attestation Verifier's
	// reference values (pkg/attestation/appraisal): storing a signed CoRIM,
	// reading, listing and removing the caller's tenant's baselines.
	ResourceAttestationReferenceValues = "attestation_reference_values"

	// ResourceAttestationVerifier is the attestation Verifier's appraisal
	// verb (pkg/attestation/appraisal): appraising a TPM quote against the
	// caller's tenant's endorsements and reference values.
	ResourceAttestationVerifier = "attestation_verifier"

	// ResourceAttestationSigningKeys is the attestation Verifier's
	// per-repository signing-key bindings (pkg/attestation/appraisal):
	// naming the key that signs one of the caller's tenant's repositories in
	// place of the tenant release key, reading, listing and resolving them.
	// Changing a binding is attestation_signing_keys:bind (ActionBind).
	ResourceAttestationSigningKeys = "attestation_signing_keys"

	// ResourceAttestationVerdicts is continuous attestation's verdicts
	// (pkg/attestation/continuous): listing a device's verdicts, reading its
	// latest one, and re-attesting it now (attestation_verdicts:create).
	ResourceAttestationVerdicts = "attestation_verdicts"

	// ResourceTrust is the platform trust plane's write verbs that act
	// outside the trust-root store: publishing the CA's DANE TLSA records to
	// DNS (pkg/trust/dane Publisher.PublishDANE, trust:publish_dane) and
	// importing an issuer CA from a certificate's AIA caIssuers URL
	// (trust:auto_import_aia). No go-xkms transport serves either verb; the
	// consumer that does (go-quicbaas) gates it with these names, so xkms
	// declares and registers them (pkg/apimodule/module_grants.go). Both act
	// on process-wide state, so they are cross-scoped like trust_roots.
	ResourceTrust = "trust"

	// ResourceBackup is whole-node backup and restore: capturing shard
	// snapshots of the embedded go-qrdb node's replicated state, listing and
	// inspecting them, verifying their integrity, and restoring from one.
	// Mirrors go-qrdb's canonical permission.Backup* family verbatim
	// (pkg/permission/constants.go), which is ScopeSelf — a tenant's grant
	// reaches only its own tenant's backups — so this resource carries no
	// local xkms scoping declaration (pkg/apimodule/module_scopes.go).
	ResourceBackup = "backup"

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

	// Certificate actions, mirroring qrdb's certs:* vocabulary: issue signs a
	// certificate (from a CSR or a TCG enrollment), enroll stores a
	// certificate the caller already holds, revoke withdraws one.
	ActionIssue  = "issue"
	ActionEnroll = "enroll"
	ActionRevoke = "revoke"

	// ActionGenerate produces new secret material that is not a key, such as
	// a password (passwords:generate).
	ActionGenerate = "generate"

	// Shared read/update actions for certs, backends, and users.
	ActionRead   = "read"
	ActionUpdate = "update"

	// Tenant plan-management actions. Mirror qrdb
	// permission.TenantsSetEntitlements and permission.TenantsSetQuotas: a
	// tenant's entitlements and quotas decide what it may consume, so they are
	// gated separately from tenants:update (display metadata) and are never
	// implied by it.
	ActionSetEntitlements = "set_entitlements"
	ActionSetQuotas       = "set_quotas"

	// ActionSetTPMMode changes a tenant's TPM mode (none, shared, vtpm) and
	// starts or stops its vTPM (tenants:set_tpm_mode). The physical TPM
	// belongs to the system tenant, so it is a cross-tenant permission that
	// xkms owns and declares (pkg/apimodule/module_scopes.go); qrdb does not
	// know it.
	ActionSetTPMMode = "set_tpm_mode"

	// Trust write actions (ResourceTrust). ActionPublishDANE writes the CA's
	// DANE TLSA records (RFC 6698) to the configured DNS provider;
	// ActionAutoImportAIA fetches an issuer CA from an AIA caIssuers URL
	// (RFC 5280 §4.2.2.1) and adds it to the trust pool. Neither is implied
	// by trust_roots:import, which takes a root the caller supplies.
	ActionPublishDANE   = "publish_dane"
	ActionAutoImportAIA = "auto_import_aia"

	// ActionToken reads a credential's current access token
	// (oidc_credentials:token). It is the secret-bearing read, distinct
	// from oidc_credentials:get, which returns metadata only.
	ActionToken = "token"

	// ActionWrite is the coarse mutating action of the resource families that
	// do not model create/update separately (piv:write, ssh:write,
	// passwords:write).
	ActionWrite = "write"

	// ActionService is the explicit permission to address service-scoped
	// objects (pkg/scope Service): workload-owned assets that no user owns,
	// so owner == caller cannot authorize them (ssh:service). It is checked
	// below the transport gate, in addition to the verb's own permission
	// (ssh:read, ssh:write, ssh:delete). qrdb does not know the name; xkms
	// owns it and declares its scope (pkg/apimodule/module_scopes.go).
	ActionService = "service"

	// ActionIssueService is the explicit permission to issue a certificate
	// whose SPIFFE URI SAN names the svc (service) kind (certs:issue_service,
	// go-xkms#1659). A svc identity is a workload credential other services
	// trust as a node or agent, so it is a privilege beyond certs:issue. It
	// is checked below the transport gate, in addition to certs:issue, when a
	// SignCSR request asks for the svc kind. qrdb does not know the name;
	// xkms owns it and declares its scope (pkg/apimodule/module_scopes.go).
	ActionIssueService = "issue_service"

	// ActionBind changes which key signs a repository: setting or removing a
	// per-repository signing-key binding (attestation_signing_keys:bind,
	// go-xkms#1697). A binding redirects every image and CoRIM verification
	// of the repository to another key, so it is a privilege of its own,
	// apart from reading the bindings. qrdb does not know the name; xkms owns
	// it and declares its scope (pkg/apimodule/module_scopes.go).
	ActionBind = "bind"

	// ActionUse authorizes a cryptographic operation with a slot key whose
	// material never leaves the card (piv:use). It is deliberately distinct
	// from piv:read, which returns only slot metadata and certificates.
	ActionUse = "use"

	// ActionDisable deactivates a principal or registration (users:disable,
	// acme_accounts:disable).
	ActionDisable = "disable"

	// ActionEnable (re)activates a principal or registration (users:enable).
	// Mirrors go-qrdb permission.UsersEnable verbatim.
	ActionEnable = "enable"

	// Admin service actions. ActionStatus mirrors go-qrdb's AdminStatus
	// permission verbatim. Raft status, membership and peers are go-qrdb's own
	// AdminService surface, served on its control plane, not re-hosted here.
	ActionStatus       = "status"
	ActionCapabilities = "capabilities"

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

	// Credential submission actions. ActionSubmit also submits attestation
	// evidence (peer_attestation:submit).
	ActionSubmit   = "submit"
	ActionStrategy = "strategy"

	// ActionChallenge issues a single-use challenge nonce the caller must
	// answer (peer_attestation:challenge).
	ActionChallenge = "challenge"

	// Password vault actions.
	ActionLock   = "lock"
	ActionUnlock = "unlock"

	// ActionRestore overwrites live state from a backup (backup:restore). It
	// is the most destructive backup action, so qrdb grants it separately
	// from backup:create/backup:read. Mirrors go-qrdb permission.BackupRestore
	// verbatim.
	ActionRestore = "restore"
)
