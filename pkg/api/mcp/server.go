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

// Package mcp implements the JSON-RPC 2.0 method surface backing xkms's
// Model Context Protocol integration.
//
// The package owns the dispatch core -- the rpcMethodHandlers table, the
// per-method handlers, tenant scoping (tenant.go), and authorization
// (authz.go) -- consumed through Server.InvokeMethod (module_support.go),
// which is the sole production entry point. It backs the unified-API-
// server's real MCP tools (pkg/apimodule RegisterMCP registers one mcp-go
// tool per ModuleMethods() entry, dispatching each call to InvokeMethod).
//
// There is no standalone network listener in this package. It previously
// ran a hand-rolled, line-framed JSON-RPC 2.0 server over a raw net.Conn
// (TCP or a Unix domain socket), including a connection-bound xkms.subscribe
// event stream; that plane was retired once the unified server superseded
// it, since every caller now reaches the dispatch core through the shared
// server's transports instead of dialing this package directly. Live
// subscription/watch notification parity is expected to arrive with a
// real-MCP notifications design layered on top of the dispatch core, not by
// resurrecting the old net.Conn fan-out.
package mcp

import (
	"context"
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Typed errors for barrier MCP handlers.
var (
	// ErrBarrierNotConfigured is returned when a barrier operation is attempted
	// on a server that has no XKMSService composed.
	ErrBarrierNotConfigured = errors.New("barrier not configured")

	// ErrBarrierSecretRequired is returned when a barrier operation requires
	// a secret but none was provided.
	ErrBarrierSecretRequired = errors.New("secret is required")

	// ErrBarrierShareRequired is returned when a barrier unseal share
	// operation is missing the share value.
	ErrBarrierShareRequired = errors.New("share is required")

	// ErrBarrierSharesRequired is returned when a barrier operation requires
	// shares but none were provided.
	ErrBarrierSharesRequired = errors.New("shares are required")

	// ErrBarrierShamirNotConfigured is returned when a Shamir strategy
	// operation is attempted but no Shamir strategy is registered.
	ErrBarrierShamirNotConfigured = errors.New("shamir strategy not configured")

	// ErrBarrierThresholdInvalid is returned when the threshold parameter
	// is less than 2.
	ErrBarrierThresholdInvalid = errors.New("threshold must be >= 2")

	// ErrBarrierTotalInvalid is returned when the total parameter is less
	// than the threshold.
	ErrBarrierTotalInvalid = errors.New("total must be >= threshold")

	// ErrBarrierRecoveryKeysRequired is returned when a recovery operation
	// requires keys but none were provided.
	ErrBarrierRecoveryKeysRequired = errors.New("recovery keys are required")

	// ErrXKMSServiceRequired is returned when NewServer is called without
	// an XKMSService in the Config.
	ErrXKMSServiceRequired = errors.New("xkms service is required")

	// ErrAuthenticatorRequired is returned by NewServer when Config carries no
	// Authenticator. The constructor refuses to substitute a NoOp authenticator
	// because doing so would silently disable authentication; a caller that
	// really wants an unauthenticated server must pass
	// auth.NewNoOpAuthenticator() explicitly.
	ErrAuthenticatorRequired = errors.New("mcp: authenticator is required")
)

// Server holds the xkms JSON-RPC 2.0 dispatch core: the method table, the
// tenant and authorization gates, and the sub-system references (backends,
// password store, SSH) each handler needs. The system barrier is reached only
// through the XKMSService, which enforces its platform scope. It carries no network
// state; InvokeMethod is the only entry point.
type Server struct {
	keystore        xkms.Backend // Default keystore for backward compatibility
	xkmsService     *xkms.XKMSService
	barrierRegistry *seal.BarrierRegistry
	authenticator   auth.Authenticator
	// authorizer is the qrdb-backed authorization seam shared with the REST,
	// gRPC, and QUIC transports. It is never nil: when RBAC is disabled it is
	// a disabled Authorizer (no RBAC client) that allows every request.
	authorizer *auth.Authorizer
	// rbacEnabled mirrors Config.EnableRBAC. When false, authorizeMethod is a
	// no-op, matching the REST server's un-decorated routes and the QUIC
	// server's default (RBAC-client-less) authorizer.
	rbacEnabled bool
	logger      *slog.Logger

	// sshClient is the optional SSH sub-system. When non-nil, SSH
	// JSON-RPC methods (ssh.keys.*, ssh.knownHosts.*, etc.) are
	// dispatched to it. When nil those methods return
	// ErrSSHNotConfigured.
	sshClient sdkssh.Client
}

// Config holds the MCP server configuration.
type Config struct {
	Authenticator auth.Authenticator
	Logger        *slog.Logger
	// BarrierRegistry gates per-request tenant access the same way REST,
	// gRPC, and QUIC do (see pkg/api/tenantgate). Nil disables tenant
	// enforcement.
	BarrierRegistry *seal.BarrierRegistry
	// XKMSService is the injected XKMS service; replaces the package singleton lookup.
	XKMSService *xkms.XKMSService
	// SSHClient is the optional SSH sub-system. When set, the MCP server
	// advertises and handles ssh.keys.*, ssh.knownHosts.*, and
	// ssh.authorizedKeys.* methods. When nil those namespaces return
	// ErrSSHNotConfigured.
	SSHClient sdkssh.Client

	// Authorizer is the qrdb-backed authorizer (optional). It gates every
	// privileged JSON-RPC method against the hosted go-qrdb node's RBAC
	// service, scoped to the caller identity's tenant. It is consulted only
	// when EnableRBAC is true; production wiring passes the same
	// auth.NewAuthorizer instance the REST, gRPC, and QUIC transports use.
	Authorizer *auth.Authorizer

	// EnableRBAC enables role-based access control on JSON-RPC methods
	// (default: false). When false no authorization check runs at all —
	// identical to the REST server registering its routes without the RBAC
	// decorator and the QUIC server defaulting to an RBAC-client-less
	// authorizer. When true, Authorizer must be non-nil and backed by an RBAC
	// client or NewServer returns ErrAuthorizerRequired: MCP refuses to run a
	// server that believes it enforces RBAC but would allow everything.
	EnableRBAC bool
}

// NewServer creates a new MCP JSON-RPC dispatch core. The XKMS service is
// injected via Config.XKMSService by the composition root; the constructor
// rejects a nil service so the server never dispatches without an
// initialized service.
func NewServer(config *Config) (*Server, error) {
	svc := config.XKMSService
	if svc == nil {
		return nil, ErrXKMSServiceRequired
	}

	// The authenticator is mandatory. Substituting a NoOp authenticator for a
	// missing one would silently disable authentication for every JSON-RPC
	// method, so an omitted authenticator is an error: selecting
	// auth.NewNoOpAuthenticator() must always be an explicit caller decision.
	authenticator := config.Authenticator
	if authenticator == nil {
		return nil, ErrAuthenticatorRequired
	}

	// The authorizer is mandatory whenever RBAC is enabled. A nil (or
	// RBAC-client-less) authorizer under EnableRBAC would authorize every
	// method while the operator believes RBAC is enforced, so the constructor
	// fails closed instead. With RBAC disabled the server keeps a disabled
	// authorizer, which allows all — the documented open-gate configuration.
	authorizer := config.Authorizer
	if config.EnableRBAC {
		if !authorizer.Enabled() {
			return nil, ErrAuthorizerRequired
		}
	} else if authorizer == nil {
		authorizer = auth.NewAuthorizer(nil)
	}

	// Set up logger (default to stdlib if not provided)
	log := config.Logger
	if log == nil {
		log = slog.Default()
	}

	s := &Server{
		xkmsService:     svc,
		barrierRegistry: config.BarrierRegistry,
		authenticator:   authenticator,
		authorizer:      authorizer,
		rbacEnabled:     config.EnableRBAC,
		logger:          log,
		sshClient:       config.SSHClient,
	}

	if config.EnableRBAC {
		log.Info("RBAC enabled for MCP")
	}

	if config.SSHClient != nil {
		log.Info("SSH sub-system configured for MCP")
	}

	// Set default keystore from the injected service for backward compatibility.
	keystore, err := svc.LookupDefaultBackend()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "failed to get default keystore", Err: err}
	}
	s.keystore = keystore

	return s, nil
}

// SetBarrierRegistry configures the tenant barrier registry for the MCP
// server. This allows tenant enforcement to be configured after server
// creation.
func (s *Server) SetBarrierRegistry(registry *seal.BarrierRegistry) {
	s.barrierRegistry = registry
}

// rpcHandler dispatches a single JSON-RPC method to its handler. The *Server
// receiver is passed explicitly so the dispatch table can be populated from
// method expressions, mirroring the qrdb kvMethodHandlers pattern.
type rpcHandler func(s *Server, ctx context.Context, req *JSONRPCRequest) (interface{}, error)

// rpcMethodHandlers maps every supported JSON-RPC method to its handler for
// O(1) dispatch. It is built once at package initialization.
//
// WebAuthn/FIDO2 registration and authentication (transport.FIDO2Servicer:
// BeginRegistration, FinishRegistration, BeginAuthentication,
// FinishAuthentication) have no entry here and never will: they are a named
// exclusion from the MCP surface (issue #193), not a gap. An agent tool-call
// surface must not mint sessions or enrol credentials, and this table is
// also ModuleMethods' source of tool names for capability discovery, so the
// absence here is what keeps those ceremonies off the advertised tool list
// as well as off the dispatcher. See
// pkg/api/transport/mcp.ErrIdentityCeremonyExcluded and docs/webauthn/api.md.
var rpcMethodHandlers = map[string]rpcHandler{
	// Health
	"health": (*Server).handleHealth,

	// Public algorithm discovery, mirroring the unauthenticated REST route.
	"xkms.algorithms": (*Server).handleAlgorithms,

	// XKMS key operations
	"xkms.listBackends": (*Server).handleListBackends,
	"xkms.getBackend":   (*Server).handleGetBackend,
	"xkms.generateKey":  (*Server).handleGenerateKey,
	"xkms.getKey":       (*Server).handleGetKey,
	"xkms.deleteKey":    (*Server).handleDeleteKey,
	"xkms.listKeys":     (*Server).handleListKeys,
	"xkms.rotateKey":    (*Server).handleRotateKey,

	// Key versions
	"xkms.listKeyVersions":       (*Server).handleListKeyVersions,
	"xkms.enableKeyVersion":      (*Server).handleEnableKeyVersion,
	"xkms.disableKeyVersion":     (*Server).handleDisableKeyVersion,
	"xkms.retireKeyVersion":      (*Server).handleRetireKeyVersion,
	"xkms.enableAllKeyVersions":  (*Server).handleEnableAllKeyVersions,
	"xkms.disableAllKeyVersions": (*Server).handleDisableAllKeyVersions,
	"xkms.rotateScopeKeys":       (*Server).handleRotateScopeKeys,

	"xkms.sign":                (*Server).handleSign,
	"xkms.verify":              (*Server).handleVerify,
	"xkms.encrypt":             (*Server).handleEncrypt,
	"xkms.decrypt":             (*Server).handleDecrypt,
	"xkms.asymmetricEncrypt":   (*Server).handleAsymmetricEncrypt,
	"xkms.asymmetricDecrypt":   (*Server).handleAsymmetricDecrypt,
	"xkms.getImportParameters": (*Server).handleGetImportParameters,
	"xkms.wrapKey":             (*Server).handleWrapKey,
	"xkms.unwrapKey":           (*Server).handleUnwrapKey,
	"xkms.importKey":           (*Server).handleImportKeyMaterial,
	"xkms.exportKey":           (*Server).handleExportKey,
	"xkms.copyKey":             (*Server).handleCopyKey,

	// Hardware-capability key operations (attestation, ECDH, server-side
	// wrap/unwrap by key ID, raw symmetric key material export). These
	// delegate entirely to the xkms service layer; see errors_keyops.go for
	// how capability-boundary errors (ErrOperationNotSupported) map onto
	// JSON-RPC error codes.
	"xkms.attestKey":         (*Server).handleAttestKey,
	"xkms.deriveKeyECDH":     (*Server).handleDeriveKeyECDH,
	"xkms.deriveKey":         (*Server).handleDeriveKey,
	"xkms.exportKeyMaterial": (*Server).handleExportKeyMaterial,
	"xkms.wrapKeyByID":       (*Server).handleWrapKeyByID,
	"xkms.unwrapKeyByID":     (*Server).handleUnwrapKeyByID,

	// XKMS certificate operations
	"xkms.saveCert":          (*Server).handleSaveCert,
	"xkms.getCert":           (*Server).handleGetCert,
	"xkms.deleteCert":        (*Server).handleDeleteCert,
	"xkms.listCerts":         (*Server).handleListCerts,
	"xkms.certExists":        (*Server).handleCertExists,
	"xkms.saveCertChain":     (*Server).handleSaveCertChain,
	"xkms.getCertChain":      (*Server).handleGetCertChain,
	"xkms.getTLSCertificate": (*Server).handleGetTLSCertificate,

	// XKMS seal operations
	"xkms.seal":    (*Server).handleSeal,
	"xkms.unseal":  (*Server).handleUnseal,
	"xkms.canSeal": (*Server).handleCanSeal,

	// XKMS PIV operations
	"xkms.listPIVSlots":         (*Server).handleListPIVSlots,
	"xkms.getPIVCertificate":    (*Server).handleGetPIVCertificate,
	"xkms.storePIVCertificate":  (*Server).handleStorePIVCertificate,
	"xkms.deletePIVCertificate": (*Server).handleDeletePIVCertificate,
	"xkms.generatePIVKey":       (*Server).handleGeneratePIVKey,
	"xkms.importPIVCertificate": (*Server).handleImportPIVCertificate,
	"xkms.exportPIVCertificate": (*Server).handleExportPIVCertificate,
	"xkms.generatePIVCSR":       (*Server).handleGeneratePIVCSR,

	// CA operations
	"xkms.ca.bundle":      (*Server).handleGetCABundle,
	"xkms.ca.certificate": (*Server).handleGetCACertificate,
	"xkms.ca.sign-csr":    (*Server).handleSignCSR,
	"xkms.ca.issue":       (*Server).handleIssueCertificate,
	"xkms.ca.revoke":      (*Server).handleRevokeCertificate,
	"xkms.ca.crl":         (*Server).handleGenerateCRL,
	"xkms.ca.is-revoked":  (*Server).handleIsRevoked,

	// TCG CA operations
	"xkms.ca.tcg.issue-ek": (*Server).handleIssueEKCertificate,
	"xkms.ca.tcg.issue-ak": (*Server).handleIssueAKCertificate,
	"xkms.ca.tcg.sign-csr": (*Server).handleSignTCGCSR,
	"xkms.ca.tcg.enroll":   (*Server).handleEnrollDevice,

	// Barrier and Shamir operations
	"barrier.initialize":           (*Server).handleBarrierInitialize,
	"barrier.initializeShamir":     (*Server).handleBarrierInitializeShamir,
	"barrier.unseal":               (*Server).handleBarrierUnseal,
	"barrier.unsealShare":          (*Server).handleBarrierUnsealShare,
	"barrier.unsealShares":         (*Server).handleBarrierUnsealShares,
	"barrier.seal":                 (*Server).handleBarrierSeal,
	"barrier.status":               (*Server).handleBarrierStatus,
	"barrier.rekey":                (*Server).handleBarrierRekey,
	"barrier.generateRecoveryKeys": (*Server).handleBarrierGenerateRecoveryKeys,
	"barrier.recoverWithKeys":      (*Server).handleBarrierRecoverWithKeys,
	"barrier.deleteRecoveryKeys":   (*Server).handleBarrierDeleteRecoveryKeys,
	"barrier.hasRecoveryKeys":      (*Server).handleBarrierHasRecoveryKeys,
	"barrier.generateRootToken":    (*Server).handleBarrierGenerateRootToken,
	"barrier.enableEncryption":     (*Server).handleBarrierEnableEncryption,

	// Trust bootstrap listener (go-xkms#632).
	"bootstrap.showKeys": (*Server).handleBootstrapShowKeys,

	// PIN management (SO PIN / user PIN / lockout). Delegate entirely to the
	// xkms service layer's composed qrdbsdk.PINBackend (go-xkms#773).
	"xkms.setSOPIN":         (*Server).handleSetSOPIN,
	"xkms.setUserPIN":       (*Server).handleSetUserPIN,
	"xkms.changeSOPIN":      (*Server).handleChangeSOPIN,
	"xkms.changeUserPIN":    (*Server).handleChangeUserPIN,
	"xkms.verifySOPIN":      (*Server).handleVerifySOPIN,
	"xkms.verifyUserPIN":    (*Server).handleVerifyUserPIN,
	"xkms.getLockoutStatus": (*Server).handleGetLockoutStatus,
	"xkms.resetLockout":     (*Server).handleResetLockout,

	// Custodian groups (Shamir share custody roster). Custodian state lives
	// in the embedded go-qrdb node, reached through the XKMS service
	// (go-xkms#773).
	"xkms.createCustodianGroup":  (*Server).handleCreateCustodianGroup,
	"xkms.getCustodianGroup":     (*Server).handleGetCustodianGroup,
	"xkms.listCustodianGroups":   (*Server).handleListCustodianGroups,
	"xkms.deleteCustodianGroup":  (*Server).handleDeleteCustodianGroup,
	"xkms.addCustodianMember":    (*Server).handleAddCustodianMember,
	"xkms.removeCustodianMember": (*Server).handleRemoveCustodianMember,
	"xkms.distributeShares":      (*Server).handleDistributeShares,

	// Tenant administration (multi-tenant lifecycle plus per-tenant
	// barrier). Delegates to the xkms service layer's composed go-qrdb
	// TenantService (go-xkms#773).
	"xkms.createTenant":             (*Server).handleCreateTenant,
	"xkms.getTenant":                (*Server).handleGetTenant,
	"xkms.listTenants":              (*Server).handleListTenants,
	"xkms.deleteTenant":             (*Server).handleDeleteTenant,
	"xkms.tenantBarrierInit":        (*Server).handleTenantBarrierInit,
	"xkms.tenantBarrierUnseal":      (*Server).handleTenantBarrierUnseal,
	"xkms.tenantBarrierStatus":      (*Server).handleTenantBarrierStatus,
	"xkms.updateTenantEntitlements": (*Server).handleUpdateTenantEntitlements,
	"xkms.updateTenantQuotas":       (*Server).handleUpdateTenantQuotas,

	// Shamir share operations. Share state lives in the embedded go-qrdb
	// node, reached through the XKMS service.
	"xkms.submitShare":              (*Server).handleSubmitShare,
	"xkms.listShares":               (*Server).handleListShares,
	"xkms.getShare":                 (*Server).handleGetShare,
	"xkms.deleteShare":              (*Server).handleDeleteShare,
	"xkms.getShareCollectionStatus": (*Server).handleGetShareCollectionStatus,

	// Audit read endpoint. Audit state lives in the embedded go-qrdb node,
	// reached through the XKMS service.
	"xkms.queryAudit": (*Server).handleQueryAudit,

	// Init ceremony operations
	"init.getStatus":          (*Server).handleGetInitStatus,
	"init.claimCertBegin":     (*Server).handleClaimCertBegin,
	"init.claimCertComplete":  (*Server).handleClaimCertComplete,
	"init.claimShareBegin":    (*Server).handleClaimShareBegin,
	"init.claimShareComplete": (*Server).handleClaimShareComplete,
	"init.signCSR":            (*Server).handleSignCSRInit,

	// Credential management operations
	"credentials.submit":   (*Server).handleCredentialSubmit,
	"credentials.strategy": (*Server).handleCredentialStrategy,

	// User management operations. xkms presents its own user model; the
	// backing store is the embedded qrdb node (see pkg/xkms/servicer_user.go).
	"user.create":          (*Server).handleCreateUser,
	"user.list":            (*Server).handleListUsers,
	"user.get":             (*Server).handleGetUser,
	"user.delete":          (*Server).handleDeleteUser,
	"user.enable":          (*Server).handleEnableUser,
	"user.disable":         (*Server).handleDisableUser,
	"user.bindCert":        (*Server).handleBindUserCert,
	"user.listCredentials": (*Server).handleListUserCredentials,

	// Invitation redemption (go-xkms#1294 part B). The FIDO2 half
	// (Begin/FinishInviteRegistration) is a named exclusion — see
	// handlers_invite.go's package comment — matching the existing
	// WebAuthn registration/authentication exclusion.
	"invite.get":         (*Server).handleGetInvite,
	"invite.pivActivate": (*Server).handleActivateInvitePIV,

	// Password store operations
	"password.add":                (*Server).handlePasswordAdd,
	"password.get":                (*Server).handlePasswordGet,
	"password.list":               (*Server).handlePasswordList,
	"password.update":             (*Server).handlePasswordUpdate,
	"password.delete":             (*Server).handlePasswordDelete,
	"password.unlock":             (*Server).handlePasswordUnlock,
	"password.lock":               (*Server).handlePasswordLock,
	"password.status":             (*Server).handlePasswordStatus,
	"password.generate":           (*Server).handlePasswordGenerate,
	"password.setAccessMode":      (*Server).handlePasswordSetAccessMode,
	"password.vault.status":       (*Server).handlePasswordVaultStatus,
	"password.vault.enroll":       (*Server).handlePasswordVaultEnroll,
	"password.vault.rotate":       (*Server).handlePasswordVaultRotate,
	"password.vault.removeFactor": (*Server).handlePasswordVaultRemoveFactor,
	"password.vault.recover":      (*Server).handlePasswordVaultRecover,

	// Platform-sealed store (machine-local sealed credential store)
	"sealStore.put":    (*Server).handleSealStorePut,
	"sealStore.get":    (*Server).handleSealStoreGet,
	"sealStore.delete": (*Server).handleSealStoreDelete,
	"sealStore.list":   (*Server).handleSealStoreList,
	"sealStore.reseal": (*Server).handleSealStoreReseal,
	"sealStore.status": (*Server).handleSealStoreStatus,

	// TPM policy management (pkg/tpmpolicy)
	"tpm.policy.create":         (*Server).handleTPMPolicyCreate,
	"tpm.policy.get":            (*Server).handleTPMPolicyGet,
	"tpm.policy.list":           (*Server).handleTPMPolicyList,
	"tpm.policy.update":         (*Server).handleTPMPolicyUpdate,
	"tpm.policy.revoke":         (*Server).handleTPMPolicyRevoke,
	"tpm.policy.verify":         (*Server).handleTPMPolicyVerify,
	"tpm.policy.delete":         (*Server).handleTPMPolicyDelete,
	"tpm.policy.objects":        (*Server).handleTPMPolicyObjects,
	"tpm.policy.autoUnseal":     (*Server).handleTPMPolicyAutoUnseal,
	"tpm.policy.setDescription": (*Server).handleTPMPolicySetDescription,
	"tpm.object.policy":         (*Server).handleTPMObjectPolicy,
	"tpm.authority.rotate":      (*Server).handleTPMAuthorityRotate,
	"xkms.getTenantTPMMode":     (*Server).handleGetTenantTPMMode,
	"xkms.setTenantTPMMode":     (*Server).handleSetTenantTPMMode,
	"xkms.tenantVTPMStatus":     (*Server).handleTenantVTPMStatus,
	"xkms.tenantVTPMStart":      (*Server).handleTenantVTPMStart,
	"xkms.tenantVTPMStop":       (*Server).handleTenantVTPMStop,

	// Server-side OIDC credentials (pkg/oidc/credential)
	"oidc.credential.create":       (*Server).handleOIDCCredentialCreate,
	"oidc.credential.import":       (*Server).handleOIDCCredentialImport,
	"oidc.credential.get":          (*Server).handleOIDCCredentialGet,
	"oidc.credential.list":         (*Server).handleOIDCCredentialList,
	"oidc.credential.delete":       (*Server).handleOIDCCredentialDelete,
	"oidc.credential.refresh":      (*Server).handleOIDCCredentialRefresh,
	"oidc.credential.token":        (*Server).handleOIDCCredentialToken,
	"oidc.credential.device.start": (*Server).handleOIDCCredentialDeviceStart,
	"oidc.credential.device.poll":  (*Server).handleOIDCCredentialDevicePoll,

	// SSH key operations
	"ssh.keys.generate": (*Server).handleSSHKeysGenerate,
	"ssh.keys.import":   (*Server).handleSSHKeysImport,
	"ssh.keys.list":     (*Server).handleSSHKeysList,
	"ssh.keys.get":      (*Server).handleSSHKeysGet,
	"ssh.keys.delete":   (*Server).handleSSHKeysDelete,
	"ssh.keys.export":   (*Server).handleSSHKeysExport,
	"ssh.keys.sign":     (*Server).handleSSHKeysSign,

	// SSH known-hosts operations
	"ssh.knownHosts.add":    (*Server).handleSSHKnownHostsAdd,
	"ssh.knownHosts.list":   (*Server).handleSSHKnownHostsList,
	"ssh.knownHosts.remove": (*Server).handleSSHKnownHostsRemove,
	"ssh.knownHosts.verify": (*Server).handleSSHKnownHostsVerify,

	// SSH authorized-keys operations
	"ssh.authorizedKeys.add":    (*Server).handleSSHAuthorizedKeysAdd,
	"ssh.authorizedKeys.get":    (*Server).handleSSHAuthorizedKeysGet,
	"ssh.authorizedKeys.list":   (*Server).handleSSHAuthorizedKeysList,
	"ssh.authorizedKeys.remove": (*Server).handleSSHAuthorizedKeysRemove,
	"ssh.authorizedKeys.emit":   (*Server).handleSSHAuthorizedKeysEmit,
	"ssh.authorizedKeys.verify": (*Server).handleSSHAuthorizedKeysVerify,
}

// Stop releases whatever server-held resources remain. It is safe to call on
// a server that was never used to serve a connection -- there is none left
// to close -- and is kept only so pkg/server's Shutdown, which holds a
// *mcp.Server reference from before the network plane was retired, can keep
// calling it unconditionally.
func (s *Server) Stop() error {
	return nil
}
