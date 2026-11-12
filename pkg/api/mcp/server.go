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
// The package owns the dispatch core -- the rpcMethods table, the
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

// rpcMethods registers every supported JSON-RPC method for O(1) dispatch:
// its handler and, through handle, the permission authorizeMethod enforces,
// or, through handlePublic, that it is public. It is built once at package
// initialization and is the only place a method's permission is declared;
// MCPToolPermissions and the module's role grants are derived from it.
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
var rpcMethods = map[string]rpcMethod{
	// Liveness is public, matching the REST RBAC middleware's SkipPaths
	// ("/health", "/health/live", "/health/ready", "/health/startup").
	"health": handlePublic((*Server).handleHealth),

	// Algorithm discovery reports compiled-in capability and reads no state.
	// REST serves it unauthenticated (pkg/api/rest/server.go, outside the
	// authenticated /api/v1 group), so gating it here would make the same
	// question answerable on one transport and not another.
	"xkms.algorithms": handlePublic((*Server).handleAlgorithms),

	// Backends.
	"xkms.listBackends": handle(auth.ResourceBackends, auth.ActionList, (*Server).handleListBackends),
	"xkms.getBackend":   handle(auth.ResourceBackends, auth.ActionRead, (*Server).handleGetBackend),

	// Key lifecycle and crypto operations -- pkg/api/grpc/service.go's
	// s.authorize(ctx, "keys", ...) calls.
	"xkms.generateKey": handle(auth.ResourceKeys, auth.ActionCreate, (*Server).handleGenerateKey),
	"xkms.getKey":      handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleGetKey),
	"xkms.deleteKey":   handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleDeleteKey),
	"xkms.listKeys":    handle(auth.ResourceKeys, auth.ActionList, (*Server).handleListKeys),
	"xkms.rotateKey":   handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleRotateKey),

	// OTA image keys: one ES256 signing key per trusted-firmware board id,
	// under the same permissions as any other key.
	"xkms.createOTAImageKey": handle(auth.ResourceKeys, auth.ActionCreate, (*Server).handleCreateOTAImageKey),
	"xkms.rotateOTAImageKey": handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleRotateOTAImageKey),
	"xkms.signOTAImage":      handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleSignOTAImage),

	// Key versions: listing reads like listing keys; enabling and disabling
	// versions is rotation lifecycle management; retiring destroys a
	// version's key material, as deleting a key does.
	"xkms.listKeyVersions":       handle(auth.ResourceKeys, auth.ActionList, (*Server).handleListKeyVersions),
	"xkms.enableKeyVersion":      handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleEnableKeyVersion),
	"xkms.disableKeyVersion":     handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleDisableKeyVersion),
	"xkms.retireKeyVersion":      handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleRetireKeyVersion),
	"xkms.enableAllKeyVersions":  handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleEnableAllKeyVersions),
	"xkms.disableAllKeyVersions": handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleDisableAllKeyVersions),
	"xkms.rotateScopeKeys":       handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleRotateScopeKeys),

	// Crypto utility operations
	"xkms.rewrap":                 handle(auth.ResourceKeys, auth.ActionDecrypt, (*Server).handleRewrap),
	"xkms.encryptBatch":           handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleEncryptBatch),
	"xkms.decryptBatch":           handle(auth.ResourceKeys, auth.ActionDecrypt, (*Server).handleDecryptBatch),
	"xkms.generateDataKey":        handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleGenerateDataKey),
	"xkms.generateWrappedDataKey": handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleGenerateWrappedDataKey),
	"xkms.generateHMAC":           handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleGenerateHMAC),
	"xkms.verifyHMAC":             handle(auth.ResourceKeys, auth.ActionVerify, (*Server).handleVerifyHMAC),
	"xkms.generateRandom":         handle(auth.ResourceKeys, auth.ActionVerify, (*Server).handleGenerateRandom),
	"xkms.hash":                   handle(auth.ResourceKeys, auth.ActionVerify, (*Server).handleHash),

	// Key management (go-xkms#1681), matching pkg/api/rest/routes.go's
	// decorators: reads are keys:get, removals keys:delete, changes
	// keys:rotate; backend probes are backends:read.
	"xkms.getPublicKey":            handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleGetPublicKey),
	"xkms.revokeKey":               handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleRevokeKey),
	"xkms.updateKeyStatus":         handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleUpdateKeyStatus),
	"xkms.getKeyMetadata":          handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleGetKeyMetadata),
	"xkms.updateKeyMetadata":       handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleUpdateKeyMetadata),
	"xkms.setKeyPolicy":            handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleSetKeyPolicy),
	"xkms.getKeyPolicy":            handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleGetKeyPolicy),
	"xkms.deleteKeyPolicy":         handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleDeleteKeyPolicy),
	"xkms.setKeyRotationPolicy":    handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleSetKeyRotationPolicy),
	"xkms.getKeyRotationPolicy":    handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleGetKeyRotationPolicy),
	"xkms.deleteKeyRotationPolicy": handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleDeleteKeyRotationPolicy),
	"xkms.getSupportedAlgorithms":  handle(auth.ResourceKeys, auth.ActionList, (*Server).handleGetSupportedAlgorithms),
	"xkms.backendStatus":           handle(auth.ResourceBackends, auth.ActionRead, (*Server).handleBackendStatus),
	"xkms.backendTest":             handle(auth.ResourceBackends, auth.ActionRead, (*Server).handleBackendTest),
	"xkms.setKeySafety":            handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleSetKeySafety),
	"xkms.clearKeySafety":          handle(auth.ResourceKeys, auth.ActionRotate, (*Server).handleClearKeySafety),
	"xkms.safetyCheck":             handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleSafetyCheck),
	"xkms.safetyReport":            handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleSafetyReport),

	"xkms.sign":                handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleSign),
	"xkms.verify":              handle(auth.ResourceKeys, auth.ActionVerify, (*Server).handleVerify),
	"xkms.encrypt":             handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleEncrypt),
	"xkms.decrypt":             handle(auth.ResourceKeys, auth.ActionDecrypt, (*Server).handleDecrypt),
	"xkms.asymmetricEncrypt":   handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleAsymmetricEncrypt),
	"xkms.asymmetricDecrypt":   handle(auth.ResourceKeys, auth.ActionDecrypt, (*Server).handleAsymmetricDecrypt),
	"xkms.getImportParameters": handle(auth.ResourceKeys, auth.ActionImport, (*Server).handleGetImportParameters),
	"xkms.wrapKey":             handle(auth.ResourceKeys, auth.ActionWrap, (*Server).handleWrapKey),
	"xkms.unwrapKey":           handle(auth.ResourceKeys, auth.ActionUnwrap, (*Server).handleUnwrapKey),
	"xkms.importKey":           handle(auth.ResourceKeys, auth.ActionImport, (*Server).handleImportKeyMaterial),
	"xkms.exportKey":           handle(auth.ResourceKeys, auth.ActionExport, (*Server).handleExportKey),
	"xkms.copyKey":             handle(auth.ResourceKeys, auth.ActionCreate, (*Server).handleCopyKey),

	// Hardware-capability key operations (attestation, ECDH, server-side
	// wrap/unwrap by key ID, raw symmetric key material export), matching
	// pkg/api/rest/routes.go's decorators. These delegate entirely to the
	// xkms service layer; see errors_keyops.go for how capability-boundary
	// errors (ErrOperationNotSupported) map onto JSON-RPC error codes.
	// xkms.deriveKey is gRPC's DeriveKey (go-xkms#773); REST carries no route
	// for it.
	"xkms.attestKey":         handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleAttestKey),
	"xkms.deriveKeyECDH":     handle(auth.ResourceKeys, auth.ActionDerive, (*Server).handleDeriveKeyECDH),
	"xkms.deriveKey":         handle(auth.ResourceKeys, auth.ActionDerive, (*Server).handleDeriveKey),
	"xkms.exportKeyMaterial": handle(auth.ResourceKeys, auth.ActionExport, (*Server).handleExportKeyMaterial),
	"xkms.wrapKeyByID":       handle(auth.ResourceKeys, auth.ActionWrap, (*Server).handleWrapKeyByID),
	"xkms.unwrapKeyByID":     handle(auth.ResourceKeys, auth.ActionUnwrap, (*Server).handleUnwrapKeyByID),

	// Certificate storage.
	"xkms.saveCert":          handle(auth.ResourceCerts, auth.ActionEnroll, (*Server).handleSaveCert),
	"xkms.getCert":           handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGetCert),
	"xkms.deleteCert":        handle(auth.ResourceCerts, auth.ActionRevoke, (*Server).handleDeleteCert),
	"xkms.listCerts":         handle(auth.ResourceCerts, auth.ActionList, (*Server).handleListCerts),
	"xkms.certExists":        handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleCertExists),
	"xkms.saveCertChain":     handle(auth.ResourceCerts, auth.ActionEnroll, (*Server).handleSaveCertChain),
	"xkms.getCertChain":      handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGetCertChain),
	"xkms.getTLSCertificate": handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGetTLSCertificate),

	// Hardware sealing -- gRPC's Seal/Unseal/CanSeal RPCs, identical to the
	// REST /seal, /unseal, /seal/capability decorators.
	"xkms.seal":    handle(auth.ResourceKeys, auth.ActionEncrypt, (*Server).handleSeal),
	"xkms.unseal":  handle(auth.ResourceKeys, auth.ActionDecrypt, (*Server).handleUnseal),
	"xkms.canSeal": handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleCanSeal),

	// PIV slots -- pkg/api/grpc/service_piv.go.
	"xkms.listPIVSlots":         handle(auth.ResourcePIV, auth.ActionRead, (*Server).handleListPIVSlots),
	"xkms.getPIVCertificate":    handle(auth.ResourcePIV, auth.ActionRead, (*Server).handleGetPIVCertificate),
	"xkms.storePIVCertificate":  handle(auth.ResourcePIV, auth.ActionWrite, (*Server).handleStorePIVCertificate),
	"xkms.deletePIVCertificate": handle(auth.ResourcePIV, auth.ActionDelete, (*Server).handleDeletePIVCertificate),
	"xkms.generatePIVKey":       handle(auth.ResourcePIV, auth.ActionWrite, (*Server).handleGeneratePIVKey),
	"xkms.importPIVCertificate": handle(auth.ResourcePIV, auth.ActionWrite, (*Server).handleImportPIVCertificate),
	"xkms.exportPIVCertificate": handle(auth.ResourcePIV, auth.ActionRead, (*Server).handleExportPIVCertificate),
	"xkms.generatePIVCSR":       handle(auth.ResourcePIV, auth.ActionUse, (*Server).handleGeneratePIVCSR),

	// Certificate authority -- pkg/api/grpc/service_ca.go.
	"xkms.ca.bundle":      handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGetCABundle),
	"xkms.ca.certificate": handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGetCACertificate),
	"xkms.ca.sign-csr":    handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleSignCSR),
	"xkms.ca.issue":       handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleIssueCertificate),
	"xkms.ca.revoke":      handle(auth.ResourceCerts, auth.ActionRevoke, (*Server).handleRevokeCertificate),
	"xkms.ca.crl":         handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleGenerateCRL),
	"xkms.ca.is-revoked":  handle(auth.ResourceCerts, auth.ActionRead, (*Server).handleIsRevoked),

	// TCG certificate authority -- pkg/api/grpc/service_ca_tcg.go.
	"xkms.ca.tcg.issue-ek":  handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleIssueEKCertificate),
	"xkms.ca.tcg.issue-ak":  handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleIssueAKCertificate),
	"xkms.ca.tcg.sign-csr":  handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleSignTCGCSR),
	"xkms.ca.tcg.enroll":    handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleEnrollDevice),
	"xkms.ca.tcg.issue-lak": handle(auth.ResourceCerts, auth.ActionIssue, (*Server).handleIssueLAKCertificate),

	// Trust bootstrap listener (go-xkms#632).
	"bootstrap.showKeys": handle(auth.ResourceBootstrap, auth.ActionRead, (*Server).handleBootstrapShowKeys),

	// PIN management (SO PIN / user PIN / lockout) -- pkg/api/grpc/
	// service_pin.go's s.authorize(ctx, auth.ResourcePIN, ...) calls. Delegates
	// entirely to the xkms service layer's composed qrdbsdk.PINBackend
	// (go-xkms#773).
	"xkms.setSOPIN":         handle(auth.ResourcePIN, auth.ActionWrite, (*Server).handleSetSOPIN),
	"xkms.setUserPIN":       handle(auth.ResourcePIN, auth.ActionWrite, (*Server).handleSetUserPIN),
	"xkms.changeSOPIN":      handle(auth.ResourcePIN, auth.ActionWrite, (*Server).handleChangeSOPIN),
	"xkms.changeUserPIN":    handle(auth.ResourcePIN, auth.ActionWrite, (*Server).handleChangeUserPIN),
	"xkms.verifySOPIN":      handle(auth.ResourcePIN, auth.ActionRead, (*Server).handleVerifySOPIN),
	"xkms.verifyUserPIN":    handle(auth.ResourcePIN, auth.ActionRead, (*Server).handleVerifyUserPIN),
	"xkms.getLockoutStatus": handle(auth.ResourcePIN, auth.ActionRead, (*Server).handleGetLockoutStatus),
	"xkms.resetLockout":     handle(auth.ResourcePIN, auth.ActionWrite, (*Server).handleResetLockout),

	// Tenant administration -- pkg/api/grpc/service_tenant.go's s.authorize
	// calls (go-xkms#773), delegating to the xkms service layer's composed
	// go-qrdb TenantService. Tenant metadata CRUD carries tenants:*;
	// entitlements and quotas are plan management and carry their own qrdb
	// permissions, never tenants:update.
	"xkms.createTenant":             handle(auth.ResourceTenants, auth.ActionCreate, (*Server).handleCreateTenant),
	"xkms.getTenant":                handle(auth.ResourceTenants, auth.ActionRead, (*Server).handleGetTenant),
	"xkms.listTenants":              handle(auth.ResourceTenants, auth.ActionList, (*Server).handleListTenants),
	"xkms.deleteTenant":             handle(auth.ResourceTenants, auth.ActionDelete, (*Server).handleDeleteTenant),
	"xkms.updateTenantEntitlements": handle(auth.ResourceTenants, auth.ActionSetEntitlements, (*Server).handleUpdateTenantEntitlements),
	"xkms.updateTenantQuotas":       handle(auth.ResourceTenants, auth.ActionSetQuotas, (*Server).handleUpdateTenantQuotas),

	// Credential submission -- pkg/api/rest/routes.go's /credentials
	// decorators.
	"credentials.submit":   handle(auth.ResourceCredentials, auth.ActionSubmit, (*Server).handleCredentialSubmit),
	"credentials.strategy": handle(auth.ResourceCredentials, auth.ActionStrategy, (*Server).handleCredentialStrategy),

	// User management. xkms presents its own user model; the backing store is
	// the embedded qrdb node (see pkg/xkms/servicer_user.go). Mirrors
	// pkg/api/rest/routes.go's /api/v1/users decorators: create/list/read/
	// delete carry their ordinary CRUD actions, bindCert carries update since
	// it mutates an existing user's state rather than replacing it.
	// enable/disable carry qrdb's own users:enable/users:disable
	// (go-xkms#1249), matching gRPC's EnableUser/DisableUser RPCs and REST's
	// .../enable and .../disable routes.
	"user.create":          handle(auth.ResourceUsers, auth.ActionCreate, (*Server).handleCreateUser),
	"user.list":            handle(auth.ResourceUsers, auth.ActionList, (*Server).handleListUsers),
	"user.get":             handle(auth.ResourceUsers, auth.ActionRead, (*Server).handleGetUser),
	"user.delete":          handle(auth.ResourceUsers, auth.ActionDelete, (*Server).handleDeleteUser),
	"user.enable":          handle(auth.ResourceUsers, auth.ActionEnable, (*Server).handleEnableUser),
	"user.disable":         handle(auth.ResourceUsers, auth.ActionDisable, (*Server).handleDisableUser),
	"user.bindCert":        handle(auth.ResourceUsers, auth.ActionUpdate, (*Server).handleBindUserCert),
	"user.listCredentials": handle(auth.ResourceUsers, auth.ActionRead, (*Server).handleListUserCredentials),

	// Invitation redemption (go-xkms#1294 part B) is public: there is no
	// credential yet to authenticate a request with. REST serves the same two
	// methods (GetInvite, ActivateInvitePIV) unauthenticated
	// (pkg/api/rest/handlers_invite.go, GroupInvite), so the transports
	// agree. The FIDO2 half (Begin/FinishInviteRegistration) is a named
	// exclusion -- see handlers_invite.go's package comment -- matching the
	// WebAuthn registration/authentication exclusion.
	"invite.get":         handlePublic((*Server).handleGetInvite),
	"invite.pivActivate": handlePublic((*Server).handleActivateInvitePIV),

	// Password store -- pkg/api/grpc/service_password.go and the matching
	// pkg/api/rest/routes.go /passwords decorators. The caller's personal
	// vault: reading it is passwords:read, managing one's own factors is
	// gated with the session verb, passwords:unlock.
	"password.add":                handle(auth.ResourcePasswords, auth.ActionWrite, (*Server).handlePasswordAdd),
	"password.get":                handle(auth.ResourcePasswords, auth.ActionRead, (*Server).handlePasswordGet),
	"password.list":               handle(auth.ResourcePasswords, auth.ActionRead, (*Server).handlePasswordList),
	"password.update":             handle(auth.ResourcePasswords, auth.ActionWrite, (*Server).handlePasswordUpdate),
	"password.delete":             handle(auth.ResourcePasswords, auth.ActionDelete, (*Server).handlePasswordDelete),
	"password.unlock":             handle(auth.ResourcePasswords, auth.ActionUnlock, (*Server).handlePasswordUnlock),
	"password.lock":               handle(auth.ResourcePasswords, auth.ActionLock, (*Server).handlePasswordLock),
	"password.status":             handle(auth.ResourcePasswords, auth.ActionRead, (*Server).handlePasswordStatus),
	"password.generate":           handle(auth.ResourcePasswords, auth.ActionGenerate, (*Server).handlePasswordGenerate),
	"password.setAccessMode":      handle(auth.ResourcePasswords, auth.ActionWrite, (*Server).handlePasswordSetAccessMode),
	"password.vault.status":       handle(auth.ResourcePasswords, auth.ActionRead, (*Server).handlePasswordVaultStatus),
	"password.vault.enroll":       handle(auth.ResourcePasswords, auth.ActionUnlock, (*Server).handlePasswordVaultEnroll),
	"password.vault.rotate":       handle(auth.ResourcePasswords, auth.ActionUnlock, (*Server).handlePasswordVaultRotate),
	"password.vault.removeFactor": handle(auth.ResourcePasswords, auth.ActionUnlock, (*Server).handlePasswordVaultRemoveFactor),
	"password.vault.recover":      handle(auth.ResourcePasswords, auth.ActionUnlock, (*Server).handlePasswordVaultRecover),

	// Platform-sealed store (machine-local sealed credential store). Secrets
	// sealed here are key-protection material, so the actions mirror the
	// per-verb keys:* pairs every other transport's SealStore* handlers use
	// (go-xkms#1249): put stores a new value under a name (create), reseal
	// re-wraps an existing value in place without changing it (update), and
	// status reports store-wide state the same way get reports one secret's.
	"sealStore.put":    handle(auth.ResourceKeys, auth.ActionCreate, (*Server).handleSealStorePut),
	"sealStore.get":    handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleSealStoreGet),
	"sealStore.delete": handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleSealStoreDelete),
	"sealStore.list":   handle(auth.ResourceKeys, auth.ActionList, (*Server).handleSealStoreList),
	"sealStore.reseal": handle(auth.ResourceKeys, auth.ActionUpdate, (*Server).handleSealStoreReseal),
	"sealStore.status": handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleSealStoreStatus),

	// TPM policy management (pkg/tpmpolicy) -- pkg/auth.ResourceTPMPolicy, a
	// resource family go-qrdb's canonical registry does not declare upstream;
	// xkms owns it and scopes it in pkg/apimodule/module_scopes.go. Mirrors
	// the gRPC TPMPolicy* RPCs' (qrdb.v1.permission) options one-for-one. A
	// tenant's TPM mode and vTPM are system-scope only.
	"tpm.policy.create":         handle(auth.ResourceTPMPolicy, auth.ActionCreate, (*Server).handleTPMPolicyCreate),
	"tpm.policy.get":            handle(auth.ResourceTPMPolicy, auth.ActionGet, (*Server).handleTPMPolicyGet),
	"tpm.policy.list":           handle(auth.ResourceTPMPolicy, auth.ActionList, (*Server).handleTPMPolicyList),
	"tpm.policy.update":         handle(auth.ResourceTPMPolicy, auth.ActionUpdate, (*Server).handleTPMPolicyUpdate),
	"tpm.policy.revoke":         handle(auth.ResourceTPMPolicy, auth.ActionRevoke, (*Server).handleTPMPolicyRevoke),
	"tpm.policy.verify":         handle(auth.ResourceTPMPolicy, auth.ActionVerify, (*Server).handleTPMPolicyVerify),
	"tpm.policy.delete":         handle(auth.ResourceTPMPolicy, auth.ActionDelete, (*Server).handleTPMPolicyDelete),
	"tpm.policy.objects":        handle(auth.ResourceTPMPolicy, auth.ActionGet, (*Server).handleTPMPolicyObjects),
	"tpm.policy.autoUnseal":     handle(auth.ResourceTPMPolicy, auth.ActionUpdate, (*Server).handleTPMPolicyAutoUnseal),
	"tpm.policy.setDescription": handle(auth.ResourceTPMPolicy, auth.ActionUpdate, (*Server).handleTPMPolicySetDescription),
	"tpm.object.policy":         handle(auth.ResourceTPMPolicy, auth.ActionGet, (*Server).handleTPMObjectPolicy),
	"tpm.authority.rotate":      handle(auth.ResourceTPMPolicy, auth.ActionRotate, (*Server).handleTPMAuthorityRotate),
	"xkms.getTenantTPMMode":     handle(auth.ResourceTenants, auth.ActionRead, (*Server).handleGetTenantTPMMode),
	"xkms.setTenantTPMMode":     handle(auth.ResourceTenants, auth.ActionSetTPMMode, (*Server).handleSetTenantTPMMode),
	"xkms.tenantVTPMStatus":     handle(auth.ResourceTenants, auth.ActionRead, (*Server).handleTenantVTPMStatus),
	"xkms.tenantVTPMStart":      handle(auth.ResourceTenants, auth.ActionSetTPMMode, (*Server).handleTenantVTPMStart),
	"xkms.tenantVTPMStop":       handle(auth.ResourceTenants, auth.ActionSetTPMMode, (*Server).handleTenantVTPMStop),

	// Platform trust roots (pkg/attestation/truststore), matching the
	// gRPC/REST/Unix TrustRoot* handlers.
	"trust.root.list":       handle(auth.ResourceTrustRoots, auth.ActionList, (*Server).handleTrustRootList),
	"trust.root.get":        handle(auth.ResourceTrustRoots, auth.ActionGet, (*Server).handleTrustRootGet),
	"trust.root.import":     handle(auth.ResourceTrustRoots, auth.ActionImport, (*Server).handleTrustRootImport),
	"trust.root.quarantine": handle(auth.ResourceTrustRoots, auth.ActionUpdate, (*Server).handleTrustRootQuarantine),
	"trust.root.remove":     handle(auth.ResourceTrustRoots, auth.ActionDelete, (*Server).handleTrustRootRemove),

	// Server-side OIDC credentials (pkg/oidc/credential) --
	// pkg/auth.ResourceOIDCCredentials, an xkms-owned resource family scoped
	// in pkg/apimodule/module_scopes.go. Mirrors the gRPC OIDCCredential*
	// RPCs' (qrdb.v1.permission) options one-for-one: importing tokens,
	// refreshing and a device login all change the login (update), and
	// reading a current access token is its own action, token.
	"oidc.credential.create":       handle(auth.ResourceOIDCCredentials, auth.ActionCreate, (*Server).handleOIDCCredentialCreate),
	"oidc.credential.import":       handle(auth.ResourceOIDCCredentials, auth.ActionUpdate, (*Server).handleOIDCCredentialImport),
	"oidc.credential.get":          handle(auth.ResourceOIDCCredentials, auth.ActionGet, (*Server).handleOIDCCredentialGet),
	"oidc.credential.list":         handle(auth.ResourceOIDCCredentials, auth.ActionList, (*Server).handleOIDCCredentialList),
	"oidc.credential.delete":       handle(auth.ResourceOIDCCredentials, auth.ActionDelete, (*Server).handleOIDCCredentialDelete),
	"oidc.credential.refresh":      handle(auth.ResourceOIDCCredentials, auth.ActionUpdate, (*Server).handleOIDCCredentialRefresh),
	"oidc.credential.token":        handle(auth.ResourceOIDCCredentials, auth.ActionToken, (*Server).handleOIDCCredentialToken),
	"oidc.credential.device.start": handle(auth.ResourceOIDCCredentials, auth.ActionUpdate, (*Server).handleOIDCCredentialDeviceStart),
	"oidc.credential.device.poll":  handle(auth.ResourceOIDCCredentials, auth.ActionUpdate, (*Server).handleOIDCCredentialDevicePoll),

	// Repository signing keys (go-xkms#1697) --
	// pkg/auth.ResourceAttestationSigningKeys, an xkms-owned resource family
	// scoped in pkg/apimodule/module_scopes.go. Mirrors the gRPC SigningKey
	// RPCs' (qrdb.v1.permission) options one-for-one: changing a binding is
	// bind, reading one or resolving a repository's key is get.
	"attestation.signing_key.set":     handle(auth.ResourceAttestationSigningKeys, auth.ActionBind, (*Server).handleSigningKeySet),
	"attestation.signing_key.get":     handle(auth.ResourceAttestationSigningKeys, auth.ActionGet, (*Server).handleSigningKeyGet),
	"attestation.signing_key.list":    handle(auth.ResourceAttestationSigningKeys, auth.ActionList, (*Server).handleSigningKeyList),
	"attestation.signing_key.delete":  handle(auth.ResourceAttestationSigningKeys, auth.ActionBind, (*Server).handleSigningKeyDelete),
	"attestation.signing_key.resolve": handle(auth.ResourceAttestationSigningKeys, auth.ActionGet, (*Server).handleSigningKeyResolve),
	// pkg/auth.ResourceAttestationVerdicts, the continuous attestation
	// verdicts (go-xkms#2088). Mirrors the gRPC verdict RPCs'
	// (qrdb.v1.permission) options one-for-one: re-attesting records a new
	// verdict, so it is create.
	"attestation.verdict.list":     handle(auth.ResourceAttestationVerdicts, auth.ActionList, (*Server).handleVerdictList),
	"attestation.verdict.latest":   handle(auth.ResourceAttestationVerdicts, auth.ActionGet, (*Server).handleVerdictLatest),
	"attestation.verdict.reattest": handle(auth.ResourceAttestationVerdicts, auth.ActionCreate, (*Server).handleVerdictReattest),

	// Attested-caller evidence (pkg/attestation/peergate) --
	// pkg/auth.ResourcePeerAttestation, an xkms-owned resource family scoped
	// in pkg/apimodule/module_scopes.go and exempt from the gate itself.
	// Mirrors the gRPC PeerAttestationChallenge / SubmitPeerAttestation RPCs.
	"peer.attestation.challenge": handle(auth.ResourcePeerAttestation, auth.ActionChallenge, (*Server).handlePeerAttestationChallenge),
	"peer.attestation.submit":    handle(auth.ResourcePeerAttestation, auth.ActionSubmit, (*Server).handlePeerAttestationSubmit),

	// SSH keys, known hosts and authorized keys -- pkg/api/grpc/
	// service_ssh.go and pkg/api/rest/routes.go's /xkms/v1/ssh decorators.
	"ssh.keys.generate": handle(auth.ResourceSSH, auth.ActionWrite, (*Server).handleSSHKeysGenerate),
	"ssh.keys.import":   handle(auth.ResourceSSH, auth.ActionWrite, (*Server).handleSSHKeysImport),
	"ssh.keys.list":     handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHKeysList),
	"ssh.keys.get":      handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHKeysGet),
	"ssh.keys.delete":   handle(auth.ResourceSSH, auth.ActionDelete, (*Server).handleSSHKeysDelete),
	"ssh.keys.export":   handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHKeysExport),
	"ssh.keys.sign":     handle(auth.ResourceSSH, auth.ActionWrite, (*Server).handleSSHKeysSign),

	"ssh.knownHosts.add":    handle(auth.ResourceSSH, auth.ActionWrite, (*Server).handleSSHKnownHostsAdd),
	"ssh.knownHosts.list":   handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHKnownHostsList),
	"ssh.knownHosts.remove": handle(auth.ResourceSSH, auth.ActionDelete, (*Server).handleSSHKnownHostsRemove),
	"ssh.knownHosts.verify": handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHKnownHostsVerify),

	"ssh.authorizedKeys.add":    handle(auth.ResourceSSH, auth.ActionWrite, (*Server).handleSSHAuthorizedKeysAdd),
	"ssh.authorizedKeys.get":    handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHAuthorizedKeysGet),
	"ssh.authorizedKeys.list":   handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHAuthorizedKeysList),
	"ssh.authorizedKeys.remove": handle(auth.ResourceSSH, auth.ActionDelete, (*Server).handleSSHAuthorizedKeysRemove),
	"ssh.authorizedKeys.emit":   handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHAuthorizedKeysEmit),
	"ssh.authorizedKeys.verify": handle(auth.ResourceSSH, auth.ActionRead, (*Server).handleSSHAuthorizedKeysVerify),

	// FROST threshold signatures -- pkg/api/grpc/service_frost.go gates the
	// FROST surface with the ordinary keys:* actions. The handlers live
	// behind the `frost` build tag (handlers_frost.go); without it they
	// answer "not compiled" (handlers_frost_stub.go). Registering them here,
	// untagged, means no build can ship an unenforced FROST surface.
	"frost.generateKey":    handle(auth.ResourceKeys, auth.ActionCreate, (*Server).handleFrostGenerateKey),
	"frost.importKey":      handle(auth.ResourceKeys, auth.ActionImport, (*Server).handleFrostImportKey),
	"frost.listKeys":       handle(auth.ResourceKeys, auth.ActionList, (*Server).handleFrostListKeys),
	"frost.getKey":         handle(auth.ResourceKeys, auth.ActionGet, (*Server).handleFrostGetKey),
	"frost.deleteKey":      handle(auth.ResourceKeys, auth.ActionDelete, (*Server).handleFrostDeleteKey),
	"frost.generateNonces": handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleFrostGenerateNonces),
	"frost.signRound":      handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleFrostSignRound),
	"frost.aggregate":      handle(auth.ResourceKeys, auth.ActionSign, (*Server).handleFrostAggregate),
	"frost.verify":         handle(auth.ResourceKeys, auth.ActionVerify, (*Server).handleFrostVerify),
}

// Stop releases whatever server-held resources remain. It is safe to call on
// a server that was never used to serve a connection -- there is none left
// to close -- and is kept only so pkg/server's Shutdown, which holds a
// *mcp.Server reference from before the network plane was retired, can keep
// calling it unconditionally.
func (s *Server) Stop() error {
	return nil
}
