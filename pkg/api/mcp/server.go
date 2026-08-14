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

package mcp

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/correlation"
	"github.com/jeremyhahn/go-xkms/pkg/ratelimit"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/staticpw"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// Typed errors for barrier MCP handlers.
var (
	// ErrBarrierNotConfigured is returned when a barrier operation is attempted
	// on a server that does not have a barrier configured.
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

// Server represents an MCP JSON-RPC 2.0 server
type Server struct {
	addr            string
	keystore        xkms.Backend // Default keystore for backward compatibility
	xkmsService     *xkms.XKMSService
	barrier         *seal.Barrier
	barrierRegistry *seal.BarrierRegistry
	passwordManager *staticpw.TenantPasswordStoreManager
	// mu guards listener across the Start goroutine and Stop (called from the
	// embedding server's Shutdown on a different goroutine).
	mu            sync.Mutex
	listener      net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	// authorizer is the qrdb-backed authorization seam shared with the REST,
	// gRPC, and QUIC transports. It is never nil: when RBAC is disabled it is
	// a disabled Authorizer (no RBAC client) that allows every request.
	authorizer *auth.Authorizer
	// rbacEnabled mirrors Config.EnableRBAC. When false, authorizeMethod is a
	// no-op, matching the REST server's un-decorated routes and the QUIC
	// server's default (RBAC-client-less) authorizer.
	rbacEnabled bool
	logger      *slog.Logger
	rateLimiter *ratelimit.Limiter

	// sshClient is the optional SSH sub-system. When non-nil, SSH
	// JSON-RPC methods (ssh.keys.*, ssh.knownHosts.*, etc.) are
	// dispatched to it. When nil those methods return
	// ErrSSHNotConfigured.
	sshClient sdkssh.Client

	// Event subscribers
	subscribers map[net.Conn]*Subscriber
	subMutex    sync.RWMutex
}

// Subscriber represents an event subscriber
type Subscriber struct {
	conn   net.Conn
	events map[string]bool
	mutex  sync.RWMutex
}

// Config holds the MCP server configuration
type Config struct {
	Addr          string
	TLSConfig     *tls.Config
	Authenticator auth.Authenticator
	Logger        *slog.Logger
	RateLimiter   *ratelimit.Limiter
	Barrier       *seal.Barrier
	// BarrierRegistry gates per-request tenant access the same way REST,
	// gRPC, and QUIC do (see pkg/api/tenantgate). Nil disables tenant
	// enforcement.
	BarrierRegistry *seal.BarrierRegistry
	PasswordManager *staticpw.TenantPasswordStoreManager
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

// NewServer creates a new MCP JSON-RPC server. The XKMS service is injected
// via Config.XKMSService by the composition root; the constructor rejects a
// nil service so the server never starts without an initialized service.
func NewServer(config *Config) (*Server, error) {
	svc := config.XKMSService
	if svc == nil {
		return nil, ErrXKMSServiceRequired
	}

	if config.Addr == "" {
		config.Addr = "localhost:9444"
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

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:            config.Addr,
		xkmsService:     svc,
		barrier:         config.Barrier,
		barrierRegistry: config.BarrierRegistry,
		passwordManager: config.PasswordManager,
		ctx:             ctx,
		cancel:          cancel,
		tlsConfig:       config.TLSConfig,
		authenticator:   authenticator,
		authorizer:      authorizer,
		rbacEnabled:     config.EnableRBAC,
		logger:          log,
		rateLimiter:     config.RateLimiter,
		subscribers:     make(map[net.Conn]*Subscriber),
		sshClient:       config.SSHClient,
	}

	// Log if rate limiting is enabled
	if config.RateLimiter != nil && config.RateLimiter.IsEnabled() {
		log.Info("Rate limiting enabled for MCP")
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
		cancel()
		return nil, &errs.Wrapped{Msg: "failed to get default keystore", Err: err}
	}
	s.keystore = keystore

	return s, nil
}

// SetBarrier configures the barrier for the MCP server.
func (s *Server) SetBarrier(b *seal.Barrier) {
	s.barrier = b
}

// SetBarrierRegistry configures the tenant barrier registry for the MCP
// server. This allows tenant enforcement to be configured after server
// creation.
func (s *Server) SetBarrierRegistry(registry *seal.BarrierRegistry) {
	s.barrierRegistry = registry
}

// SetPasswordManager configures the password store manager for the MCP server.
func (s *Server) SetPasswordManager(pm *staticpw.TenantPasswordStoreManager) {
	s.passwordManager = pm
}

// Start starts the MCP server
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return &errs.Wrapped{Msg: fmt.Sprintf("failed to listen on %s", s.addr), Err: err}
	}

	// Wrap with TLS if configured
	if s.tlsConfig != nil {
		listener = tls.NewListener(listener, s.tlsConfig)
		s.logger.Info("MCP server listening with TLS",
			slog.String("addr", s.addr),
			slog.String("auth", s.authenticator.Name()))
	} else {
		s.logger.Info("MCP server listening",
			slog.String("addr", s.addr),
			slog.String("auth", s.authenticator.Name()))
	}

	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()

	s.wg.Add(1)
	go s.acceptConnections(listener)

	return nil
}

// acceptConnections accepts incoming TCP connections
func (s *Server) acceptConnections(listener net.Listener) {
	defer s.wg.Done()

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				s.logger.Error("Error accepting connection", slog.String("error", err.Error()))
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection handles a single client connection
func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() { _ = conn.Close() }()

	// Check rate limit at connection level
	if s.rateLimiter != nil && !s.rateLimiter.AllowConn(conn) {
		s.logger.Warn("Connection rejected due to rate limit",
			slog.String("remote_addr", conn.RemoteAddr().String()))
		return
	}

	// Authenticate the connection using TLS certificates if mTLS is configured
	ctx := s.ctx
	if s.tlsConfig != nil && s.tlsConfig.ClientAuth != tls.NoClientCert {
		if tlsConn, ok := conn.(*tls.Conn); ok {
			if err := tlsConn.Handshake(); err != nil {
				s.logger.WarnContext(ctx, "TLS handshake failed", slog.String("error", err.Error()))
				return
			}

			// Get client certificates from TLS connection
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				identity := &auth.Identity{
					Subject: cert.Subject.CommonName,
					Metadata: map[string]string{
						"auth_method": "mtls",
						"subject_dn":  cert.Subject.String(),
					},
				}
				ctx = auth.WithIdentity(ctx, identity)

				// Carry the verified peer chain on the context so operations
				// that bind to the caller's certificate -- the Security
				// Officer share claim -- can derive the thumbprint from the
				// real handshake rather than from anything the client sent.
				connState := state
				ctx = auth.WithTLSState(ctx, &connState)

				s.logger.DebugContext(ctx, "Client authenticated via mTLS",
					slog.String("subject", identity.Subject))
			}
		}
	}

	scanner := bufio.NewScanner(conn)
	encoder := json.NewEncoder(conn)

	for scanner.Scan() {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		data := scanner.Bytes()

		// Handle batch requests (array of requests)
		if len(data) > 0 && data[0] == '[' {
			var batchRequests []JSONRPCRequest
			if err := json.Unmarshal(data, &batchRequests); err != nil {
				s.sendError(encoder, nil, ErrCodeParseError, "Parse error", err)
				continue
			}

			batchResponses := make([]JSONRPCResponse, 0, len(batchRequests))
			for _, req := range batchRequests {
				response := s.handleRequest(ctx, &req, conn)
				if response != nil {
					batchResponses = append(batchResponses, *response)
				}
			}

			if len(batchResponses) > 0 {
				if err := encoder.Encode(batchResponses); err != nil {
					s.logger.Error("Error encoding batch response", slog.String("error", err.Error()))
				}
			}
			continue
		}

		// Handle single request
		var request JSONRPCRequest
		if err := json.Unmarshal(data, &request); err != nil {
			s.sendError(encoder, nil, ErrCodeParseError, "Parse error", err)
			continue
		}

		response := s.handleRequest(ctx, &request, conn)
		if response != nil {
			if err := encoder.Encode(response); err != nil {
				s.logger.Error("Error encoding response", slog.String("error", err.Error()))
			}
		}
	}

	if err := scanner.Err(); err != nil {
		s.logger.Error("Scanner error", slog.String("error", err.Error()))
	}

	// Clean up subscriber if exists
	s.subMutex.Lock()
	delete(s.subscribers, conn)
	s.subMutex.Unlock()
}

// rpcHandler dispatches a single JSON-RPC method to its handler. The *Server
// receiver is passed explicitly so the dispatch table can be populated from
// method expressions, mirroring the qrdb kvMethodHandlers pattern.
type rpcHandler func(s *Server, ctx context.Context, req *JSONRPCRequest) (interface{}, error)

// rpcMethodHandlers maps every supported JSON-RPC method to its handler for
// O(1) dispatch. It is built once at package initialization. The connection-
// bound method xkms.subscribe is intentionally absent: it requires the live
// net.Conn and is dispatched directly in handleRequest.
var rpcMethodHandlers = map[string]rpcHandler{
	// Health
	"health": (*Server).handleHealth,

	// Public algorithm discovery, mirroring the unauthenticated REST route.
	"xkms.algorithms": (*Server).handleAlgorithms,

	// XKMS key operations
	"xkms.listBackends":        (*Server).handleListBackends,
	"xkms.generateKey":         (*Server).handleGenerateKey,
	"xkms.getKey":              (*Server).handleGetKey,
	"xkms.deleteKey":           (*Server).handleDeleteKey,
	"xkms.listKeys":            (*Server).handleListKeys,
	"xkms.rotateKey":           (*Server).handleRotateKey,
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

	// Password store operations
	"password.add":      (*Server).handlePasswordAdd,
	"password.get":      (*Server).handlePasswordGet,
	"password.list":     (*Server).handlePasswordList,
	"password.update":   (*Server).handlePasswordUpdate,
	"password.delete":   (*Server).handlePasswordDelete,
	"password.unlock":   (*Server).handlePasswordUnlock,
	"password.lock":     (*Server).handlePasswordLock,
	"password.status":   (*Server).handlePasswordStatus,
	"password.generate": (*Server).handlePasswordGenerate,

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

// handleRequest processes a JSON-RPC request and returns a response
func (s *Server) handleRequest(ctx context.Context, req *JSONRPCRequest, conn net.Conn) *JSONRPCResponse {
	if req.JSONRPC != "2.0" {
		return s.makeErrorResponse(req.ID, "", ErrCodeInvalidRequest, "Invalid JSON-RPC version", nil)
	}

	// Extract or generate correlation ID
	correlationID := req.CorrelationID
	if correlationID == "" {
		correlationID = correlation.NewID()
	}
	ctx = correlation.WithCorrelationID(ctx, correlationID)

	// Log request with identity if available
	identity := auth.GetIdentity(ctx)
	subject := "anonymous"
	if identity != nil {
		subject = identity.Subject
	}
	s.logger.DebugContext(ctx, "RPC request",
		slog.String("method", req.Method),
		slog.String("subject", subject))

	// Tenant scoping runs before authorization and independent of RBAC,
	// mirroring the REST TenantMiddleware / gRPC tenant interceptor / QUIC
	// tenantMiddleware placement: it uses only the authenticated identity and
	// the barrier registry, never the RBAC authorizer.
	var tenantErr error
	ctx, tenantErr = s.tenantAccess(ctx, req.Method)
	if tenantErr != nil {
		code := ErrCodeForbidden
		var keyOpErr *KeyOpError
		if errors.As(tenantErr, &keyOpErr) {
			code = keyOpErr.Code
		}
		return s.makeErrorResponse(req.ID, correlationID, code, tenantErr.Error(), nil)
	}

	// Authorize before dispatch. Every privileged method is gated here rather
	// than inside each handler so no dispatch path — the rpcMethodHandlers
	// table, the connection-bound xkms.subscribe, or the build-tagged FROST
	// namespace — can reach the service layer unauthorized.
	if authzErr := s.authorizeMethod(ctx, req.Method); authzErr != nil {
		code := ErrCodeForbidden
		var keyOpErr *KeyOpError
		if errors.As(authzErr, &keyOpErr) {
			code = keyOpErr.Code
		}
		s.logger.WarnContext(ctx, "RPC request denied",
			slog.String("method", req.Method),
			slog.String("subject", subject),
			slog.String("error", authzErr.Error()))
		return s.makeErrorResponse(req.ID, correlationID, code, authzErr.Error(), nil)
	}

	// Route to appropriate handler
	var result interface{}
	var err error

	// Try FROST methods first
	if frostResult, frostErr, handled := s.routeFrostMethods(ctx, req); handled {
		result = frostResult
		err = frostErr
		if err != nil {
			s.logger.WarnContext(ctx, "RPC request failed",
				slog.String("method", req.Method),
				slog.String("subject", subject),
				slog.String("error", err.Error()))
			return s.makeErrorResponse(req.ID, correlationID, ErrCodeInternalError, err.Error(), nil)
		}

		// Don't send response for notifications (no ID)
		if req.ID == nil {
			return nil
		}

		return &JSONRPCResponse{
			JSONRPC:       "2.0",
			Result:        result,
			ID:            req.ID,
			CorrelationID: correlationID,
		}
	}

	// xkms.subscribe is the only method that needs the live connection (to
	// register the event subscriber), so it is dispatched directly. Every
	// other JSON-RPC method is routed through the rpcMethodHandlers table.
	if handler, ok := rpcMethodHandlers[req.Method]; ok {
		result, err = handler(s, ctx, req)
	} else if req.Method == "xkms.subscribe" {
		result, err = s.handleSubscribe(ctx, req, conn)
	} else {
		return s.makeErrorResponse(req.ID, correlationID, ErrCodeMethodNotFound, "Method not found", nil)
	}

	if err != nil {
		s.logger.WarnContext(ctx, "RPC request failed",
			slog.String("method", req.Method),
			slog.String("subject", subject),
			slog.String("error", err.Error()))

		// A handler that delegated to the key-operations service layer
		// (attestation, ECDH, wrap/unwrap by ID, key material export)
		// carries its capability-boundary classification in a *KeyOpError;
		// every other handler falls back to the generic internal-error code.
		code := ErrCodeInternalError
		var keyOpErr *KeyOpError
		if errors.As(err, &keyOpErr) {
			code = keyOpErr.Code
		}
		return s.makeErrorResponse(req.ID, correlationID, code, err.Error(), nil)
	}

	// Don't send response for notifications (no ID)
	if req.ID == nil {
		return nil
	}

	return &JSONRPCResponse{
		JSONRPC:       "2.0",
		Result:        result,
		ID:            req.ID,
		CorrelationID: correlationID,
	}
}

// sendError sends an error response
func (s *Server) sendError(encoder *json.Encoder, id interface{}, code int, message string, data interface{}) {
	response := s.makeErrorResponse(id, "", code, message, data)
	if err := encoder.Encode(response); err != nil {
		s.logger.Error("Error encoding error response", slog.String("error", err.Error()))
	}
}

// makeErrorResponse creates an error response
func (s *Server) makeErrorResponse(id interface{}, correlationID string, code int, message string, data interface{}) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		Error: &JSONRPCError{
			Code:    code,
			Message: message,
			Data:    data,
		},
		ID:            id,
		CorrelationID: correlationID,
	}
}

// NotifyEvent sends an event notification to all subscribers
func (s *Server) NotifyEvent(event string, keyID string, data interface{}) {
	s.subMutex.RLock()
	defer s.subMutex.RUnlock()

	notification := JSONRPCNotification{
		JSONRPC: "2.0",
		Method:  event,
		Params: EventNotification{
			Event: event,
			KeyID: keyID,
			Data:  data,
		},
	}

	for conn, sub := range s.subscribers {
		sub.mutex.RLock()
		shouldNotify := sub.events[event]
		sub.mutex.RUnlock()

		if shouldNotify {
			encoder := json.NewEncoder(conn)
			if err := encoder.Encode(notification); err != nil {
				s.logger.Error("Error sending notification", slog.String("error", err.Error()))
			}
		}
	}
}

// Stop stops the MCP server
func (s *Server) Stop() error {
	s.logger.Info("Stopping MCP server")
	s.cancel()

	s.mu.Lock()
	ln := s.listener
	s.mu.Unlock()
	if ln != nil {
		if err := ln.Close(); err != nil {
			s.logger.Error("Failed to close listener", slog.String("error", err.Error()))
			return err
		}
	}

	s.wg.Wait()
	s.logger.Info("MCP server stopped")
	return nil
}
