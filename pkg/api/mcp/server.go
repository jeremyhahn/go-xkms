// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/jeremyhahn/go-keychain/pkg/adapters/auth"
	"github.com/jeremyhahn/go-keychain/pkg/correlation"
	"github.com/jeremyhahn/go-keychain/pkg/keychain"
	"github.com/jeremyhahn/go-keychain/pkg/ratelimit"
)

// Server represents an MCP JSON-RPC 2.0 server
type Server struct {
	addr          string
	keystore      keychain.KeyStore // Default keystore for backward compatibility
	listener      net.Listener
	ctx           context.Context
	cancel        context.CancelFunc
	wg            sync.WaitGroup
	tlsConfig     *tls.Config
	authenticator auth.Authenticator
	logger        *slog.Logger
	rateLimiter   *ratelimit.Limiter

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
}

// NewServer creates a new MCP JSON-RPC server
// The server uses the global keychain service for backend management
func NewServer(config *Config) (*Server, error) {
	if !keychain.IsInitialized() {
		return nil, fmt.Errorf("keychain service must be initialized before creating MCP server")
	}

	if config.Addr == "" {
		config.Addr = "localhost:9444"
	}

	// Set up authenticator (default to NoOp if not provided)
	authenticator := config.Authenticator
	if authenticator == nil {
		authenticator = auth.NewNoOpAuthenticator()
	}

	// Set up logger (default to stdlib if not provided)
	log := config.Logger
	if log == nil {
		log = slog.Default()
	}

	ctx, cancel := context.WithCancel(context.Background())

	s := &Server{
		addr:          config.Addr,
		ctx:           ctx,
		cancel:        cancel,
		tlsConfig:     config.TLSConfig,
		authenticator: authenticator,
		logger:        log,
		rateLimiter:   config.RateLimiter,
		subscribers:   make(map[net.Conn]*Subscriber),
	}

	// Log if rate limiting is enabled
	if config.RateLimiter != nil && config.RateLimiter.IsEnabled() {
		log.Info("Rate limiting enabled for MCP")
	}

	// Set default keystore from default backend for backward compatibility
	keystore, err := keychain.DefaultBackend()
	if err != nil {
		cancel()
		return nil, fmt.Errorf("failed to get default keystore: %w", err)
	}
	s.keystore = keystore

	return s, nil
}

// Start starts the MCP server
func (s *Server) Start() error {
	listener, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %w", s.addr, err)
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

	s.listener = listener

	s.wg.Add(1)
	go s.acceptConnections()

	return nil
}

// acceptConnections accepts incoming TCP connections
func (s *Server) acceptConnections() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
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
					Claims:  make(map[string]interface{}),
					Attributes: map[string]string{
						"auth_method": "mtls",
						"subject_dn":  cert.Subject.String(),
					},
				}
				ctx = auth.WithIdentity(ctx, identity)
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

	// Route to appropriate handler
	var result interface{}
	var err error

	// Try FROST methods first
	if frostResult, frostErr, handled := s.routeFrostMethods(req); handled {
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

	switch req.Method {
	case "health":
		result, err = s.handleHealth(req)
	case "keychain.listBackends":
		result, err = s.handleListBackends(req)
	case "keychain.generateKey":
		result, err = s.handleGenerateKey(req)
	case "keychain.getKey":
		result, err = s.handleGetKey(req)
	case "keychain.deleteKey":
		result, err = s.handleDeleteKey(req)
	case "keychain.listKeys":
		result, err = s.handleListKeys(req)
	case "keychain.rotateKey":
		result, err = s.handleRotateKey(req)
	case "keychain.sign":
		result, err = s.handleSign(req)
	case "keychain.verify":
		result, err = s.handleVerify(req)
	case "keychain.encrypt":
		result, err = s.handleEncrypt(req)
	case "keychain.decrypt":
		result, err = s.handleDecrypt(req)
	case "keychain.asymmetricEncrypt":
		result, err = s.handleAsymmetricEncrypt(req)
	case "keychain.asymmetricDecrypt":
		result, err = s.handleAsymmetricDecrypt(req)
	case "keychain.getImportParameters":
		result, err = s.handleGetImportParameters(req)
	case "keychain.wrapKey":
		result, err = s.handleWrapKey(req)
	case "keychain.unwrapKey":
		result, err = s.handleUnwrapKey(req)
	case "keychain.importKey":
		result, err = s.handleImportKeyMaterial(req)
	case "keychain.exportKey":
		result, err = s.handleExportKeyMaterial(req)
	case "keychain.copyKey":
		result, err = s.handleCopyKey(req)
	case "keychain.saveCert":
		result, err = s.handleSaveCert(req)
	case "keychain.getCert":
		result, err = s.handleGetCert(req)
	case "keychain.deleteCert":
		result, err = s.handleDeleteCert(req)
	case "keychain.listCerts":
		result, err = s.handleListCerts(req)
	case "keychain.certExists":
		result, err = s.handleCertExists(req)
	case "keychain.saveCertChain":
		result, err = s.handleSaveCertChain(req)
	case "keychain.getCertChain":
		result, err = s.handleGetCertChain(req)
	case "keychain.getTLSCertificate":
		result, err = s.handleGetTLSCertificate(req)
	case "keychain.subscribe":
		result, err = s.handleSubscribe(req, conn)
	case "keychain.listKeyVersions":
		result, err = s.handleListKeyVersions(req)
	case "keychain.enableKeyVersion":
		result, err = s.handleEnableKeyVersion(req)
	case "keychain.disableKeyVersion":
		result, err = s.handleDisableKeyVersion(req)
	case "keychain.enableAllKeyVersions":
		result, err = s.handleEnableAllKeyVersions(req)
	case "keychain.disableAllKeyVersions":
		result, err = s.handleDisableAllKeyVersions(req)
	case "keychain.seal":
		result, err = s.handleSeal(ctx, req)
	case "keychain.unseal":
		result, err = s.handleUnseal(ctx, req)
	case "keychain.canSeal":
		result, err = s.handleCanSeal(req)
	default:
		return s.makeErrorResponse(req.ID, correlationID, ErrCodeMethodNotFound, "Method not found", nil)
	}

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

	if s.listener != nil {
		if err := s.listener.Close(); err != nil {
			s.logger.Error("Failed to close listener", slog.String("error", err.Error()))
			return err
		}
	}

	s.wg.Wait()
	s.logger.Info("MCP server stopped")
	return nil
}
