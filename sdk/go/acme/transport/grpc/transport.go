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

// Package grpc provides a gRPC transport implementation for the Trusted CA SDK.
//
// The gRPC transport offers high-performance, bidirectional streaming communication
// with the CA server's Admin API. It supports connection pooling, keepalive configuration,
// and automatic reconnection.
//
// This transport uses a JSON codec instead of protobuf for wire encoding, enabling
// plain Go structs (admin API types) to be transmitted without requiring protobuf
// definitions on the client side.
//
// Note: ACME protocol operations (RFC 8555) are not supported via gRPC as ACME is
// fundamentally a REST-based protocol. Use the REST transport for ACME operations.
//
// Example usage:
//
//	cfg := &transport.Config{
//	    Address:   "localhost:9443",
//	    TLSConfig: tlsConfig,
//	}
//	t, err := grpc.NewTransport(cfg)
//	if err != nil {
//	    return err
//	}
//	defer t.Close()
package grpc

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/encoding"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// jsonCodec implements grpc encoding.Codec using JSON serialization.
// It uses protojson for proto.Message types and standard json for plain Go structs.
type jsonCodec struct{}

func (jsonCodec) Marshal(v interface{}) ([]byte, error) {
	if pm, ok := v.(proto.Message); ok {
		return protojson.Marshal(pm)
	}
	return json.Marshal(v)
}

func (jsonCodec) Unmarshal(data []byte, v interface{}) error {
	if pm, ok := v.(proto.Message); ok {
		return protojson.Unmarshal(data, pm)
	}
	return json.Unmarshal(data, v)
}

func (jsonCodec) Name() string {
	return "json"
}

func init() {
	encoding.RegisterCodec(jsonCodec{})
}

// Service names for routing.
const (
	ServiceAdmin       = "admin"
	ServiceTenant      = "tenant"
	ServiceEAB         = "eab"
	ServicePolicy      = "policy"
	ServiceCertificate = "certificate"
	ServiceStatus      = "status"

	// ACME services (not supported via gRPC).
	ServiceDirectory     = "directory"
	ServiceNonce         = "nonce"
	ServiceAccount       = "account"
	ServiceOrder         = "order"
	ServiceAuthorization = "authorization"
	ServiceChallenge     = "challenge"
	ServiceFinalize      = "finalize"
	ServiceRevoke        = "revoke"
)

// Default configuration values.
const (
	defaultTimeout          = 30 * time.Second
	defaultKeepaliveTime    = 30 * time.Second
	defaultKeepaliveTimeout = 10 * time.Second
	defaultPoolMinSize      = 1
	defaultPoolMaxSize      = 10
	defaultPoolMaxAge       = 5 * time.Minute
	defaultHealthInterval   = 30 * time.Second
)

// Transport implements transport.Transport using gRPC.
type Transport struct {
	cfg      *transport.Config
	conn     *grpc.ClientConn
	pool     *connectionPool
	closed   atomic.Bool
	mu       sync.RWMutex
	handlers map[string]requestHandler
}

// requestHandler is the function signature for handling service/method requests.
// The service parameter provides context for disambiguating generic method names
// (e.g., "create" maps to different gRPC methods depending on the service).
type requestHandler func(ctx context.Context, t *Transport, service, method string, req interface{}) (interface{}, error)

// NewTransport creates a new gRPC transport with the given configuration.
func NewTransport(cfg *transport.Config) (transport.Transport, error) {
	if cfg == nil {
		return nil, errors.NewInvalidInput("grpc.NewTransport", "config cannot be nil")
	}

	if cfg.Address == "" {
		return nil, errors.NewInvalidInput("grpc.NewTransport", "address cannot be empty")
	}

	t := &Transport{
		cfg: cfg,
	}

	// Initialize handler dispatch map.
	t.initHandlers()

	// Apply defaults.
	t.applyDefaults()

	// Build connection options.
	opts, err := t.buildDialOptions()
	if err != nil {
		return nil, errors.Wrap(err, errors.CodeConfiguration, "grpc.NewTransport", "failed to build dial options")
	}

	// Parse address for gRPC.
	parsed := transport.ParseAddress(cfg.Address)
	target := parsed.NormalizeForGRPC()

	// Handle Unix socket dialer.
	if parsed.IsUnix() {
		socketPath := parsed.Address
		opts = append(opts, grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			dialer := &net.Dialer{}
			return dialer.DialContext(ctx, "unix", socketPath)
		}))
		target = "passthrough:///" + socketPath
	}

	// Create connection pool if enabled.
	if cfg.PoolEnabled {
		pool, poolErr := newConnectionPool(t, target, opts)
		if poolErr != nil {
			return nil, errors.Wrap(poolErr, errors.CodeConnection, "grpc.NewTransport", "failed to create connection pool")
		}
		t.pool = pool
	} else {
		// Create single connection.
		conn, connErr := grpc.NewClient(target, opts...)
		if connErr != nil {
			return nil, errors.Wrap(connErr, errors.CodeConnection, "grpc.NewTransport", "failed to connect to gRPC server")
		}
		t.conn = conn
	}

	return t, nil
}

// initHandlers initializes the map-based dispatch for O(1) routing.
func (t *Transport) initHandlers() {
	t.handlers = map[string]requestHandler{
		// Admin API handlers (bare service names).
		ServiceAdmin:       t.handleAdminRequest,
		ServiceTenant:      t.handleAdminRequest,
		ServiceEAB:         t.handleAdminRequest,
		ServicePolicy:      t.handleAdminRequest,
		ServiceCertificate: t.handleAdminRequest,
		ServiceStatus:      t.handleAdminRequest,

		// Admin API handlers (dotted service names from SDK admin client).
		"admin.tenant":      t.handleAdminRequest,
		"admin.eab":         t.handleAdminRequest,
		"admin.role":        t.handleAdminRequest,
		"admin.user":        t.handleAdminRequest,
		"admin.certificate": t.handleAdminRequest,
		"admin.account":     t.handleAdminRequest,
		"admin.status":      t.handleAdminRequest,
		"admin.order":       t.handleAdminRequest,
		"admin.tenant.ca":   t.handleAdminRequest,

		// ACME services - not supported via gRPC.
		ServiceDirectory:     t.handleACMEUnsupported,
		ServiceNonce:         t.handleACMEUnsupported,
		ServiceAccount:       t.handleACMEUnsupported,
		ServiceOrder:         t.handleACMEUnsupported,
		ServiceAuthorization: t.handleACMEUnsupported,
		ServiceChallenge:     t.handleACMEUnsupported,
		ServiceFinalize:      t.handleACMEUnsupported,
		ServiceRevoke:        t.handleACMEUnsupported,
	}
}

// applyDefaults applies default configuration values.
func (t *Transport) applyDefaults() {
	if t.cfg.Timeout == 0 {
		t.cfg.Timeout = defaultTimeout
	}
	if t.cfg.KeepaliveTime == 0 {
		t.cfg.KeepaliveTime = defaultKeepaliveTime
	}
	if t.cfg.KeepaliveTimeout == 0 {
		t.cfg.KeepaliveTimeout = defaultKeepaliveTimeout
	}
	if t.cfg.PoolEnabled {
		if t.cfg.PoolMinSize <= 0 {
			t.cfg.PoolMinSize = defaultPoolMinSize
		}
		if t.cfg.PoolMaxSize <= 0 {
			t.cfg.PoolMaxSize = defaultPoolMaxSize
		}
		if t.cfg.PoolMaxSize < t.cfg.PoolMinSize {
			t.cfg.PoolMaxSize = t.cfg.PoolMinSize
		}
		if t.cfg.PoolMaxAge == 0 {
			t.cfg.PoolMaxAge = defaultPoolMaxAge
		}
		if t.cfg.PoolHealthInterval == 0 {
			t.cfg.PoolHealthInterval = defaultHealthInterval
		}
	}
}

// buildDialOptions constructs gRPC dial options from configuration.
func (t *Transport) buildDialOptions() ([]grpc.DialOption, error) {
	var opts []grpc.DialOption

	// Force JSON codec for all calls. This enables plain Go structs
	// (admin API types) to be used without protobuf definitions.
	opts = append(opts, grpc.WithDefaultCallOptions(grpc.ForceCodec(jsonCodec{})))

	// Insecure mode is forbidden. Callers must supply an explicit TLSConfig
	// with RootCAs or an SPKI-pinned VerifyConnection callback.
	if t.cfg.Insecure && t.cfg.TLSConfig == nil {
		return nil, errors.NewInvalidInput("grpc.buildDialOptions",
			"Insecure=true requires an explicit TLSConfig with RootCAs or VerifyConnection; InsecureSkipVerify is forbidden")
	}

	if t.cfg.TLSConfig != nil {
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(t.cfg.TLSConfig)))
	} else {
		// Default to system TLS with TLS 1.3.
		opts = append(opts, grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
			MinVersion: tls.VersionTLS13,
		})))
	}

	// Configure keepalive.
	opts = append(opts, grpc.WithKeepaliveParams(keepalive.ClientParameters{
		Time:                t.cfg.KeepaliveTime,
		Timeout:             t.cfg.KeepaliveTimeout,
		PermitWithoutStream: true,
	}))

	return opts, nil
}

// Request sends a unary request and returns the response.
func (t *Transport) Request(ctx context.Context, service, method string, req interface{}) (interface{}, error) {
	if t.closed.Load() {
		return nil, errors.NewUnavailable("grpc.Transport.Request", "transport is closed")
	}

	// Normalize service name.
	service = strings.ToLower(service)

	// Look up handler using map-based dispatch for O(1) lookup.
	handler, ok := t.handlers[service]
	if !ok {
		return nil, errors.NewInvalidInput("grpc.Transport.Request", "unknown service: "+service)
	}

	// Apply timeout if not already set in context.
	if _, hasDeadline := ctx.Deadline(); !hasDeadline && t.cfg.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, t.cfg.Timeout)
		defer cancel()
	}

	return handler(ctx, t, service, method, req)
}

// RequestStream initiates a streaming request.
func (t *Transport) RequestStream(ctx context.Context, service, method string, req interface{}) (transport.Stream, error) {
	if t.closed.Load() {
		return nil, errors.NewUnavailable("grpc.Transport.RequestStream", "transport is closed")
	}

	// Normalize service name.
	service = strings.ToLower(service)

	// Check if this is an ACME service (not supported).
	if t.isACMEService(service) {
		return nil, errors.NewUnimplemented("grpc.Transport.RequestStream",
			"ACME streaming not supported via gRPC; use REST transport for ACME operations")
	}

	// Admin API streaming is supported.
	conn, err := t.getConnection()
	if err != nil {
		return nil, err
	}

	// Create a generic stream wrapper.
	stream := &grpcStream{
		ctx:  ctx,
		conn: conn,
	}

	return stream, nil
}

// Conn returns the underlying gRPC connection.
func (t *Transport) Conn() interface{} {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.pool != nil {
		// Return the pool for advanced usage.
		return t.pool
	}
	return t.conn
}

// Close closes the transport connection.
func (t *Transport) Close() error {
	if !t.closed.CompareAndSwap(false, true) {
		return nil // Already closed.
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	var closeErr error

	if t.pool != nil {
		closeErr = t.pool.Close()
		t.pool = nil
	}

	if t.conn != nil {
		if err := t.conn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
		t.conn = nil
	}

	if closeErr != nil {
		return errors.Wrap(closeErr, errors.CodeConnection, "grpc.Transport.Close", "failed to close connection")
	}

	return nil
}

// Healthy returns true if the transport is healthy.
func (t *Transport) Healthy() bool {
	if t.closed.Load() {
		return false
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.pool != nil {
		return t.pool.Healthy()
	}

	if t.conn == nil {
		return false
	}

	state := t.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// getConnection returns a gRPC connection, either from pool or single connection.
func (t *Transport) getConnection() (*grpc.ClientConn, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.pool != nil {
		return t.pool.Get()
	}

	if t.conn == nil {
		return nil, errors.NewUnavailable("grpc.Transport.getConnection", "no connection available")
	}

	return t.conn, nil
}

// releaseConnection returns a connection to the pool if pooling is enabled.
func (t *Transport) releaseConnection(conn *grpc.ClientConn) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.pool != nil {
		t.pool.Put(conn)
	}
}

// isACMEService returns true if the service is an ACME-specific service.
func (t *Transport) isACMEService(service string) bool {
	switch service {
	case ServiceDirectory, ServiceNonce, ServiceAccount, ServiceOrder,
		ServiceAuthorization, ServiceChallenge, ServiceFinalize, ServiceRevoke:
		return true
	}
	return false
}

// handleAdminRequest handles Admin API requests via gRPC.
func (t *Transport) handleAdminRequest(ctx context.Context, tr *Transport, service, method string, req interface{}) (interface{}, error) {
	conn, err := tr.getConnection()
	if err != nil {
		return nil, err
	}

	if tr.pool != nil {
		defer tr.releaseConnection(conn)
	}

	// Build the full method path for gRPC invocation using service context.
	fullMethod := buildFullMethod(service, method)

	// Ensure request is not nil (gRPC requires a non-nil message).
	if req == nil {
		req = struct{}{}
	}

	// Create response placeholder.
	var resp json.RawMessage

	// Invoke the method dynamically using JSON codec.
	err = conn.Invoke(ctx, fullMethod, req, &resp)
	if err != nil {
		return nil, tr.translateGRPCError(err)
	}

	// Parse JSON response into a map for the SDK client layer.
	if len(resp) == 0 {
		return nil, nil
	}
	var data map[string]interface{}
	if err := json.Unmarshal(resp, &data); err != nil {
		return nil, errors.Wrap(err, errors.CodeInternal, "grpc.Transport",
			"failed to parse gRPC response")
	}
	return data, nil
}

// handleACMEUnsupported returns an error for ACME operations.
func (t *Transport) handleACMEUnsupported(ctx context.Context, tr *Transport, service, method string, req interface{}) (interface{}, error) {
	return nil, errors.NewUnimplemented("grpc.Transport.Request",
		"ACME operations are not supported via gRPC; use REST transport for RFC 8555 ACME protocol")
}

// grpcServiceMethodMap provides service-aware method mapping for O(1) lookup.
// The outer key is the service name (or dotted service name), and the inner key
// is the SDK method name, mapping to the gRPC proto method name.
var grpcServiceMethodMap = map[string]map[string]string{
	// Tenant operations
	"admin.tenant": {
		"create":       "CreateTenant",
		"get":          "GetTenant",
		"update":       "UpdateTenant",
		"delete":       "DeleteTenant",
		"list":         "ListTenants",
		"updateStatus": "UpdateTenantStatus",
	},
	ServiceTenant: {
		"create":       "CreateTenant",
		"get":          "GetTenant",
		"update":       "UpdateTenant",
		"delete":       "DeleteTenant",
		"list":         "ListTenants",
		"updateStatus": "UpdateTenantStatus",
	},

	// EAB operations
	"admin.eab": {
		"create": "CreateEAB",
		"get":    "GetEAB",
		"delete": "DeleteEAB",
		"list":   "ListEABs",
	},
	ServiceEAB: {
		"create": "CreateEAB",
		"get":    "GetEAB",
		"delete": "DeleteEAB",
		"list":   "ListEABs",
	},

	// Certificate operations
	"admin.certificate": {
		"list":              "ListCertificates",
		"get":               "GetCertificate",
		"revoke":            "RevokeCertificate",
		"listCertificates":  "ListCertificates",
		"getCertificate":    "GetCertificate",
		"revokeCertificate": "RevokeCertificate",
	},
	ServiceCertificate: {
		"list":              "ListCertificates",
		"get":               "GetCertificate",
		"revoke":            "RevokeCertificate",
		"listCertificates":  "ListCertificates",
		"getCertificate":    "GetCertificate",
		"revokeCertificate": "RevokeCertificate",
	},

	// Account operations
	"admin.account": {
		"list":           "ListAccounts",
		"get":            "GetAccount",
		"disable":        "DisableAccount",
		"listAccounts":   "ListAccounts",
		"getAccount":     "GetAccount",
		"disableAccount": "DisableAccount",
	},

	// Role operations (RBAC)
	"admin.role": {
		"create":     "CreateTenantRole",
		"get":        "GetTenantRole",
		"update":     "UpdateTenantRole",
		"delete":     "DeleteTenantRole",
		"list":       "ListTenantRoles",
		"createRole": "CreateTenantRole",
		"getRole":    "GetTenantRole",
		"updateRole": "UpdateTenantRole",
		"deleteRole": "DeleteTenantRole",
		"listRoles":  "ListTenantRoles",
	},

	// User operations (RBAC)
	"admin.user": {
		"create":     "CreateTenantUser",
		"get":        "GetTenantUser",
		"update":     "UpdateTenantUser",
		"delete":     "DeleteTenantUser",
		"list":       "ListTenantUsers",
		"createUser": "CreateTenantUser",
		"getUser":    "GetTenantUser",
		"updateUser": "UpdateTenantUser",
		"deleteUser": "DeleteTenantUser",
		"listUsers":  "ListTenantUsers",
	},

	// Order operations
	"admin.order": {
		"list":       "ListOrders",
		"get":        "GetOrder",
		"listOrders": "ListOrders",
		"getOrder":   "GetOrder",
	},

	// Tenant CA operations
	"admin.tenant.ca": {
		"createRootCA":               "CreateTenantRootCA",
		"getRootCA":                  "GetTenantRootCA",
		"createIntermediateCA":       "CreateTenantIntermediateCA",
		"listIntermediateCAs":        "ListTenantIntermediateCAs",
		"caStatus":                   "GetTenantCAStatus",
		"status":                     "GetTenantCAStatus",
		"updateIntermediateCAStatus": "UpdateTenantIntermediateCAStatus",
	},

	// Status operations
	"admin.status": {
		"status": "GetStatus",
		"stats":  "GetStats",
	},
	ServiceStatus: {
		"status": "GetStatus",
		"stats":  "GetStats",
	},
}

// grpcFallbackMethodMap maps SDK method names to proto service method names
// for methods that are already fully qualified (e.g., "listCertificates")
// and do not need service context for disambiguation.
var grpcFallbackMethodMap = map[string]string{
	"status":                     "GetStatus",
	"stats":                      "GetStats",
	"listCertificates":           "ListCertificates",
	"getCertificate":             "GetCertificate",
	"revokeCertificate":          "RevokeCertificate",
	"listAccounts":               "ListAccounts",
	"getAccount":                 "GetAccount",
	"disableAccount":             "DisableAccount",
	"createEAB":                  "CreateEAB",
	"getEAB":                     "GetEAB",
	"deleteEAB":                  "DeleteEAB",
	"listEABs":                   "ListEABs",
	"createRole":                 "CreateTenantRole",
	"getRole":                    "GetTenantRole",
	"updateRole":                 "UpdateTenantRole",
	"deleteRole":                 "DeleteTenantRole",
	"listRoles":                  "ListTenantRoles",
	"createUser":                 "CreateTenantUser",
	"getUser":                    "GetTenantUser",
	"updateUser":                 "UpdateTenantUser",
	"deleteUser":                 "DeleteTenantUser",
	"listUsers":                  "ListTenantUsers",
	"listOrders":                 "ListOrders",
	"getOrder":                   "GetOrder",
	"updateStatus":               "UpdateTenantStatus",
	"createRootCA":               "CreateTenantRootCA",
	"getRootCA":                  "GetTenantRootCA",
	"createIntermediateCA":       "CreateTenantIntermediateCA",
	"listIntermediateCAs":        "ListTenantIntermediateCAs",
	"caStatus":                   "GetTenantCAStatus",
	"updateIntermediateCAStatus": "UpdateTenantIntermediateCAStatus",
}

// buildFullMethod constructs the full gRPC method path from a service and SDK method name.
// The service parameter provides context for disambiguating generic method names like
// "create", "get", "list", "delete" which map to different gRPC methods depending on
// the service (e.g., "list" on "admin.tenant" maps to ListTenants, while "list" on
// "admin.certificate" maps to ListCertificates).
func buildFullMethod(service, method string) string {
	// If method already contains a slash, assume it's a full path.
	if strings.Contains(method, "/") {
		if !strings.HasPrefix(method, "/") {
			return "/" + method
		}
		return method
	}

	// Try service-specific method map first for proper disambiguation.
	if serviceMap, ok := grpcServiceMethodMap[service]; ok {
		if protoMethod, ok := serviceMap[method]; ok {
			return "/trustedca.admin.v1.AdminService/" + protoMethod
		}
	}

	// Fall back to the unambiguous method map for fully qualified method names.
	if protoMethod, ok := grpcFallbackMethodMap[method]; ok {
		return "/trustedca.admin.v1.AdminService/" + protoMethod
	}

	// If no mapping found, use the method name as-is (may be a proto method name already).
	return "/trustedca.admin.v1.AdminService/" + method
}

// translateGRPCError converts gRPC errors to SDK errors.
func (t *Transport) translateGRPCError(err error) error {
	if err == nil {
		return nil
	}

	st, ok := status.FromError(err)
	if !ok {
		return errors.Wrap(err, errors.CodeInternal, "grpc.Transport", "unknown error")
	}

	// Map gRPC status codes to SDK error codes.
	code := grpcCodeToErrorCode(st.Code())
	return errors.New(code, "grpc.Transport", st.Message())
}

// grpcCodeToErrorCode maps gRPC status codes to SDK error codes using map-based dispatch.
var grpcCodeMap = map[codes.Code]errors.ErrorCode{
	codes.OK:                 errors.CodeUnknown,
	codes.Canceled:           errors.CodeCanceled,
	codes.Unknown:            errors.CodeUnknown,
	codes.InvalidArgument:    errors.CodeInvalidInput,
	codes.DeadlineExceeded:   errors.CodeTimeout,
	codes.NotFound:           errors.CodeNotFound,
	codes.AlreadyExists:      errors.CodeAlreadyExists,
	codes.PermissionDenied:   errors.CodeForbidden,
	codes.ResourceExhausted:  errors.CodeResourceExhausted,
	codes.FailedPrecondition: errors.CodePreconditionFailed,
	codes.Aborted:            errors.CodeConflict,
	codes.OutOfRange:         errors.CodeInvalidInput,
	codes.Unimplemented:      errors.CodeUnimplemented,
	codes.Internal:           errors.CodeInternal,
	codes.Unavailable:        errors.CodeUnavailable,
	codes.DataLoss:           errors.CodeInternal,
	codes.Unauthenticated:    errors.CodeUnauthorized,
}

// grpcCodeToErrorCode converts a gRPC status code to an SDK error code.
func grpcCodeToErrorCode(code codes.Code) errors.ErrorCode {
	if errCode, ok := grpcCodeMap[code]; ok {
		return errCode
	}
	return errors.CodeUnknown
}

// grpcStream implements transport.Stream for gRPC bidirectional streaming.
type grpcStream struct {
	ctx    context.Context
	conn   *grpc.ClientConn
	stream grpc.ClientStream
	closed atomic.Bool
}

// Send sends a message on the stream.
func (s *grpcStream) Send(msg interface{}) error {
	if s.closed.Load() {
		return errors.NewUnavailable("grpc.Stream.Send", "stream is closed")
	}

	if s.stream == nil {
		return errors.NewNotInitialized("grpc.Stream.Send", "stream not initialized")
	}

	if err := s.stream.SendMsg(msg); err != nil {
		return errors.Wrap(err, errors.CodeTransport, "grpc.Stream.Send", "failed to send message")
	}

	return nil
}

// Recv receives a message from the stream.
func (s *grpcStream) Recv() (interface{}, error) {
	if s.closed.Load() {
		return nil, errors.NewUnavailable("grpc.Stream.Recv", "stream is closed")
	}

	if s.stream == nil {
		return nil, errors.NewNotInitialized("grpc.Stream.Recv", "stream not initialized")
	}

	var msg interface{}
	if err := s.stream.RecvMsg(&msg); err != nil {
		return nil, errors.Wrap(err, errors.CodeTransport, "grpc.Stream.Recv", "failed to receive message")
	}

	return msg, nil
}

// CloseSend closes the send side of the stream.
func (s *grpcStream) CloseSend() error {
	if s.stream == nil {
		return nil
	}

	if err := s.stream.CloseSend(); err != nil {
		return errors.Wrap(err, errors.CodeTransport, "grpc.Stream.CloseSend", "failed to close send")
	}

	return nil
}

// Close closes the stream entirely.
func (s *grpcStream) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil
	}

	return s.CloseSend()
}

// connectionPool manages a pool of gRPC connections.
type connectionPool struct {
	transport     *Transport
	target        string
	opts          []grpc.DialOption
	connections   []*pooledConnection
	mu            sync.Mutex
	closed        atomic.Bool
	healthTicker  *time.Ticker
	healthDone    chan struct{}
	nextConnIndex atomic.Uint64
}

// pooledConnection wraps a gRPC connection with metadata.
type pooledConnection struct {
	conn      *grpc.ClientConn
	createdAt time.Time
	inUse     atomic.Bool
}

// newConnectionPool creates a new connection pool.
func newConnectionPool(t *Transport, target string, opts []grpc.DialOption) (*connectionPool, error) {
	pool := &connectionPool{
		transport:   t,
		target:      target,
		opts:        opts,
		connections: make([]*pooledConnection, 0, t.cfg.PoolMaxSize),
		healthDone:  make(chan struct{}),
	}

	// Create minimum connections.
	for i := 0; i < t.cfg.PoolMinSize; i++ {
		if err := pool.addConnection(); err != nil {
			_ = pool.Close()
			return nil, err
		}
	}

	// Start health check routine.
	pool.healthTicker = time.NewTicker(t.cfg.PoolHealthInterval)
	go pool.healthCheckLoop()

	return pool, nil
}

// addConnection creates a new connection and adds it to the pool.
func (p *connectionPool) addConnection() error {
	conn, err := grpc.NewClient(p.target, p.opts...)
	if err != nil {
		return err
	}

	pc := &pooledConnection{
		conn:      conn,
		createdAt: time.Now(),
	}

	p.connections = append(p.connections, pc)
	return nil
}

// Get retrieves a connection from the pool.
func (p *connectionPool) Get() (*grpc.ClientConn, error) {
	if p.closed.Load() {
		return nil, errors.NewUnavailable("grpc.Pool.Get", "pool is closed")
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	// Round-robin selection.
	numConns := len(p.connections)
	if numConns == 0 {
		return nil, errors.NewUnavailable("grpc.Pool.Get", "no connections available")
	}

	// Try to find an available connection.
	startIdx := int(p.nextConnIndex.Add(1) % uint64(numConns))
	for i := 0; i < numConns; i++ {
		idx := (startIdx + i) % numConns
		pc := p.connections[idx]

		// Check if connection is healthy and not too old.
		if p.isConnectionHealthy(pc) {
			if pc.inUse.CompareAndSwap(false, true) {
				return pc.conn, nil
			}
		}
	}

	// All connections in use, try to create a new one if under max.
	if numConns < p.transport.cfg.PoolMaxSize {
		if err := p.addConnection(); err == nil {
			pc := p.connections[len(p.connections)-1]
			pc.inUse.Store(true)
			return pc.conn, nil
		}
	}

	// Return the first connection anyway (shared usage).
	idx := startIdx % numConns
	return p.connections[idx].conn, nil
}

// Put returns a connection to the pool.
func (p *connectionPool) Put(conn *grpc.ClientConn) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pc := range p.connections {
		if pc.conn == conn {
			pc.inUse.Store(false)
			return
		}
	}
}

// isConnectionHealthy checks if a pooled connection is healthy.
func (p *connectionPool) isConnectionHealthy(pc *pooledConnection) bool {
	// Check age.
	if time.Since(pc.createdAt) > p.transport.cfg.PoolMaxAge {
		return false
	}

	// Check connectivity state.
	state := pc.conn.GetState()
	return state == connectivity.Ready || state == connectivity.Idle
}

// Healthy returns true if the pool has at least one healthy connection.
func (p *connectionPool) Healthy() bool {
	if p.closed.Load() {
		return false
	}

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, pc := range p.connections {
		if p.isConnectionHealthy(pc) {
			return true
		}
	}

	return false
}

// Close closes all connections in the pool.
func (p *connectionPool) Close() error {
	if !p.closed.CompareAndSwap(false, true) {
		return nil
	}

	// Stop health check.
	if p.healthTicker != nil {
		p.healthTicker.Stop()
	}
	close(p.healthDone)

	p.mu.Lock()
	defer p.mu.Unlock()

	var closeErr error
	for _, pc := range p.connections {
		if err := pc.conn.Close(); err != nil && closeErr == nil {
			closeErr = err
		}
	}
	p.connections = nil

	return closeErr
}

// healthCheckLoop periodically checks connection health.
func (p *connectionPool) healthCheckLoop() {
	for {
		select {
		case <-p.healthDone:
			return
		case <-p.healthTicker.C:
			p.performHealthCheck()
		}
	}
}

// performHealthCheck removes unhealthy connections and ensures minimum pool size.
func (p *connectionPool) performHealthCheck() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.closed.Load() {
		return
	}

	// Remove unhealthy or expired connections.
	healthy := make([]*pooledConnection, 0, len(p.connections))
	for _, pc := range p.connections {
		if p.isConnectionHealthy(pc) && !pc.inUse.Load() {
			healthy = append(healthy, pc)
		} else if !pc.inUse.Load() {
			// Close unhealthy connection.
			_ = pc.conn.Close()
		} else {
			// Keep in-use connections even if unhealthy.
			healthy = append(healthy, pc)
		}
	}
	p.connections = healthy

	// Ensure minimum pool size.
	for len(p.connections) < p.transport.cfg.PoolMinSize {
		if err := p.addConnection(); err != nil {
			break
		}
	}
}

// WithAuth returns a context with authorization metadata.
func WithAuth(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+token)
}

// Factory creates gRPC transports.
type Factory struct{}

// NewFactory creates a new gRPC transport factory.
func NewFactory() transport.Factory {
	return &Factory{}
}

// Create creates a new gRPC transport with the given configuration.
func (f *Factory) Create(cfg *transport.Config) (transport.Transport, error) {
	return NewTransport(cfg)
}

// Verify interface compliance.
var (
	_ transport.Transport = (*Transport)(nil)
	_ transport.Stream    = (*grpcStream)(nil)
	_ transport.Factory   = (*Factory)(nil)
)
