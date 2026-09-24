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
	stderrors "errors"
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

	// defaultPoolAcquireTimeout is how long Get waits for a borrower to return
	// a connection before reporting the pool exhausted. It is not a request
	// timeout: the request has not started yet, and the caller still has its
	// own context deadline afterwards.
	defaultPoolAcquireTimeout = 5 * time.Second
)

// ErrPoolExhausted reports that every pooled connection was leased out and the
// pool was already at PoolMaxSize, for the whole of PoolAcquireTimeout.
//
// It is wrapped in a CAError with CodeUnavailable, so callers that classify by
// code keep working unchanged and callers that need to tell exhaustion from
// "the server is down" can use errors.Is. Retrying is the sensible response;
// this says the CLIENT ran out of connections, not that the CA is unreachable.
//
// Before the owner ruling of 2026-08-23 on #104 there was no such error: a
// saturated pool returned the first connection anyway, WITHOUT recording the
// second borrower, and the first Put then cleared the in-use flag for both --
// after which the health check was free to close a connection another caller
// was still using. A connection is now never lent to two borrowers.
var ErrPoolExhausted = stderrors.New("grpc: connection pool exhausted")

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
		if t.cfg.PoolAcquireTimeout <= 0 {
			t.cfg.PoolAcquireTimeout = defaultPoolAcquireTimeout
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
// getConnection returns a connection for one request, honouring ctx.
//
// The transport lock is SNAPSHOTTED rather than held across the acquisition,
// and that is load-bearing now that Get can block: Close takes t.mu for writing
// before it can call pool.Close, so holding the read lock here would stop Close
// from ever reaching the pool.Close that closes healthDone and wakes this
// waiter. Shutdown would then stall for the whole PoolAcquireTimeout -- longer
// on a deployment that configured a large one -- and the deadlock is between
// the two operations most likely to overlap: a request in flight and a
// shutdown.
//
// Reading the two fields under the lock and using them after it is released is
// sound because neither is mutated in place: Close swaps them out and the pool
// itself handles being closed underneath a borrower (Get returns
// ErrSessionPool-style closed errors rather than panicking).
func (t *Transport) getConnection(ctx context.Context) (*grpc.ClientConn, error) {
	t.mu.RLock()
	pool, conn := t.pool, t.conn
	t.mu.RUnlock()

	if pool != nil {
		return pool.Get(ctx)
	}

	if conn == nil {
		return nil, errors.NewUnavailable("grpc.Transport.getConnection", "no connection available")
	}

	return conn, nil
}

// releaseConnection returns a connection to the pool if pooling is enabled.
func (t *Transport) releaseConnection(conn *grpc.ClientConn) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.pool != nil {
		t.pool.Put(conn)
	}
}

// handleAdminRequest handles Admin API requests via gRPC.
func (t *Transport) handleAdminRequest(ctx context.Context, tr *Transport, service, method string, req interface{}) (interface{}, error) {
	conn, err := tr.getConnection(ctx)
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

	// available is a BROADCAST latch, not a queue of nudges. It is closed and
	// replaced under mu whenever capacity appears, so every parked Get wakes
	// and re-scans; those that find nothing park again on the new channel.
	//
	// It replaces a 1-buffered "one nudge" channel, which lost capacity as soon
	// as more than one of anything was involved: with two connections leased
	// and two callers waiting, two Puts landing before either waiter consumed
	// the token made the second send take the default branch. One waiter woke
	// and took one connection; the other slept out PoolAcquireTimeout and
	// reported the pool exhausted with an idle connection sitting in it. The
	// bug was structural -- coalescing N independent capacity events into one
	// wake-up is only sound when at most one waiter can consume them.
	//
	// Closing cannot lose an event the way a buffered send can: a waiter
	// snapshots this channel BEFORE it scans, so capacity appearing between its
	// scan and its park closes the channel it is about to wait on, and the wait
	// returns immediately.
	//
	// Waiting is why any of this exists. Get used to hand a leased connection
	// to a second borrower rather than wait, which is what #104 is about.
	available chan struct{}
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
		available:   make(chan struct{}),
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

// Get retrieves a connection from the pool, waiting up to PoolAcquireTimeout
// for one to become free before reporting ErrPoolExhausted.
//
// Every connection it returns is leased EXCLUSIVELY to the caller, which is the
// owner ruling of 2026-08-23 on #104. The version this replaces ended with:
//
//	// Return the first connection anyway (shared usage).
//	idx := startIdx % numConns
//	return p.connections[idx].conn, nil
//
// -- a hand-out that recorded no borrower, because inUse is a bool and a bool
// cannot count. The first Put then cleared the flag for both holders, and
// performHealthCheck was free to Close a ClientConn the second holder was still
// issuing requests on. Saturation is exactly when that happens: it is when the
// pool is under load, which is when the health check is most likely to find an
// aged connection.
//
// Saturation is therefore now visible to the caller instead of absorbed. That
// is a behaviour change and it is the point: absorbing it was not free, it was
// paid for with an occasional request failing on a closed connection, at a
// place in the code that gave no hint where the failure came from.
func (p *connectionPool) Get(ctx context.Context) (*grpc.ClientConn, error) {
	timeout := p.transport.cfg.PoolAcquireTimeout
	if timeout <= 0 {
		timeout = defaultPoolAcquireTimeout
	}

	// One timer for the whole wait, not one per iteration: a woken Get that
	// loses the race for the released connection must keep the REMAINING
	// budget, not start a fresh one, or a busy pool never times out.
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	// A nil ctx blocks forever in the select below, which would silently drop
	// the timeout case's sibling; treat it as "no cancellation".
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}

	for {
		// Snapshot the latch BEFORE scanning. Capacity that appears between the
		// scan below and the park underneath closes THIS channel, so the wait
		// returns immediately instead of missing the event. Taking it after the
		// scan would reintroduce exactly that gap.
		latch := p.availableLatch()

		conn, err := p.tryGet()
		if err != nil {
			return nil, err
		}
		if conn != nil {
			return conn, nil
		}

		select {
		case <-latch:
			// Capacity appeared -- a Put, or a health check that opened a
			// replacement. Loop and try to take it: every waiter woke, and
			// another may get there first, which is why this is a loop and not
			// a hand-off.
		case <-done:
			// The CALLER's deadline, which is shorter than ours far more often
			// than not. Waiting out PoolAcquireTimeout for a request whose
			// context expired 4.9 seconds ago serves nobody, and acquiring a
			// connection afterwards would start work for a cancelled request.
			return nil, ctxError(ctx)
		case <-p.healthDone:
			return nil, errors.NewUnavailable("grpc.Pool.Get", "pool is closed")
		case <-timer.C:
			return nil, errors.NewUnavailable("grpc.Pool.Get",
				"every connection is leased and the pool is at PoolMaxSize").
				WithCause(ErrPoolExhausted)
		}
	}
}

// ctxError maps a finished context to the transport's error vocabulary,
// preserving the cause so errors.Is(err, context.Canceled) still answers.
func ctxError(ctx context.Context) error {
	err := ctx.Err()
	if stderrors.Is(err, context.DeadlineExceeded) {
		return errors.NewTimeout("grpc.Pool.Get",
			"the caller's deadline expired while waiting for a pooled connection").
			WithCause(err)
	}
	return errors.NewCanceled("grpc.Pool.Get",
		"the caller's context was cancelled while waiting for a pooled connection").
		WithCause(err)
}

// tryGet makes one non-blocking attempt to lease a connection.
//
// It returns (nil, nil) for "nothing free right now, try again later" -- the
// only case Get waits on. Everything else is decided here and returned.
func (p *connectionPool) tryGet() (*grpc.ClientConn, error) {
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

	return nil, nil
}

// Put returns a connection to the pool and wakes one waiter.
func (p *connectionPool) Put(conn *grpc.ClientConn) {
	p.mu.Lock()
	for _, pc := range p.connections {
		if pc.conn == conn {
			pc.inUse.Store(false)
			// Announced under the SAME lock that released it, so a waiter
			// cannot scan the pool between the two and then park on a latch
			// that has already been swapped.
			//
			// A connection that is not ours -- most likely already dropped by
			// a health check -- announces nothing: waking every waiter to
			// re-scan a pool nothing changed in is pure churn.
			p.signalAvailableLocked()
			break
		}
	}
	p.mu.Unlock()
}

// availableLatch returns the current broadcast latch.
func (p *connectionPool) availableLatch() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.available
}

// signalAvailableLocked wakes EVERY parked Get to re-scan the pool. The caller
// must hold mu.
//
// It closes the current latch and installs a fresh one. Closing rather than
// sending is what makes it correct with more than one waiter: a buffered send
// delivers to at most one of them and silently drops the rest, so N connections
// becoming free at once woke one caller and left the others to time out beside
// idle capacity.
//
// It is called from BOTH places capacity can appear, not only from Put. The
// health check is the other one: with every idle connection expired and the
// pool at PoolMaxSize, tryGet returns nothing and Get waits; performHealthCheck
// then closes those connections and opens replacements that no Put will ever
// announce, because nobody leased them.
//
// There is deliberately no unlocked wrapper. Both callers already hold mu, and
// an unlocked form would be a deadlock waiting to be called from
// performHealthCheck, which holds mu for its whole body.
func (p *connectionPool) signalAvailableLocked() {
	if p.available == nil {
		// A zero-value pool has no waiters to wake.
		return
	}
	close(p.available)
	p.available = make(chan struct{})
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
		switch {
		case pc.inUse.Load():
			// Kept even when unhealthy: closing a connection that is leased
			// out would fail the request its holder is making.
			//
			// This is now a guarantee rather than a hope, which it was not
			// when this comment was first written. inUse is a bool and a bool
			// cannot count borrowers -- so it is only sound while there can
			// never be two. Get's saturated fallback used to hand out an
			// already-leased connection without recording the extra borrower,
			// the first Put cleared the flag for both, and this branch stopped
			// applying while a second caller was still mid-request (#104).
			// Get now waits and then returns ErrPoolExhausted instead, so
			// exactly one caller holds a connection whose flag is set, and the
			// caller this branch protects is that one.
			healthy = append(healthy, pc)
		case p.isConnectionHealthy(pc):
			healthy = append(healthy, pc)
		default:
			// Not leased and not healthy, and it will not recover: close it
			// and let the pool refill below.
			_ = pc.conn.Close()
		}
	}
	p.connections = healthy

	// Ensure minimum pool size.
	added := false
	for len(p.connections) < p.transport.cfg.PoolMinSize {
		if err := p.addConnection(); err != nil {
			break
		}
		added = true
	}

	// Capacity that appears here is capacity a waiter is entitled to. Nothing
	// else will wake it: the connections this loop replaced were unhealthy and
	// idle, so no Put is coming for them.
	//
	// ...Locked, because this function holds mu for its whole body and
	// sync.Mutex is not reentrant: the unlocked form would deadlock the health
	// check against itself.
	if added {
		p.signalAvailableLocked()
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
	_ transport.Factory   = (*Factory)(nil)
)
