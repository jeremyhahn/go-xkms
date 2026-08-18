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

// Package apimodule registers go-xkms's hardware crypto + identity plane into
// go-qrdb's unified multi-protocol server as a qrdbsdk.ServiceModule (the
// Phase 3 seam of plans/unified-api-server-2026-08-14.md). The stack-wide
// convention is one module per provider project, named after the project:
// go-xkms exports this Module ("xkms"); go-quicbaas and go-trusted-platform
// export their own, and any daemon hosting an embedded qrdb node composes the
// modules it needs via qrdbsdk.WithModule.
//
// Module carries the WHOLESALE KeystoreService gRPC surface — the same
// pb.KeystoreServiceServer implementation every legacy transport drives — so
// that when the embedded qrdb node's server transports are enabled (the Phase 4
// cutover), the full xkms capability plane is served by qrdb's one server.
// Registration is ADDITIVE: xkms's legacy transport stacks keep serving exactly
// as today.
//
// Authorization: on the unified server, per-method authorization is enforced
// by qrdb's reflection interceptor reading the option (qrdb.v1.permission)
// annotation on each RPC (pkg/api/grpc/proto/xkmsv1/xkms.proto) — an
// unannotated RPC is DEFAULT-DENY there. The in-handler authorizer of the
// registered Service is therefore constructed the same way the Unix-socket
// listener constructs it (nil authorizer + WithLocalTrust, see
// pkg/api/unix/grpc_server.go): the interceptor is the gate, and a second
// in-handler RBAC pass would double-authorize every call against a different
// decision point.
package apimodule

import (
	"context"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	grpcapi "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// ModuleName is the unique ServiceModule name go-xkms's module registers
// under; qrdb's WithModule fails fast on a duplicate.
const ModuleName = "xkms"

// NilServiceResolverError is returned by NewModule when constructed
// without a service resolver: the module would have no way to ever reach the
// XKMSService, so construction fails instead of registering a dead surface.
type NilServiceResolverError struct{}

// Error implements the error interface.
func (e *NilServiceResolverError) Error() string {
	return "apimodule: NewModule requires a non-nil XKMSService resolver"
}

// ServiceResolver returns the composed *xkms.XKMSService, or nil while it is
// not yet available.
//
// It exists because of a construction-order inversion in xkmsd: the embedded
// qrdb node is built by initEmbeddedQRDBNode (pkg/server/qrdb_node.go), which
// runs from initializeQRDBStorage near the top of server.New — and when the
// node's server transports are enabled, node construction runs the full
// server.Start pipeline, invoking every module's RegisterGRPC immediately.
// The XKMSService, by contrast, is composed much later in server.New (after
// backends, CA, and first-boot). A module holding the service directly would
// therefore always register a nil service. The resolver defers the binding to
// the first RPC, by which point server.New has completed.
type ServiceResolver func() *xkms.XKMSService

// SSHClientResolver returns the SSH SDK client wired into the Service (the
// same auxiliary wiring the Unix listener performs via SetSSHClient), or nil
// when the SSH subsystem is unavailable — SSH RPCs then answer Unavailable.
// It is a resolver for the same late-binding reason as ServiceResolver.
type SSHClientResolver func() sdkssh.Client

// Option configures optional Module behavior at construction time.
type Option func(*Module)

// WithSSHClient wires the SSH SDK client resolver used by the SSH RPC
// handlers, mirroring the Unix listener's SetSSHClient auxiliary wiring.
func WithSSHClient(resolve SSHClientResolver) Option {
	return func(m *Module) {
		m.resolveSSH = resolve
	}
}

// QRDBClientResolver returns the host's embedded/dialed qrdb node client, or
// nil while it is not yet available. It backs the module's self-built REST
// surface (rest.NewHostServer) when the host does not supply its own
// *rest.Server via WithRESTServer: WebAuthn user/credential persistence,
// refresh-token storage, and the mTLS/PIV login identity plane all resolve
// through it, exactly as xkmsd's own composition (pkg/server) resolves them
// through its own qrdb client.
type QRDBClientResolver func() *qrdbsdk.Client

// WithQRDBClient wires the host's qrdb client resolver. Absent one, the
// module's self-built REST surface still serves the crypto-operation
// surface (keys, certs, seal, ...) from the resolved XKMSService, but the
// WebAuthn and mTLS/PIV login route families stay disabled — the same
// RouteEnabled gating a resolver-supplied server with no qrdb client would
// produce.
func WithQRDBClient(resolve QRDBClientResolver) Option {
	return func(m *Module) {
		m.resolveQRDBClient = resolve
	}
}

// WithWebAuthnConfig enables the module's self-built WebAuthn relying-party
// surface, using the same operator-facing configuration shape xkmsd's own
// config file section uses (pkg/config WebAuthnConfig: rp_id, rp_origins,
// rp_display_name, ...). Requires WithQRDBClient; without one the WebAuthn
// routes stay unmounted (BuildWebAuthnService requires a qrdb client).
func WithWebAuthnConfig(cfg *config.WebAuthnConfig) Option {
	return func(m *Module) {
		m.webauthnConfig = cfg
	}
}

// WithSessionOptions tunes the module's self-built JWT signing key, token
// claims/TTLs, and login rate limiting. Nil (the default) uses the same
// defaults xkmsd itself derives.
func WithSessionOptions(opts *rest.SessionOptions) Option {
	return func(m *Module) {
		m.sessionOptions = opts
	}
}

// WithPIVLogin enables the module's self-built TLS-client-certificate login
// exchange at POST /api/v1/auth/login/piv.
func WithPIVLogin(opts *rest.PIVLoginOptions) Option {
	return func(m *Module) {
		m.pivLogin = opts
	}
}

// Module is go-xkms's hardware crypto + identity plane as a qrdb
// ServiceModule. It registers the full KeystoreService gRPC surface into the
// unified server's gRPC-wire transports (gRPC and unix), the full REST route
// table (module_http.go), and the full MCP tool surface (module_mcp.go).
// The REST surface binds to a host-supplied *rest.Server (WithRESTServer) or,
// absent one, self-builds a working REST surface from the resolved
// XKMSService and whatever host inputs were configured (WithQRDBClient,
// WithWebAuthnConfig, WithSessionOptions, WithPIVLogin) — see module_host.go.
//
// Start and Stop are inherited BaseModule no-ops by design: the XKMSService
// lifecycle (backends, CA, barrier, TPM/PKCS#11 handles) is owned by
// pkg/server, which composes the service and tears it down — the module only
// exposes it and must not double-manage those resources.
type Module struct {
	qrdbsdk.BaseModule

	resolve           ServiceResolver
	resolveSSH        SSHClientResolver
	resolveREST       RESTResolver
	resolveMCP        MCPResolver
	resolveQRDBClient QRDBClientResolver

	uiPrefix       string
	uiRedirectRoot bool

	// webauthnConfig, sessionOptions, and pivLogin configure the module's
	// self-built REST surface (rest.NewHostServer, module_host.go) when the
	// host supplies no WithRESTServer resolver. Nil leaves the
	// corresponding surface at rest.NewHostServer's own defaults / disabled
	// state.
	webauthnConfig *config.WebAuthnConfig
	sessionOptions *rest.SessionOptions
	pivLogin       *rest.PIVLoginOptions

	// service memoizes the lazily-constructed keystore Service. Lock-free:
	// concurrent first calls may both construct, and CompareAndSwap keeps
	// exactly one (construction is cheap and side-effect free).
	service atomic.Pointer[grpcapi.Service]

	// selfREST memoizes the module's self-built REST surface
	// (rest.NewHostServer), built the first time restServer() is called
	// with no WithRESTServer resolver configured. Lock-free: concurrent
	// first calls may both construct, and CompareAndSwap keeps exactly one.
	selfREST atomic.Pointer[rest.Server]
}

// Compile-time interface check.
var _ qrdbsdk.ServiceModule = (*Module)(nil)

// NewModule builds go-xkms's ServiceModule around the XKMSService resolver.
// A nil resolver is a composition error and fails construction.
func NewModule(resolve ServiceResolver, opts ...Option) (*Module, error) {
	if resolve == nil {
		return nil, &NilServiceResolverError{}
	}
	m := &Module{resolve: resolve}
	for _, opt := range opts {
		opt(m)
	}
	// Contribute the module's permission set into qrdb's role-grant
	// registry before the embedded node seeds roles (module_grants.go).
	registerRoleGrants()
	return m, nil
}

// Name uniquely identifies the module.
func (m *Module) Name() string { return ModuleName }

// RegisterGRPC attaches the full KeystoreService to the unified server. The
// registered service descriptor is late-bound: each method handler resolves
// the Service on invocation (see keystore), so registration is valid even
// though it runs before xkmsd has composed the XKMSService. Until the
// resolver yields a service, every RPC answers codes.Unavailable — fail-safe,
// never a nil dereference.
func (m *Module) RegisterGRPC(reg grpc.ServiceRegistrar) {
	reg.RegisterService(lazyServiceDesc(&pb.KeystoreService_ServiceDesc, m.keystore), nil)
}

// PublicGRPCMethods declares the KeystoreService RPCs that must be reachable
// without authentication, admitting them into qrdb's unified-server gRPC
// interceptor the same way HTTPRegistrar.HandlePublic admits the mirrored
// REST routes (GET /health, GET /api/v1/algorithms — see routes.go). Health
// and Algorithms are unannotated in xkms.proto (no (qrdb.v1.permission)
// option), so without this declaration qrdb's reflection interceptor
// DEFAULT-DENYs them before the handler ever runs (see the interceptor's
// doc comment in go-qrdb/pkg/api/grpc/proto/qrdbv1/authz.proto) — the
// Unix-socket transport never hit this because it grants local callers
// WithLocalTrust() instead of going through the reflection interceptor.
func (m *Module) PublicGRPCMethods() []string {
	return []string{
		"/xkms.v1.KeystoreService/Health",
		"/xkms.v1.KeystoreService/Algorithms",
	}
}

// keystore returns the memoized keystore Service, constructing it on first
// use once the resolver yields the composed XKMSService.
//
// The Service is built exactly the way the Unix-socket listener builds it
// (pkg/api/unix/grpc_server.go): nil authorizer + WithLocalTrust. On the
// unified server the authorization gate is qrdb's reflection interceptor
// enforcing option (qrdb.v1.permission) per RPC, so the in-handler authorizer
// intentionally stays disabled — the interceptor decides before the handler
// runs, and unannotated RPCs never reach it at all.
func (m *Module) keystore() (pb.KeystoreServiceServer, error) {
	if svc := m.service.Load(); svc != nil {
		return svc, nil
	}
	x := m.resolve()
	if x == nil {
		return nil, status.Error(codes.Unavailable,
			"xkms crypto service is not yet available (server still composing)")
	}
	svc := grpcapi.NewService(nil, nil, x, grpcapi.WithLocalTrust())
	if m.resolveSSH != nil {
		if client := m.resolveSSH(); client != nil {
			svc.SetSSHClient(client)
		}
	}
	if m.service.CompareAndSwap(nil, svc) {
		return svc, nil
	}
	return m.service.Load(), nil
}

// lazyServiceDesc copies a generated grpc.ServiceDesc, rebinding every unary
// and stream handler to resolve its implementation through impl at call time
// instead of at registration time. A resolution error is returned to the
// caller as the RPC's status; the wire surface (service name, method set,
// metadata, reflection descriptors) is byte-identical to the generated one.
func lazyServiceDesc(src *grpc.ServiceDesc, impl func() (pb.KeystoreServiceServer, error)) *grpc.ServiceDesc {
	desc := &grpc.ServiceDesc{
		ServiceName: src.ServiceName,
		HandlerType: src.HandlerType,
		Metadata:    src.Metadata,
		Methods:     make([]grpc.MethodDesc, 0, len(src.Methods)),
		Streams:     make([]grpc.StreamDesc, 0, len(src.Streams)),
	}
	for _, md := range src.Methods {
		handler := md.Handler
		desc.Methods = append(desc.Methods, grpc.MethodDesc{
			MethodName: md.MethodName,
			Handler: func(_ any, ctx context.Context, dec func(any) error, interceptor grpc.UnaryServerInterceptor) (any, error) {
				svc, err := impl()
				if err != nil {
					return nil, err
				}
				return handler(svc, ctx, dec, interceptor)
			},
		})
	}
	// KeystoreService defines no streaming RPCs today; this keeps the copy
	// correct-by-construction if a regeneration ever adds one.
	for _, sd := range src.Streams {
		handler := sd.Handler
		desc.Streams = append(desc.Streams, grpc.StreamDesc{
			StreamName:    sd.StreamName,
			ServerStreams: sd.ServerStreams,
			ClientStreams: sd.ClientStreams,
			Handler: func(_ any, ss grpc.ServerStream) error {
				svc, err := impl()
				if err != nil {
					return err
				}
				return handler(svc, ss)
			},
		})
	}
	return desc
}
