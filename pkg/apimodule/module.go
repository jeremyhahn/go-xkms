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
// go-qrdb's unified multi-protocol server as a qrdbserver.ServiceModule (the
// Phase 3 seam of plans/unified-api-server-2026-08-14.md). The stack-wide
// convention is one module per provider project, named after the project:
// go-xkms exports this Module ("xkms"); go-quicbaas and go-trusted-platform
// export their own, and any daemon hosting an embedded qrdb node composes the
// modules it needs via qrdbserver.WithModule.
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
	"sync"
	"sync/atomic"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbserver "github.com/jeremyhahn/go-qrdb/sdk/go/server"

	grpcapi "github.com/jeremyhahn/go-xkms/pkg/api/grpc"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/compose"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/datastore"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	qrdbstorage "github.com/jeremyhahn/go-xkms/pkg/storage/qrdb"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/vtpm"
	"github.com/jeremyhahn/go-xkms/pkg/types"
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

// WithServiceContext wires the host's service-context binder: every call a
// datastore the module opens on the host's qrdb client makes -- database
// initialisation and each later DAO call -- runs on the context bind
// derives, the way xkmsd binds its own datastore (pkg/server). An embedded
// node's Node.ServiceContext is one: it binds the node's service principal,
// without which a node that enforces authentication refuses the module's
// storage with qrdbsdk.ErrUnauthenticated. Nil runs the calls on the
// caller's context.
func WithServiceContext(bind qrdbstorage.CallContext) Option {
	return func(m *Module) {
		m.serviceContext = bind
	}
}

// openDatastore opens a datastore on the host's qrdb client, bound to the
// host's service context (WithServiceContext).
func (m *Module) openDatastore(client *qrdbsdk.Client) (*datastore.Datastore, error) {
	return datastore.New(client, config.DatastoreConfig{}, datastore.WithCallContext(m.serviceContext))
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

// WithPasswordVaultRelyingParty sets the WebAuthn relying party ID -- the
// domain the host's web console is served from -- that password-vault
// passkey factors are created for. Unset, the module uses the RPID of
// WithWebAuthnConfig; with neither, passkey factors are unavailable
// (staticpw.ErrVaultPasskeyUnavailable). A host serving WebAuthn itself
// passes its own relying party ID here.
func WithPasswordVaultRelyingParty(rpID string) Option {
	return func(m *Module) {
		m.vaultRelyingParty = rpID
	}
}

// passwordVaultRelyingParty is the relying party ID vault passkeys are
// created for: WithPasswordVaultRelyingParty, else WithWebAuthnConfig's.
func (m *Module) passwordVaultRelyingParty() string {
	if m.vaultRelyingParty != "" {
		return m.vaultRelyingParty
	}
	if m.webauthnConfig != nil {
		return m.webauthnConfig.RPID
	}
	return ""
}

// WithWebAuthnCredentialStoreDecorator wraps the qrdb-backed credential
// store the module's self-built WebAuthn relying party persists passkeys
// through, so a composing host can attach its own registration side effects
// — an identity-plane auth factor, an audit record — to credentials enrolled
// through the module's own ceremony routes instead of building a second
// relying party over the same store.
//
// Requires WithWebAuthnConfig and WithQRDBClient (the decorator only applies
// to the store those two build). Nil, or an unset option, leaves the qrdb
// store in place unchanged.
//
// A decorator that returns nil fails WebAuthn construction with
// rest.ErrWebAuthnCredentialStoreDecoratorNil rather than yielding a relying
// party that cannot persist a passkey; as with every other WebAuthn
// construction failure on the self-built surface, the error is logged and
// the WebAuthn route family stays unmounted while the rest of the surface
// (keys, certs, seal) serves on.
func WithWebAuthnCredentialStoreDecorator(decorate rest.WebAuthnCredentialStoreDecorator) Option {
	return func(m *Module) {
		m.webauthnCredentialStoreDecorator = decorate
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

// BarrierRegistryResolver returns the host's tenant barrier registry (an
// embedded qrdb node's BarrierRegistry), or nil when the host has none.
type BarrierRegistryResolver func() *qrdbsdk.BarrierRegistry

// WithBarrierRegistry wires the host's tenant barrier registry into the
// module's host composition (pkg/compose). It enables the "barrier"
// credential strategy and the barrier-backed features. Only consulted when
// the module self-builds (no WithRESTServer).
func WithBarrierRegistry(resolve BarrierRegistryResolver) Option {
	return func(m *Module) {
		m.resolveBarrierRegistry = resolve
	}
}

// TenantStoresResolver returns the host's per-tenant store resolver (an
// embedded qrdb node's Services().StoreResolver), or nil when the host has
// none.
type TenantStoresResolver func() qrdbsdk.TenantStoreResolver

// WithTenantStores wires the host's per-tenant store resolver into the
// module's host composition (pkg/compose). It enables per-tenant Password
// Manager routing: each tenant's entries live in that tenant's system
// database, behind that tenant's barrier. Only consulted when the module
// self-builds (no WithRESTServer).
func WithTenantStores(resolve TenantStoresResolver) Option {
	return func(m *Module) {
		m.resolveTenantStores = resolve
	}
}

// WithPINBackend supplies the host's PIN backend (the one its qrdb node was
// built with, qrdbsdk.WithPINBackend). Its user PIN opens a tenant's
// Password Manager session (/api/v1/password-vault/unlock), so without it tenant
// password stores stay locked; it also backs the /api/v1/pin/* routes.
func WithPINBackend(pin qrdbsdk.PINBackend) Option {
	return func(m *Module) {
		m.pinBackend = pin
	}
}

// WithPlatformSealer enables the platform sealed-secret store
// (/api/v1/platform/*): records are sealed through sealer, which implements
// the named seal strategy (tpm2, pkcs11, awskms, gcpkms, azurekv, vault,
// passphrase). Requires WithQRDBClient for storage.
func WithPlatformSealer(strategy string, sealer types.Sealer) Option {
	return func(m *Module) {
		m.platformSealer = &compose.PlatformSealer{Strategy: seal.StrategyID(strategy), Sealer: sealer}
	}
}

// WithCredentialStrategy selects how the backend credential service
// (/api/v1/credentials/*) seals credentials: "manual" (the default:
// operator-submitted, held in memory), "barrier" (requires
// WithBarrierRegistry), or a platform strategy (requires
// WithPlatformSealer).
func WithCredentialStrategy(strategy string) Option {
	return func(m *Module) {
		m.credentialStrategy = strategy
	}
}

// WithCA enables the Certificate Authority (/api/v1/ca/* and the CA RPCs)
// from cfg, the same identity-hierarchy shape xkmsd's ca config section
// uses. Each CA key lives in the XKMSService backend named by its store
// type. The CA loads its persisted hierarchy, or initializes one on first
// use. Requires WithQRDBClient for storage.
func WithCA(cfg *ca.MultiIdentityCAConfig) Option {
	return func(m *Module) {
		m.caConfig = cfg
	}
}

// WithVTPM makes vtpm mode available to the TPM policy service a self-built
// module composes when its XKMSService has a TPM2 backend: each vtpm-mode
// tenant's objects live in a virtual TPM (swtpm) the module's process
// supervises under cfg. Without it a tenant set to vtpm mode is refused with
// tpmpolicy.ErrVTPMUnavailable.
func WithVTPM(cfg *vtpm.Config) Option {
	return func(m *Module) {
		m.vtpm = cfg
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
// A self-built module also composes xkms's store-backed features (Password
// Manager, platform store, credentials, SSH, CA, TPM policies) from the
// host's dependencies (WithBarrierRegistry, WithTenantStores, WithPINBackend,
// WithPlatformSealer, WithCredentialStrategy, WithCA, WithVTPM, and the
// XKMSService's TPM2 backend) through pkg/compose, the path xkmsd builds them
// through.
//
// Start and Stop are inherited BaseModule no-ops by design: the XKMSService
// lifecycle (backends, CA, barrier, TPM/PKCS#11 handles) is owned by
// pkg/server, which composes the service and tears it down — the module only
// exposes it and must not double-manage those resources.
type Module struct {
	qrdbserver.BaseModule

	resolve           ServiceResolver
	resolveSSH        SSHClientResolver
	resolveREST       RESTResolver
	resolveMCP        MCPResolver
	resolveQRDBClient QRDBClientResolver

	// serviceContext is WithServiceContext's binder, applied to every
	// datastore the module opens (openDatastore).
	serviceContext qrdbstorage.CallContext

	// Host composition inputs (module_host.go): the dependencies the module
	// builds its store-backed features from when it self-builds.
	resolveBarrierRegistry BarrierRegistryResolver
	resolveTenantStores    TenantStoresResolver
	pinBackend             qrdbsdk.PINBackend
	platformSealer         *compose.PlatformSealer
	credentialStrategy     string
	caConfig               *ca.MultiIdentityCAConfig
	vtpm                   *vtpm.Config

	uiPrefix       string
	uiRedirectRoot bool

	// webauthnConfig, sessionOptions, and pivLogin configure the module's
	// self-built REST surface (rest.NewHostServer, module_host.go) when the
	// host supplies no WithRESTServer resolver. Nil leaves the
	// corresponding surface at rest.NewHostServer's own defaults / disabled
	// state.
	webauthnConfig *config.WebAuthnConfig
	sessionOptions *rest.SessionOptions

	// vaultRelyingParty is WithPasswordVaultRelyingParty's relying party.
	vaultRelyingParty string
	pivLogin          *rest.PIVLoginOptions

	// webauthnCredentialStoreDecorator wraps the credential store the
	// self-built WebAuthn relying party persists through
	// (WithWebAuthnCredentialStoreDecorator). Nil leaves the qrdb-backed
	// store xkms builds in place.
	webauthnCredentialStoreDecorator rest.WebAuthnCredentialStoreDecorator

	// service memoizes the lazily-constructed keystore Service. Lock-free:
	// concurrent first calls may both construct, and CompareAndSwap keeps
	// exactly one (construction is cheap and side-effect free).
	service atomic.Pointer[grpcapi.Service]

	// selfREST memoizes the module's self-built REST surface
	// (rest.NewHostServer), built the first time restServer() is called
	// with no WithRESTServer resolver configured. Lock-free: concurrent
	// first calls may both construct, and CompareAndSwap keeps exactly one.
	selfREST atomic.Pointer[rest.Server]

	// stores memoizes the host composition (hostStores). Unlike the
	// service and REST memos it must be built exactly once -- building the
	// CA initializes a root on first use -- so construction is serialized
	// by composeMu; the atomic keeps the steady-state read lock-free.
	stores    atomic.Pointer[compose.Stores]
	composeMu sync.Mutex

	// attestedCallerPolicy is WithAttestedCallerGate's policy, and peerGate
	// the gate NewModule built from it (module_peergate.go). peerGateWired
	// records that the gate's collector reached the resolved service.
	attestedCallerPolicy *peergate.GatePolicy
	peerGate             *peergate.Gate
	peerGateWired        atomic.Bool
}

// Compile-time interface check.
var _ qrdbserver.ServiceModule = (*Module)(nil)

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
	if err := m.buildAttestedCallerGate(); err != nil {
		return nil, err
	}
	// Contribute the module's permission set into qrdb's role-grant
	// registry before the embedded node seeds roles (module_grants.go).
	RegisterRoleGrants()
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
// doc comment in go-qrdb/sdk/go/proto/qrdb/v1/permission.proto) — the
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
	m.wirePeerEvidenceCollector()
	if svc := m.service.Load(); svc != nil {
		return svc, nil
	}
	x := m.resolve()
	if x == nil {
		return nil, status.Error(codes.Unavailable,
			"xkms crypto service is not yet available (server still composing)")
	}
	var composed *compose.Stores
	if m.selfBuilds() {
		composed = m.hostStores(x)
	}
	svc := grpcapi.NewService(nil, nil, x, grpcapi.WithLocalTrust())
	switch {
	case m.resolveSSH != nil:
		if client := m.resolveSSH(); client != nil {
			svc.SetSSHClient(client)
		}
	case composed != nil && composed.SSH != nil:
		svc.SetSSHClient(composed.SSH)
	}
	// x itself is the CA servicer: it exposes the transport-shaped CA
	// methods (GetCACertificate, SignCSR, IssueCertificate, ...) the CA RPC
	// handlers delegate to. Gated on x.CA() != nil, mirroring the condition
	// pkg/server's buildRESTConfig uses for restConfig.CA (s.ca != nil) and
	// the Unix listener uses for GRPCConfig.CA (go-xkms#951): a host whose
	// XKMSService composed no CA gets no CA RPC surface here either, instead
	// of a surface that always answers "not configured" at a lower layer.
	if x.CA() != nil {
		svc.SetCA(x)
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
