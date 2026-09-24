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

// Package trustedca provides the official Go SDK for the Trusted CA ACME server.
//
// The SDK supports the REST, QUIC, Unix, MCP, and Embedded transport
// protocols and provides a unified client interface for interacting with the
// RFC-8555 compliant ACME server. gRPC is not one of them: RFC 8555 defines
// ACME as HTTP+JWS, so there is no gRPC binding for the protocol, and
// NewClient refuses TransportGRPC (the zero value) with a typed error at
// construction rather than handing back a client whose ACME calls would each
// fail individually on their first Request (go-xkms#727). The gRPC transport
// package still exists for the Admin API and can be driven directly with
// admin.NewClient, bypassing this combined client.
//
// # Quick Start
//
// Create a unified client to access all Trusted CA services:
//
//	client, err := trustedca.NewClient("/var/run/trusted-ca.sock", trustedca.WithUnix("/var/run/trusted-ca.sock"))
//	if err != nil {
//	    log.Fatal(err)
//	}
//	defer client.Close()
//
//	// Get ACME directory
//	dir, err := client.Directory().Get(ctx, &trustedca.GetDirectoryRequest{})
//
//	// Create an account
//	account, err := client.Account().Create(ctx, &trustedca.CreateAccountRequest{
//	    Contact: []string{"mailto:admin@example.com"},
//	    TermsOfServiceAgreed: true,
//	})
//
// # Connection Options
//
// The SDK supports various connection methods:
//
//	// Unix socket (recommended for local)
//	client, _ := trustedca.NewClient("/var/run/trusted-ca.sock", trustedca.WithUnix("/var/run/trusted-ca.sock"))
//
//	// REST transport with mTLS
//	client, _ := trustedca.NewClient("https://localhost:9443",
//	    trustedca.WithREST(),
//	    trustedca.WithTLS(trustedca.TLSConfig{
//	        CertFile: "client.crt",
//	        KeyFile:  "client.key",
//	        CAFile:   "ca.crt",
//	    }),
//	)
//
//	// REST transport
//	client, _ := trustedca.NewClient("https://ca.example.com:8443",
//	    trustedca.WithREST(),
//	)
//
//	// QUIC transport
//	client, _ := trustedca.NewClient("ca.example.com:9444",
//	    trustedca.WithQUIC(),
//	)
//
//	// Embedded transport (in-process)
//	client, _ := trustedca.NewClient("", trustedca.WithEmbedded(acmeService))
//
// # Available Services
//
//   - Account: ACME account operations
//   - Order: Certificate order lifecycle
//   - Authorization: Domain authorization
//   - Challenge: Challenge verification
//   - Certificate: Certificate issuance and revocation
//   - Directory: ACME directory resource
//   - Nonce: Replay protection
package trustedca

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/account"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/admin"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/authorization"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/certificate"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/challenge"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/directory"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/nonce"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/client/order"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/errors"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/embedded"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/mcp"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/quic"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/rest"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/transport/unix"
	"github.com/jeremyhahn/go-xkms/sdk/go/acme/workflow"
)

// =============================================================================
// Transport Types
// =============================================================================

// TransportType identifies the transport protocol.
type TransportType int

const (
	// TransportGRPC is the zero value of TransportType. NewClient refuses it
	// with a typed error: ACME (RFC 8555) is HTTP+JWS and has no gRPC
	// binding, so a caller must select a supported transport explicitly
	// (WithREST, WithQUIC, WithUnix, WithMCP, or WithEmbedded).
	TransportGRPC TransportType = iota
	// TransportREST uses REST/HTTP protocol.
	TransportREST
	// TransportQUIC uses QUIC protocol.
	TransportQUIC
	// TransportUnix uses gRPC over Unix Domain Socket.
	TransportUnix
	// TransportEmbedded uses in-process direct service access.
	TransportEmbedded
	// TransportMCP uses Model Context Protocol (JSON-RPC 2.0 over HTTP).
	TransportMCP
)

// String returns the string representation of the transport type.
func (t TransportType) String() string {
	switch t {
	case TransportGRPC:
		return "grpc"
	case TransportREST:
		return "rest"
	case TransportQUIC:
		return "quic"
	case TransportUnix:
		return "unix"
	case TransportEmbedded:
		return "embedded"
	case TransportMCP:
		return "mcp"
	default:
		return "unknown"
	}
}

// =============================================================================
// TLS Configuration
// =============================================================================

// TLSConfig holds TLS configuration for mTLS authentication.
type TLSConfig struct {
	// CertFile is the path to the client certificate file.
	CertFile string
	// KeyFile is the path to the client private key file.
	KeyFile string
	// CAFile is the path to the CA certificate file for server verification.
	CAFile string
	// ServerName overrides the server name for certificate verification.
	ServerName string
}

// =============================================================================
// Client Options
// =============================================================================

// clientOptions holds all client configuration options.
type clientOptions struct {
	transportType      TransportType
	timeout            time.Duration
	keepaliveTime      time.Duration
	keepaliveTimeout   time.Duration
	maxRetries         int
	retryBackoff       time.Duration
	maxRetryBackoff    time.Duration
	tlsEnabled         bool
	tlsConfig          *tls.Config
	insecure           bool
	poolEnabled        bool
	poolMinSize        int
	poolMaxSize        int
	poolMaxAge         time.Duration
	poolHealthInterval time.Duration
	poolAcquireTimeout time.Duration
	unixSocketPath     string
	embeddedService    interface{}
	logger             *slog.Logger
}

// Option is a functional option for configuring the client.
type Option func(*clientOptions) error

// defaultOptions returns clientOptions with sensible defaults.
func defaultOptions() *clientOptions {
	return &clientOptions{
		transportType:      TransportGRPC,
		timeout:            30 * time.Second,
		keepaliveTime:      10 * time.Second,
		keepaliveTimeout:   5 * time.Second,
		maxRetries:         3,
		retryBackoff:       100 * time.Millisecond,
		maxRetryBackoff:    5 * time.Second,
		poolMinSize:        5,
		poolMaxSize:        50,
		poolMaxAge:         time.Hour,
		poolHealthInterval: 30 * time.Second,
		poolAcquireTimeout: 5 * time.Second,
	}
}

// WithTimeout sets the request timeout.
func WithTimeout(d time.Duration) Option {
	return func(o *clientOptions) error {
		if d <= 0 {
			return errors.NewInvalidInput("WithTimeout", "timeout must be positive")
		}
		o.timeout = d
		return nil
	}
}

// WithKeepalive sets the keepalive parameters.
func WithKeepalive(time, timeout time.Duration) Option {
	return func(o *clientOptions) error {
		if time <= 0 {
			return errors.NewInvalidInput("WithKeepalive", "keepalive time must be positive")
		}
		if timeout <= 0 {
			return errors.NewInvalidInput("WithKeepalive", "keepalive timeout must be positive")
		}
		o.keepaliveTime = time
		o.keepaliveTimeout = timeout
		return nil
	}
}

// WithRetry configures retry behavior.
func WithRetry(maxRetries int, backoff time.Duration) Option {
	return func(o *clientOptions) error {
		if maxRetries < 0 {
			return errors.NewInvalidInput("WithRetry", "maxRetries cannot be negative")
		}
		if backoff < 0 {
			return errors.NewInvalidInput("WithRetry", "backoff cannot be negative")
		}
		o.maxRetries = maxRetries
		o.retryBackoff = backoff
		return nil
	}
}

// WithMaxRetryBackoff sets the maximum retry backoff duration.
func WithMaxRetryBackoff(d time.Duration) Option {
	return func(o *clientOptions) error {
		if d <= 0 {
			return errors.NewInvalidInput("WithMaxRetryBackoff", "max backoff must be positive")
		}
		o.maxRetryBackoff = d
		return nil
	}
}

// WithTLS configures mTLS authentication using certificate files.
func WithTLS(cfg TLSConfig) Option {
	return func(o *clientOptions) error {
		tlsConfig, err := loadTLSConfig(cfg)
		if err != nil {
			return err
		}
		o.tlsEnabled = true
		o.tlsConfig = tlsConfig
		o.insecure = false
		return nil
	}
}

// WithTLSConfig sets a custom tls.Config directly.
func WithTLSConfig(cfg *tls.Config) Option {
	return func(o *clientOptions) error {
		if cfg == nil {
			return errors.NewInvalidInput("WithTLSConfig", "tls config cannot be nil")
		}
		o.tlsEnabled = true
		o.tlsConfig = cfg
		o.insecure = false
		return nil
	}
}

// WithInsecure disables TLS (for development only).
func WithInsecure() Option {
	return func(o *clientOptions) error {
		o.tlsEnabled = false
		o.tlsConfig = nil
		o.insecure = true
		return nil
	}
}

// WithConnectionPool enables connection pooling (gRPC only).
func WithConnectionPool(minSize, maxSize int) Option {
	return func(o *clientOptions) error {
		if minSize <= 0 {
			return errors.NewInvalidInput("WithConnectionPool", "minSize must be positive")
		}
		if maxSize < minSize {
			return errors.NewInvalidInput("WithConnectionPool", "maxSize must be >= minSize")
		}
		o.poolEnabled = true
		o.poolMinSize = minSize
		o.poolMaxSize = maxSize
		return nil
	}
}

// WithPoolMaxAge sets the maximum age of pooled connections.
func WithPoolMaxAge(d time.Duration) Option {
	return func(o *clientOptions) error {
		if d <= 0 {
			return errors.NewInvalidInput("WithPoolMaxAge", "max age must be positive")
		}
		o.poolMaxAge = d
		return nil
	}
}

// WithPoolAcquireTimeout sets how long a pooled Get waits for a connection to
// be returned before reporting the pool exhausted.
//
// A saturated pool waits rather than lending one connection to two callers
// (go-xkms#104), so this bounds that wait. It is not a request timeout: the
// request has not started yet.
func WithPoolAcquireTimeout(d time.Duration) Option {
	return func(o *clientOptions) error {
		if d <= 0 {
			return errors.NewInvalidInput("WithPoolAcquireTimeout", "acquire timeout must be positive")
		}
		o.poolAcquireTimeout = d
		return nil
	}
}

// WithPoolHealthInterval sets the health check interval for pooled connections.
func WithPoolHealthInterval(d time.Duration) Option {
	return func(o *clientOptions) error {
		if d <= 0 {
			return errors.NewInvalidInput("WithPoolHealthInterval", "interval must be positive")
		}
		o.poolHealthInterval = d
		return nil
	}
}

// WithREST configures the client to use REST transport.
func WithREST() Option {
	return func(o *clientOptions) error {
		o.transportType = TransportREST
		return nil
	}
}

// WithQUIC configures the client to use QUIC transport.
func WithQUIC() Option {
	return func(o *clientOptions) error {
		o.transportType = TransportQUIC
		return nil
	}
}

// WithUnix configures the client to use Unix socket transport.
func WithUnix(socketPath string) Option {
	return func(o *clientOptions) error {
		if socketPath == "" {
			return errors.NewInvalidInput("WithUnix", "socket path cannot be empty")
		}
		o.transportType = TransportUnix
		o.unixSocketPath = socketPath
		return nil
	}
}

// WithEmbedded configures the client for in-process service access.
func WithEmbedded(svc interface{}) Option {
	return func(o *clientOptions) error {
		if svc == nil {
			return errors.NewInvalidInput("WithEmbedded", "service cannot be nil")
		}
		o.transportType = TransportEmbedded
		o.embeddedService = svc
		return nil
	}
}

// WithMCP configures the client to use MCP transport.
func WithMCP() Option {
	return func(o *clientOptions) error {
		o.transportType = TransportMCP
		return nil
	}
}

// WithLogger sets the logger for SDK operations.
func WithLogger(logger *slog.Logger) Option {
	return func(o *clientOptions) error {
		if logger == nil {
			return errors.NewInvalidInput("WithLogger", "logger cannot be nil")
		}
		o.logger = logger
		return nil
	}
}

// loadTLSConfig loads TLS configuration from files.
func loadTLSConfig(cfg TLSConfig) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if cfg.ServerName != "" {
		tlsConfig.ServerName = cfg.ServerName
	}

	if cfg.CertFile != "" && cfg.KeyFile != "" {
		cert, err := tls.LoadX509KeyPair(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeConfiguration, "loadTLSConfig",
				"failed to load client certificate")
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	if cfg.CAFile != "" {
		caCert, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, errors.Wrap(err, errors.CodeConfiguration, "loadTLSConfig",
				"failed to read CA certificate")
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New(errors.CodeConfiguration, "loadTLSConfig",
				"failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
	}

	return tlsConfig, nil
}

// =============================================================================
// Client Interface
// =============================================================================

// Client is the unified Trusted CA client interface.
type Client interface {
	Account() AccountClient
	Order() OrderClient
	Authorization() AuthorizationClient
	Challenge() ChallengeClient
	Certificate() CertificateClient
	Directory() DirectoryClient
	Nonce() NonceClient
	Admin() AdminClient
	Transport() Transport
	Workflow(opts ...workflow.Option) workflow.Workflow
	Close() error
}

// Transport is an alias for transport.Transport interface.
type Transport = transport.Transport

// =============================================================================
// Service Client Type Aliases
// =============================================================================

type (
	AccountClient       = account.Client
	OrderClient         = order.Client
	AuthorizationClient = authorization.Client
	ChallengeClient     = challenge.Client
	CertificateClient   = certificate.Client
	DirectoryClient     = directory.Client
	NonceClient         = nonce.Client
	AdminClient         = admin.Client
)

// =============================================================================
// Request/Response Type Aliases
// =============================================================================

// Account types
type (
	Account                  = account.Account
	AccountStatus            = account.Status
	CreateAccountRequest     = account.CreateRequest
	CreateAccountResponse    = account.CreateResponse
	GetAccountRequest        = account.GetRequest
	GetAccountResponse       = account.GetResponse
	UpdateAccountRequest     = account.UpdateRequest
	UpdateAccountResponse    = account.UpdateResponse
	DeactivateAccountRequest = account.DeactivateRequest
	KeyChangeRequest         = account.KeyChangeRequest
)

// Order types
type (
	Order                 = order.Order
	OrderStatus           = order.Status
	OrderIdentifier       = order.Identifier
	CreateOrderRequest    = order.CreateRequest
	CreateOrderResponse   = order.CreateResponse
	GetOrderRequest       = order.GetRequest
	GetOrderResponse      = order.GetResponse
	ListOrdersRequest     = order.ListRequest
	ListOrdersResponse    = order.ListResponse
	FinalizeOrderRequest  = order.FinalizeRequest
	FinalizeOrderResponse = order.FinalizeResponse
)

// Authorization types
type (
	Authorization                   = authorization.Authorization
	AuthorizationStatus             = authorization.Status
	GetAuthorizationRequest         = authorization.GetRequest
	GetAuthorizationResponse        = authorization.GetResponse
	DeactivateAuthorizationRequest  = authorization.DeactivateRequest
	DeactivateAuthorizationResponse = authorization.DeactivateResponse
)

// Challenge types
type (
	Challenge                  = challenge.Challenge
	ChallengeStatus            = challenge.Status
	ChallengeType              = challenge.ChallengeType
	GetChallengeRequest        = challenge.GetRequest
	GetChallengeResponse       = challenge.GetResponse
	RespondToChallengeRequest  = challenge.RespondRequest
	RespondToChallengeResponse = challenge.RespondResponse
)

// Certificate types
type (
	Certificate              = certificate.Certificate
	CertificateStatus        = certificate.Status
	RevocationReason         = certificate.RevocationReason
	GetCertificateRequest    = certificate.GetRequest
	GetCertificateResponse   = certificate.GetResponse
	RevokeCertificateRequest = certificate.RevokeRequest
)

// Directory types
type (
	Directory            = directory.Directory
	DirectoryMeta        = directory.Meta
	GetDirectoryRequest  = directory.GetRequest
	GetDirectoryResponse = directory.GetResponse
)

// Nonce types
type (
	NewNonceRequest  = nonce.NewRequest
	NewNonceResponse = nonce.NewResponse
)

// Admin types
type (
	AdminTenantClient              = admin.TenantClient
	AdminEABClient                 = admin.EABClient
	AdminRoleClient                = admin.RoleClient
	AdminUserClient                = admin.UserClient
	AdminCertificateClient         = admin.CertificateClient
	AdminAccountClient             = admin.AdminAccountClient
	AdminStatusClient              = admin.StatusClient
	AdminTenantCAClient            = admin.TenantCAClient
	AdminOrderClient               = admin.OrderClient
	AdminTenantInfo                = admin.TenantInfo
	AdminCreateTenantRequest       = admin.CreateTenantRequest
	AdminUpdateTenantRequest       = admin.UpdateTenantRequest
	AdminListTenantsRequest        = admin.ListTenantsRequest
	AdminListTenantsResponse       = admin.ListTenantsResponse
	AdminEABInfo                   = admin.EABInfo
	AdminCreateEABRequest          = admin.CreateEABRequest
	AdminCreateEABResponse         = admin.CreateEABResponse
	AdminListEABRequest            = admin.ListEABRequest
	AdminListEABResponse           = admin.ListEABResponse
	AdminRole                      = admin.Role
	AdminCreateRoleRequest         = admin.CreateRoleRequest
	AdminUpdateRoleRequest         = admin.UpdateRoleRequest
	AdminListRolesRequest          = admin.ListRolesRequest
	AdminListRolesResponse         = admin.ListRolesResponse
	AdminUser                      = admin.User
	AdminCreateUserRequest         = admin.CreateUserRequest
	AdminUpdateUserRequest         = admin.UpdateUserRequest
	AdminListUsersRequest          = admin.ListUsersRequest
	AdminListUsersResponse         = admin.ListUsersResponse
	AdminCertificateInfo           = admin.CertificateInfo
	AdminListCertsRequest          = admin.ListCertificatesRequest
	AdminListCertsResponse         = admin.ListCertificatesResponse
	AdminAccountInfo               = admin.AccountInfo
	AdminListAccountsRequest       = admin.ListAccountsRequest
	AdminListAccountsResponse      = admin.ListAccountsResponse
	AdminCAStatus                  = admin.CAStatus
	AdminCAStats                   = admin.CAStats
	AdminPagination                = admin.Pagination
	AdminOrderInfo                 = admin.OrderInfo
	AdminListOrdersRequest         = admin.ListOrdersRequest
	AdminListOrdersResponse        = admin.ListOrdersResponse
	AdminTenantRootCAInfo          = admin.TenantRootCAInfo
	AdminTenantIntCAInfo           = admin.TenantIntCAInfo
	AdminTenantCAStatusInfo        = admin.TenantCAStatusInfo
	AdminCreateTenantRootCARequest = admin.CreateTenantRootCARequest
	AdminCreateTenantIntCARequest  = admin.CreateTenantIntermediateCARequest
	AdminUpdateTenantStatusRequest = admin.UpdateTenantStatusRequest
	AdminUpdateIntCAStatusRequest  = admin.UpdateIntermediateCAStatusRequest
)

// Workflow types
type (
	WorkflowInterface     = workflow.Workflow
	WorkflowOption        = workflow.Option
	WorkflowClient        = workflow.Client
	RegisterRequest       = workflow.RegisterRequest
	RegisterResponse      = workflow.RegisterResponse
	WorkflowCertRequest   = workflow.CertificateRequest
	WorkflowCertResponse  = workflow.CertificateResponse
	WorkflowRevokeRequest = workflow.RevokeRequest
	ChallengeHandler      = workflow.ChallengeHandler
	ChallengeHandlerFunc  = workflow.ChallengeHandlerFunc
)

// =============================================================================
// Status Constants
// =============================================================================

// Account status constants
const (
	AccountStatusValid       = account.StatusValid
	AccountStatusDeactivated = account.StatusDeactivated
	AccountStatusRevoked     = account.StatusRevoked
)

// Order status constants
const (
	OrderStatusPending    = order.StatusPending
	OrderStatusReady      = order.StatusReady
	OrderStatusProcessing = order.StatusProcessing
	OrderStatusValid      = order.StatusValid
	OrderStatusInvalid    = order.StatusInvalid
)

// Authorization status constants
const (
	AuthorizationStatusPending     = authorization.StatusPending
	AuthorizationStatusValid       = authorization.StatusValid
	AuthorizationStatusInvalid     = authorization.StatusInvalid
	AuthorizationStatusDeactivated = authorization.StatusDeactivated
	AuthorizationStatusExpired     = authorization.StatusExpired
	AuthorizationStatusRevoked     = authorization.StatusRevoked
)

// Challenge status constants
const (
	ChallengeStatusPending    = challenge.StatusPending
	ChallengeStatusProcessing = challenge.StatusProcessing
	ChallengeStatusValid      = challenge.StatusValid
	ChallengeStatusInvalid    = challenge.StatusInvalid
)

// Challenge type constants
const (
	ChallengeTypeHTTP01    = challenge.TypeHTTP01
	ChallengeTypeDNS01     = challenge.TypeDNS01
	ChallengeTypeTLSALPN01 = challenge.TypeTLSALPN01
)

// Certificate status constants
const (
	CertificateStatusValid   = certificate.StatusValid
	CertificateStatusRevoked = certificate.StatusRevoked
	CertificateStatusExpired = certificate.StatusExpired
)

// Revocation reason constants (RFC 5280)
const (
	RevocationReasonUnspecified          = certificate.ReasonUnspecified
	RevocationReasonKeyCompromise        = certificate.ReasonKeyCompromise
	RevocationReasonCACompromise         = certificate.ReasonCACompromise
	RevocationReasonAffiliationChanged   = certificate.ReasonAffiliationChanged
	RevocationReasonSuperseded           = certificate.ReasonSuperseded
	RevocationReasonCessationOfOperation = certificate.ReasonCessationOfOperation
	RevocationReasonCertificateHold      = certificate.ReasonCertificateHold
	RevocationReasonRemoveFromCRL        = certificate.ReasonRemoveFromCRL
	RevocationReasonPrivilegeWithdrawn   = certificate.ReasonPrivilegeWithdrawn
	RevocationReasonAACompromise         = certificate.ReasonAACompromise
)

// =============================================================================
// Client Implementation
// =============================================================================

type client struct {
	transport Transport
	opts      *clientOptions

	mu                  sync.RWMutex
	closed              bool
	accountClient       AccountClient
	orderClient         OrderClient
	authorizationClient AuthorizationClient
	challengeClient     ChallengeClient
	certificateClient   CertificateClient
	directoryClient     DirectoryClient
	nonceClient         NonceClient
	adminClient         AdminClient
	workflowInstance    workflow.Workflow
}

// NewClient creates a new Trusted CA client connected to the specified address.
func NewClient(address string, opts ...Option) (Client, error) {
	options := defaultOptions()

	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	if options.transportType != TransportEmbedded && address == "" {
		return nil, errors.NewInvalidInput("NewClient", "address cannot be empty for non-embedded transport")
	}

	// Auto-detect REST transport from HTTP URLs
	if strings.HasPrefix(address, "http://") || strings.HasPrefix(address, "https://") {
		if options.transportType == TransportGRPC {
			options.transportType = TransportREST
		}
	}

	t, err := createTransport(address, options)
	if err != nil {
		return nil, err
	}

	return &client{transport: t, opts: options}, nil
}

func createTransport(address string, opts *clientOptions) (Transport, error) {
	switch opts.transportType {
	case TransportGRPC:
		// ACME is RFC 8555 HTTP+JWS by design; there is no gRPC binding for
		// the protocol. Refuse here, at construction, instead of handing back
		// a client whose ACME calls (Account, Order, Directory, Nonce,
		// Challenge, Authorization, Certificate) would each fail individually
		// the first time they perform a Request (go-xkms#727).
		return nil, errors.NewUnimplemented("createTransport",
			"gRPC transport does not support the ACME protocol (RFC 8555 is HTTP+JWS); use WithREST, WithQUIC, WithUnix, WithMCP, or WithEmbedded")
	case TransportREST:
		return createRESTTransport(address, opts)
	case TransportQUIC:
		return createQUICTransport(address, opts)
	case TransportUnix:
		return createUnixTransport(opts)
	case TransportEmbedded:
		return createEmbeddedTransport(opts)
	case TransportMCP:
		return createMCPTransport(address, opts)
	default:
		return nil, errors.NewInvalidInput("createTransport", "unsupported transport type")
	}
}

func createRESTTransport(address string, opts *clientOptions) (Transport, error) {
	cfg := buildTransportConfig(address, opts)
	parsed := transport.ParseAddress(address)
	cfg.AddressType = parsed.Type
	return rest.NewTransport(cfg)
}

func createQUICTransport(address string, opts *clientOptions) (Transport, error) {
	cfg := buildTransportConfig(address, opts)
	parsed := transport.ParseAddress(address)
	cfg.AddressType = parsed.Type
	return quic.NewTransport(cfg)
}

func createUnixTransport(opts *clientOptions) (Transport, error) {
	cfg := &transport.Config{
		Address:          opts.unixSocketPath,
		AddressType:      transport.AddressTypeUnix,
		Timeout:          opts.timeout,
		TLSConfig:        opts.tlsConfig,
		KeepaliveTime:    opts.keepaliveTime,
		KeepaliveTimeout: opts.keepaliveTimeout,
		MaxRetries:       opts.maxRetries,
		RetryBackoff:     opts.retryBackoff,
		MaxRetryBackoff:  opts.maxRetryBackoff,
	}
	return unix.NewTransport(cfg)
}

// createEmbeddedTransport builds the in-process transport for WithEmbedded.
//
// WithEmbedded takes an interface{} because a caller may supply an ACME
// servicer, an admin servicer, or one value implementing both. The service is
// routed by asking which of the embedded transport's two service interfaces it
// satisfies, and a value satisfying both registers both route sets. Supplying a
// value that implements neither is a caller error rather than a client that
// silently answers nothing.
//
// The service used to be validated here and then dropped: NewTransport was
// called with no options, and it requires at least one service, so every
// WithEmbedded client failed to construct and TransportEmbedded was unreachable
// through NewClient.
func createEmbeddedTransport(opts *clientOptions) (Transport, error) {
	if opts.embeddedService == nil {
		return nil, errors.NewInvalidInput("createEmbeddedTransport", "embedded service cannot be nil")
	}

	var transportOpts []embedded.Option
	if svc, ok := opts.embeddedService.(embedded.RestServicer); ok {
		transportOpts = append(transportOpts, embedded.WithService(svc))
	}
	if svc, ok := opts.embeddedService.(embedded.AdminServicer); ok {
		transportOpts = append(transportOpts, embedded.WithAdminService(svc))
	}
	if len(transportOpts) == 0 {
		return nil, errors.NewInvalidInput("createEmbeddedTransport",
			fmt.Sprintf("embedded service %T implements neither embedded.RestServicer nor embedded.AdminServicer", opts.embeddedService))
	}

	cfg := &transport.Config{
		Address:     "embedded://local",
		AddressType: transport.AddressTypeEmbedded,
		Timeout:     opts.timeout,
	}
	return embedded.NewTransport(cfg, transportOpts...)
}

func createMCPTransport(address string, opts *clientOptions) (Transport, error) {
	cfg := buildTransportConfig(address, opts)
	parsed := transport.ParseAddress(address)
	cfg.AddressType = parsed.Type
	return mcp.NewTransport(cfg)
}

func buildTransportConfig(address string, opts *clientOptions) *transport.Config {
	return &transport.Config{
		Address:            address,
		Timeout:            opts.timeout,
		TLSConfig:          opts.tlsConfig,
		Insecure:           opts.insecure,
		KeepaliveTime:      opts.keepaliveTime,
		KeepaliveTimeout:   opts.keepaliveTimeout,
		MaxRetries:         opts.maxRetries,
		RetryBackoff:       opts.retryBackoff,
		MaxRetryBackoff:    opts.maxRetryBackoff,
		PoolEnabled:        opts.poolEnabled,
		PoolMinSize:        opts.poolMinSize,
		PoolMaxSize:        opts.poolMaxSize,
		PoolMaxAge:         opts.poolMaxAge,
		PoolHealthInterval: opts.poolHealthInterval,
		PoolAcquireTimeout: opts.poolAcquireTimeout,
	}
}

func (c *client) Transport() Transport { return c.transport }

func (c *client) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil
	}
	c.closed = true
	if c.transport != nil {
		return c.transport.Close()
	}
	return nil
}

func (c *client) Account() AccountClient {
	c.mu.RLock()
	if c.accountClient != nil {
		c.mu.RUnlock()
		return c.accountClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.accountClient == nil {
		c.accountClient = account.NewClient(c.transport)
	}
	return c.accountClient
}

func (c *client) Order() OrderClient {
	c.mu.RLock()
	if c.orderClient != nil {
		c.mu.RUnlock()
		return c.orderClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.orderClient == nil {
		c.orderClient = order.NewClient(c.transport)
	}
	return c.orderClient
}

func (c *client) Authorization() AuthorizationClient {
	c.mu.RLock()
	if c.authorizationClient != nil {
		c.mu.RUnlock()
		return c.authorizationClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.authorizationClient == nil {
		c.authorizationClient = authorization.NewClient(c.transport)
	}
	return c.authorizationClient
}

func (c *client) Challenge() ChallengeClient {
	c.mu.RLock()
	if c.challengeClient != nil {
		c.mu.RUnlock()
		return c.challengeClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.challengeClient == nil {
		c.challengeClient = challenge.NewClient(c.transport)
	}
	return c.challengeClient
}

func (c *client) Certificate() CertificateClient {
	c.mu.RLock()
	if c.certificateClient != nil {
		c.mu.RUnlock()
		return c.certificateClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.certificateClient == nil {
		c.certificateClient = certificate.NewClient(c.transport)
	}
	return c.certificateClient
}

func (c *client) Directory() DirectoryClient {
	c.mu.RLock()
	if c.directoryClient != nil {
		c.mu.RUnlock()
		return c.directoryClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.directoryClient == nil {
		c.directoryClient = directory.NewClient(c.transport)
	}
	return c.directoryClient
}

func (c *client) Nonce() NonceClient {
	c.mu.RLock()
	if c.nonceClient != nil {
		c.mu.RUnlock()
		return c.nonceClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.nonceClient == nil {
		c.nonceClient = nonce.NewClient(c.transport)
	}
	return c.nonceClient
}

func (c *client) Admin() AdminClient {
	c.mu.RLock()
	if c.adminClient != nil {
		c.mu.RUnlock()
		return c.adminClient
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.adminClient == nil {
		c.adminClient = admin.NewClient(c.transport)
	}
	return c.adminClient
}

func (c *client) Workflow(opts ...workflow.Option) workflow.Workflow {
	c.mu.RLock()
	if c.workflowInstance != nil {
		c.mu.RUnlock()
		return c.workflowInstance
	}
	c.mu.RUnlock()
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.workflowInstance == nil {
		c.workflowInstance = workflow.NewWorkflow(c, opts...)
	}
	return c.workflowInstance
}
