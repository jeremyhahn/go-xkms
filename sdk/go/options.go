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

package xkms

import (
	"crypto/tls"
	"errors"
	"os"
	"time"
)

// Default configuration values.
const (
	DefaultTimeout      = 30 * time.Second
	DefaultMaxRetries   = 3
	DefaultRetryBackoff = 100 * time.Millisecond
	DefaultPoolMinConns = 1
	DefaultPoolMaxConns = 10
	DefaultRESTAddress  = "http://localhost:8443"
	DefaultGRPCAddress  = "localhost:9443"
	DefaultQUICAddress  = "localhost:8444"
	DefaultMCPAddress   = "localhost:9444"
)

// defaultXKeySocketEnvVar is the environment variable for the xkey IPC socket path.
const defaultXKeySocketEnvVar = "XKEY_IPC_SOCKET"

// Option errors.
var (
	// ErrInvalidTimeout is returned when a non-positive timeout is specified.
	ErrInvalidTimeout = errors.New("timeout must be positive")
	// ErrInvalidRetryConfig is returned when invalid retry configuration is specified.
	ErrInvalidRetryConfig = errors.New("max retries must be non-negative and backoff must be positive")
	// ErrInvalidPoolConfig is returned when invalid connection pool configuration is specified.
	ErrInvalidPoolConfig = errors.New("pool min must be non-negative and max must be greater than min")
	// ErrInvalidAddress is returned when an empty address is specified.
	ErrInvalidAddress = errors.New("address cannot be empty")
	// ErrMissingService is returned when embedded protocol is used without a service.
	ErrMissingService = errors.New("service is required for embedded protocol")
	// ErrServiceNotAllowed is returned when a service is specified for non-embedded protocols.
	ErrServiceNotAllowed = errors.New("service option is only valid for embedded protocol")
	// ErrXKeyAuthFailed is returned when xkey IPC authentication setup fails.
	ErrXKeyAuthFailed = errors.New("xkey IPC authentication failed")
)

// Option is a functional option for configuring the xkms client.
type Option func(*clientOptions) error

// clientOptions holds all configurable options for the client.
type clientOptions struct {
	// Protocol specifies the communication protocol.
	protocol Protocol

	// Address is the server address.
	address string

	// TLS configuration.
	tlsConfig   *tls.Config
	tlsEnabled  bool
	tlsCertFile string
	tlsKeyFile  string
	tlsCAFile   string

	// SPKI pin for certificate pinning.
	spkiPin string

	// Timeout for operations.
	timeout time.Duration

	// Retry configuration.
	maxRetries   int
	retryBackoff time.Duration

	// Connection pool configuration.
	poolMinConns int
	poolMaxConns int

	// Authentication.
	jwtToken string

	// Additional headers.
	headers map[string]string

	// Service for embedded protocol.
	service XKMSServicer
}

// newDefaultClientOptions returns clientOptions with default values.
func newDefaultClientOptions() *clientOptions {
	return &clientOptions{
		protocol:     ProtocolUnixGRPC,
		address:      DefaultUnixSocketPath,
		timeout:      DefaultTimeout,
		maxRetries:   DefaultMaxRetries,
		retryBackoff: DefaultRetryBackoff,
		poolMinConns: DefaultPoolMinConns,
		poolMaxConns: DefaultPoolMaxConns,
		headers:      make(map[string]string),
	}
}

// WithProtocol sets the communication protocol.
func WithProtocol(p Protocol) Option {
	return func(opts *clientOptions) error {
		opts.protocol = p
		return nil
	}
}

// WithAddress sets the server address.
func WithAddress(addr string) Option {
	return func(opts *clientOptions) error {
		if addr == "" {
			return ErrInvalidAddress
		}
		opts.address = addr
		return nil
	}
}

// WithTLS sets a custom tls.Config for advanced TLS configuration.
// When this option is used, other TLS options (WithTLSEnabled,
// WithTLSCertFile, WithTLSKeyFile, WithTLSCAFile) are ignored.
func WithTLS(cfg *tls.Config) Option {
	return func(opts *clientOptions) error {
		opts.tlsConfig = cfg
		if cfg != nil {
			opts.tlsEnabled = true
		}
		return nil
	}
}

// WithTLSEnabled enables or disables TLS for network protocols.
func WithTLSEnabled(enabled bool) Option {
	return func(opts *clientOptions) error {
		opts.tlsEnabled = enabled
		return nil
	}
}

// WithTLSCertFile sets the path to the client certificate file for mTLS.
func WithTLSCertFile(path string) Option {
	return func(opts *clientOptions) error {
		opts.tlsCertFile = path
		return nil
	}
}

// WithTLSKeyFile sets the path to the client key file for mTLS.
func WithTLSKeyFile(path string) Option {
	return func(opts *clientOptions) error {
		opts.tlsKeyFile = path
		return nil
	}
}

// WithTLSCAFile sets the path to the CA certificate file.
func WithTLSCAFile(path string) Option {
	return func(opts *clientOptions) error {
		opts.tlsCAFile = path
		return nil
	}
}

// WithSPKIPin sets the SPKI pin for TLS certificate pinning.
// The pin is a hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo.
// When set, the client verifies the server certificate's SPKI pin during TLS
// handshake as additive security on top of CA chain validation.
func WithSPKIPin(pin string) Option {
	return func(opts *clientOptions) error {
		opts.spkiPin = pin
		opts.tlsEnabled = true
		return nil
	}
}

// WithTimeout sets the timeout for operations.
func WithTimeout(d time.Duration) Option {
	return func(opts *clientOptions) error {
		if d <= 0 {
			return ErrInvalidTimeout
		}
		opts.timeout = d
		return nil
	}
}

// WithRetry sets the retry configuration.
func WithRetry(maxRetries int, backoff time.Duration) Option {
	return func(opts *clientOptions) error {
		if maxRetries < 0 || backoff <= 0 {
			return ErrInvalidRetryConfig
		}
		opts.maxRetries = maxRetries
		opts.retryBackoff = backoff
		return nil
	}
}

// WithConnectionPool sets the connection pool configuration.
func WithConnectionPool(min, max int) Option {
	return func(opts *clientOptions) error {
		if min < 0 || max <= 0 || max < min {
			return ErrInvalidPoolConfig
		}
		opts.poolMinConns = min
		opts.poolMaxConns = max
		return nil
	}
}

// WithJWTToken sets the JWT token for authentication.
func WithJWTToken(token string) Option {
	return func(opts *clientOptions) error {
		opts.jwtToken = token
		return nil
	}
}

// WithHeaders sets additional HTTP headers to include in requests.
// If called multiple times, the headers are merged with later calls taking precedence.
func WithHeaders(headers map[string]string) Option {
	return func(opts *clientOptions) error {
		if opts.headers == nil {
			opts.headers = make(map[string]string)
		}
		for k, v := range headers {
			opts.headers[k] = v
		}
		return nil
	}
}

// WithService sets the xkms service for the embedded protocol.
// This option is only valid when using ProtocolEmbedded.
func WithService(service XKMSServicer) Option {
	return func(opts *clientOptions) error {
		opts.service = service
		return nil
	}
}

// WithXKeyAuth configures the client to authenticate via xkey IPC. It creates
// a crypto.Signer backed by the xkey daemon's PIV 9a slot and builds a TLS
// config for mTLS client certificate authentication. If socketPath is empty,
// the XKEY_IPC_SOCKET environment variable or the platform default is used.
func WithXKeyAuth(socketPath string) Option {
	return func(opts *clientOptions) error {
		if socketPath == "" {
			socketPath = os.Getenv(defaultXKeySocketEnvVar)
		}

		resolver := &xkeyAuthResolver{socketPath: socketPath}
		tlsCfg, err := resolver.ResolveTLSConfig()
		if err != nil {
			return ErrXKeyAuthFailed
		}

		opts.tlsConfig = tlsCfg
		opts.tlsEnabled = true
		return nil
	}
}

// NewWithOptions creates a new xkms client using functional options.
// If no options are provided, it creates a client with default settings
// (Unix socket gRPC with the default socket path).
func NewWithOptions(opts ...Option) (Client, error) {
	options := newDefaultClientOptions()

	// Apply all options.
	for _, opt := range opts {
		if err := opt(options); err != nil {
			return nil, err
		}
	}

	// Validate options based on protocol.
	if err := validateOptions(options); err != nil {
		return nil, err
	}

	// Set default address based on protocol if not explicitly set.
	if options.address == "" || options.address == DefaultUnixSocketPath {
		options.address = defaultAddressForProtocol(options.protocol)
	}

	// Convert to Config and use the standard New function.
	cfg := options.toConfig()
	return New(cfg)
}

// validateOptions validates the client options.
func validateOptions(opts *clientOptions) error {
	// Embedded protocol requires a service.
	if opts.protocol == ProtocolEmbedded && opts.service == nil {
		return ErrMissingService
	}

	// Service is only valid for embedded protocol.
	if opts.service != nil && opts.protocol != ProtocolEmbedded {
		return ErrServiceNotAllowed
	}

	return nil
}

// defaultAddressForProtocol returns the default address for a given protocol.
func defaultAddressForProtocol(p Protocol) string {
	switch p {
	case ProtocolUnix, ProtocolUnixGRPC:
		return DefaultUnixSocketPath
	case ProtocolREST:
		return DefaultRESTAddress
	case ProtocolGRPC:
		return DefaultGRPCAddress
	case ProtocolQUIC:
		return DefaultQUICAddress
	case ProtocolMCP:
		return DefaultMCPAddress
	case ProtocolEmbedded:
		return ""
	default:
		return ""
	}
}

// toConfig converts clientOptions to BackendConfig.
func (o *clientOptions) toConfig() *BackendConfig {
	return &BackendConfig{
		Protocol:    o.protocol,
		Address:     o.address,
		TLSEnabled:  o.tlsEnabled,
		TLSCertFile: o.tlsCertFile,
		TLSKeyFile:  o.tlsKeyFile,
		TLSCAFile:   o.tlsCAFile,
		TLSConfig:   o.tlsConfig,
		SPKIPin:     o.spkiPin,
		JWTToken:    o.jwtToken,
		Headers:     o.headers,
		Service:     o.service,
	}
}

// ClientOptions returns a copy of the internal options for testing or debugging.
// This method is provided for transparency and should not be used in production code.
func (o *clientOptions) ClientOptions() clientOptions {
	return *o
}
