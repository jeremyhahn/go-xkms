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

// Package transport provides a unified transport abstraction layer for the
// xkms SDK. The Client interface in client.go composes the service-specific
// contracts that every protocol implementation (gRPC, REST, QUIC, MCP, Unix,
// Embedded) must implement to enable consistent communication patterns
// across different transport mechanisms.
package transport

import (
	"crypto/tls"
	"time"
)

// Config contains common transport configuration options.
// Individual transport implementations may support additional
// protocol-specific options through functional options.
type Config struct {
	// Address is the server address.
	// Format depends on the transport:
	// - gRPC: "host:port"
	// - REST: "http://host:port" or "https://host:port"
	// - QUIC: "host:port"
	// - MCP: "host:port"
	// - Unix: "/path/to/socket.sock"
	// - Embedded: not used
	Address string

	// TLSEnabled enables TLS/SSL encryption.
	// Some transports (QUIC) always use TLS.
	TLSEnabled bool

	// TLSCertFile is the path to the client certificate file for mTLS.
	TLSCertFile string

	// TLSKeyFile is the path to the client private key file for mTLS.
	TLSKeyFile string

	// TLSCAFile is the path to the CA certificate file for server verification.
	TLSCAFile string

	// TLSConfig is an optional pre-built TLS configuration.
	// When set, this takes precedence over TLSCertFile, TLSKeyFile, and TLSCAFile.
	// This enables PKCS#11-backed mTLS where the crypto.Signer lives in hardware.
	TLSConfig *tls.Config

	// SPKIPin is the hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo.
	// When set, the client verifies the server certificate's SPKI pin as additive
	// security on top of CA chain validation. The CA chain is still verified first,
	// then the pin is checked as an additional layer of assurance.
	SPKIPin string

	// DANEHostname is the hostname for DANE/TLSA DNS-based verification.
	// When set, the client performs DANE verification using DNS TLSA records.
	DANEHostname string

	// DANEResolver is the DNS resolver address for DANE lookups (e.g., "8.8.8.8:53").
	DANEResolver string

	// Timeout is the default timeout for operations.
	// Zero means no timeout.
	Timeout time.Duration

	// MaxRetries is the maximum number of retry attempts for failed requests.
	// Zero means no retries.
	MaxRetries int

	// RetryBackoff is the initial backoff duration between retries.
	// Subsequent retries use exponential backoff.
	RetryBackoff time.Duration

	// PoolMinConns is the minimum number of connections in the pool.
	// Only applicable to transports that support connection pooling.
	PoolMinConns int

	// PoolMaxConns is the maximum number of connections in the pool.
	// Only applicable to transports that support connection pooling.
	PoolMaxConns int

	// Headers are additional headers to include in requests.
	// Primarily used by HTTP-based transports (REST, QUIC).
	Headers map[string]string

	// JWTToken is the JWT token for bearer authentication.
	JWTToken string
}

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return &Config{
		Timeout:      30 * time.Second,
		MaxRetries:   3,
		RetryBackoff: 100 * time.Millisecond,
		PoolMinConns: 1,
		PoolMaxConns: 10,
		Headers:      make(map[string]string),
	}
}

// Clone creates a deep copy of the Config.
func (c *Config) Clone() *Config {
	if c == nil {
		return nil
	}

	clone := *c
	if c.Headers != nil {
		clone.Headers = make(map[string]string, len(c.Headers))
		for k, v := range c.Headers {
			clone.Headers[k] = v
		}
	}

	// TLSConfig is a pointer - shallow copy is intentional.
	// Callers share the same *tls.Config (e.g., PKCS#11 hardware-backed).
	clone.TLSConfig = c.TLSConfig

	return &clone
}

// Validate checks if the Config has valid values.
// Returns an error if any configuration is invalid.
func (c *Config) Validate() error {
	if c == nil {
		return ErrInvalidConfig
	}

	if c.Timeout < 0 {
		return &ConfigError{
			Field:   "Timeout",
			Message: "timeout cannot be negative",
		}
	}

	if c.MaxRetries < 0 {
		return &ConfigError{
			Field:   "MaxRetries",
			Message: "max retries cannot be negative",
		}
	}

	if c.RetryBackoff < 0 {
		return &ConfigError{
			Field:   "RetryBackoff",
			Message: "retry backoff cannot be negative",
		}
	}

	if c.PoolMinConns < 0 {
		return &ConfigError{
			Field:   "PoolMinConns",
			Message: "pool min connections cannot be negative",
		}
	}

	if c.PoolMaxConns < 0 {
		return &ConfigError{
			Field:   "PoolMaxConns",
			Message: "pool max connections cannot be negative",
		}
	}

	if c.PoolMaxConns > 0 && c.PoolMinConns > c.PoolMaxConns {
		return &ConfigError{
			Field:   "PoolMinConns",
			Message: "pool min connections cannot exceed max connections",
		}
	}

	return nil
}

// Option is a functional option for configuring a Transport.
type Option func(*Config) error

// WithAddress sets the server address.
func WithAddress(addr string) Option {
	return func(c *Config) error {
		if addr == "" {
			return &ConfigError{
				Field:   "Address",
				Message: "address cannot be empty",
			}
		}
		c.Address = addr
		return nil
	}
}

// WithTLS enables TLS with the specified CA certificate file.
func WithTLS(caFile string) Option {
	return func(c *Config) error {
		c.TLSEnabled = true
		c.TLSCAFile = caFile
		return nil
	}
}

// WithMTLS enables mutual TLS with client certificate authentication.
func WithMTLS(certFile, keyFile, caFile string) Option {
	return func(c *Config) error {
		if certFile == "" {
			return &ConfigError{
				Field:   "TLSCertFile",
				Message: "certificate file cannot be empty for mTLS",
			}
		}
		if keyFile == "" {
			return &ConfigError{
				Field:   "TLSKeyFile",
				Message: "key file cannot be empty for mTLS",
			}
		}
		c.TLSEnabled = true
		c.TLSCertFile = certFile
		c.TLSKeyFile = keyFile
		c.TLSCAFile = caFile
		return nil
	}
}

// WithTLSConfig sets a pre-built TLS configuration.
// When set, this takes precedence over file-based TLS options.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return func(c *Config) error {
		if tlsConfig == nil {
			return &ConfigError{
				Field:   "TLSConfig",
				Message: "TLS config cannot be nil",
			}
		}
		c.TLSEnabled = true
		c.TLSConfig = tlsConfig
		return nil
	}
}

// WithSPKIPin sets the SPKI pin for certificate pinning.
// The pin is a hex-encoded SHA-256 hash of the server's SubjectPublicKeyInfo.
// SPKI pinning is additive security on top of CA chain validation. The standard
// CA verification still runs; the pin check is an additional layer of assurance.
func WithSPKIPin(pin string) Option {
	return func(c *Config) error {
		if pin == "" {
			return &ConfigError{
				Field:   "SPKIPin",
				Message: "SPKI pin cannot be empty",
			}
		}
		c.SPKIPin = pin
		c.TLSEnabled = true
		return nil
	}
}

// WithTimeout sets the default operation timeout.
func WithTimeout(timeout time.Duration) Option {
	return func(c *Config) error {
		if timeout < 0 {
			return &ConfigError{
				Field:   "Timeout",
				Message: "timeout cannot be negative",
			}
		}
		c.Timeout = timeout
		return nil
	}
}

// WithRetry configures retry behavior.
func WithRetry(maxRetries int, backoff time.Duration) Option {
	return func(c *Config) error {
		if maxRetries < 0 {
			return &ConfigError{
				Field:   "MaxRetries",
				Message: "max retries cannot be negative",
			}
		}
		if backoff < 0 {
			return &ConfigError{
				Field:   "RetryBackoff",
				Message: "retry backoff cannot be negative",
			}
		}
		c.MaxRetries = maxRetries
		c.RetryBackoff = backoff
		return nil
	}
}

// WithConnectionPool configures connection pooling.
func WithConnectionPool(minConns, maxConns int) Option {
	return func(c *Config) error {
		if minConns < 0 {
			return &ConfigError{
				Field:   "PoolMinConns",
				Message: "min connections cannot be negative",
			}
		}
		if maxConns < 0 {
			return &ConfigError{
				Field:   "PoolMaxConns",
				Message: "max connections cannot be negative",
			}
		}
		if maxConns > 0 && minConns > maxConns {
			return &ConfigError{
				Field:   "PoolMinConns",
				Message: "min connections cannot exceed max connections",
			}
		}
		c.PoolMinConns = minConns
		c.PoolMaxConns = maxConns
		return nil
	}
}

// WithHeaders adds custom headers to requests.
func WithHeaders(headers map[string]string) Option {
	return func(c *Config) error {
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}
		for k, v := range headers {
			c.Headers[k] = v
		}
		return nil
	}
}

// WithHeader adds a single custom header to requests.
func WithHeader(key, value string) Option {
	return func(c *Config) error {
		if key == "" {
			return &ConfigError{
				Field:   "Header",
				Message: "header key cannot be empty",
			}
		}
		if c.Headers == nil {
			c.Headers = make(map[string]string)
		}
		c.Headers[key] = value
		return nil
	}
}

// WithJWTToken sets the JWT token for bearer authentication.
func WithJWTToken(token string) Option {
	return func(c *Config) error {
		c.JWTToken = token
		return nil
	}
}

// ApplyOptions applies the given options to the config.
// Returns the first error encountered, if any.
func ApplyOptions(cfg *Config, opts ...Option) error {
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return err
		}
	}
	return nil
}
