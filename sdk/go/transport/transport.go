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
// xkms SDK. It re-exports types from the canonical pkg/transport package
// to maintain backward compatibility for SDK consumers.
package transport

import (
	"crypto/tls"
	"time"

	pkgtransport "github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// Transport defines the interface for all transport implementations.
type Transport = pkgtransport.Transport

// Stream represents a bidirectional communication stream.
type Stream = pkgtransport.Stream

// Config contains common transport configuration options.
type Config = pkgtransport.Config

// Option is a functional option for configuring a Transport.
type Option = pkgtransport.Option

// DefaultConfig returns a Config with sensible defaults.
func DefaultConfig() *Config {
	return pkgtransport.DefaultConfig()
}

// WithAddress sets the server address.
func WithAddress(addr string) Option {
	return pkgtransport.WithAddress(addr)
}

// WithTLS enables TLS with the specified CA certificate file.
func WithTLS(caFile string) Option {
	return pkgtransport.WithTLS(caFile)
}

// WithMTLS enables mutual TLS with client certificate authentication.
func WithMTLS(certFile, keyFile, caFile string) Option {
	return pkgtransport.WithMTLS(certFile, keyFile, caFile)
}

// WithTLSConfig sets a pre-built TLS configuration.
func WithTLSConfig(tlsConfig *tls.Config) Option {
	return pkgtransport.WithTLSConfig(tlsConfig)
}

// WithSPKIPin sets the SPKI pin for certificate pinning.
func WithSPKIPin(pin string) Option {
	return pkgtransport.WithSPKIPin(pin)
}

// WithTimeout sets the default operation timeout.
func WithTimeout(timeout time.Duration) Option {
	return pkgtransport.WithTimeout(timeout)
}

// WithRetry configures retry behavior.
func WithRetry(maxRetries int, backoff time.Duration) Option {
	return pkgtransport.WithRetry(maxRetries, backoff)
}

// WithConnectionPool configures connection pooling.
func WithConnectionPool(minConns, maxConns int) Option {
	return pkgtransport.WithConnectionPool(minConns, maxConns)
}

// WithHeaders adds custom headers to requests.
func WithHeaders(headers map[string]string) Option {
	return pkgtransport.WithHeaders(headers)
}

// WithHeader adds a single custom header to requests.
func WithHeader(key, value string) Option {
	return pkgtransport.WithHeader(key, value)
}

// WithJWTToken sets the JWT token for bearer authentication.
func WithJWTToken(token string) Option {
	return pkgtransport.WithJWTToken(token)
}

// ApplyOptions applies the given options to the config.
func ApplyOptions(cfg *Config, opts ...Option) error {
	return pkgtransport.ApplyOptions(cfg, opts...)
}
