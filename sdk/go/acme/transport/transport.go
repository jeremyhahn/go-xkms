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

// Package transport provides the transport abstraction layer for the Trusted CA SDK.
package transport

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net/http"
	"time"
)

// CloseResponseBody closes resp.Body and logs a failure at debug level.
// Shared by every HTTP-based transport (rest, quic, mcp, unix): each calls
// this from a defer after it has already read (or decided not to read) the
// body and computed its result, so a close failure changes nothing about
// the caller's outcome.
func CloseResponseBody(resp *http.Response) {
	if err := resp.Body.Close(); err != nil {
		slog.Debug("acme/transport: failed to close HTTP response body", "error", err)
	}
}

// Transport is the interface for protocol-specific communication with the ACME CA.
type Transport interface {
	// Request sends a unary request and returns the response.
	Request(ctx context.Context, service, method string, req interface{}) (interface{}, error)

	// Conn returns the underlying connection for advanced usage.
	Conn() interface{}

	// Close closes the transport connection.
	Close() error

	// Healthy returns true if the transport is healthy.
	Healthy() bool
}

// Config holds common transport configuration.
type Config struct {
	// Address is the server address.
	Address string

	// AddressType is the parsed address type.
	AddressType AddressType

	// Timeout is the request timeout.
	Timeout time.Duration

	// TLSConfig is the TLS configuration for secure connections.
	TLSConfig *tls.Config

	// Insecure disables TLS (development only).
	Insecure bool

	// KeepaliveTime is the keepalive ping interval.
	KeepaliveTime time.Duration

	// KeepaliveTimeout is the keepalive ping timeout.
	KeepaliveTimeout time.Duration

	// MaxRetries is the maximum number of retry attempts.
	MaxRetries int

	// RetryBackoff is the initial retry backoff duration.
	RetryBackoff time.Duration

	// MaxRetryBackoff is the maximum retry backoff duration.
	MaxRetryBackoff time.Duration

	// Pool configuration (gRPC only)
	PoolEnabled        bool
	PoolMinSize        int
	PoolMaxSize        int
	PoolMaxAge         time.Duration
	PoolHealthInterval time.Duration

	// PoolAcquireTimeout is how long Get waits for a leased connection to be
	// returned before reporting the pool exhausted. Zero selects the
	// transport's default.
	//
	// It exists because a saturated pool now WAITS rather than lending one
	// connection to two callers (owner ruling 2026-08-23, go-xkms#104).
	PoolAcquireTimeout time.Duration
}

// Factory creates transports of a specific type.
type Factory interface {
	// Create creates a new transport with the given configuration.
	Create(cfg *Config) (Transport, error)
}
