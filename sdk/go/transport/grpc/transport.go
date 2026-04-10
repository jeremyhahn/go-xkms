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

// Package grpc provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/grpc, preserving backward compatibility
// for SDK consumers.
package grpc

import (
	pkggrpc "github.com/jeremyhahn/go-xkms/pkg/api/transport/grpc"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = pkggrpc.ErrNotConnected
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = pkggrpc.ErrNotSupported
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = pkggrpc.ErrConnectionFailed
	// ErrNotImplemented is returned when a method is not yet implemented.
	ErrNotImplemented = pkggrpc.ErrNotImplemented
)

// Transport is an alias for the canonical gRPC transport implementation.
type Transport = pkggrpc.Transport

// New creates a new gRPC transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	return pkggrpc.New(opts...)
}

// NewWithConfig creates a new gRPC transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkggrpc.NewWithConfig(cfg)
}
