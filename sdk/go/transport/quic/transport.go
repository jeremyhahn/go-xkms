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

// Package quic provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/quic, preserving backward compatibility
// for SDK consumers.
package quic

import (
	pkgquic "github.com/jeremyhahn/go-xkms/pkg/api/transport/quic"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = pkgquic.ErrNotConnected
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = pkgquic.ErrNotSupported
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = pkgquic.ErrConnectionFailed
	// ErrNotImplemented is returned when a method is not yet implemented.
	ErrNotImplemented = pkgquic.ErrNotImplemented
)

// Transport is an alias for the canonical QUIC transport implementation.
type Transport = pkgquic.Transport

// New creates a new QUIC transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	return pkgquic.New(opts...)
}

// NewWithConfig creates a new QUIC transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkgquic.NewWithConfig(cfg)
}
