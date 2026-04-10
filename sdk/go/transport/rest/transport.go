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

// Package rest provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/rest, preserving backward compatibility
// for SDK consumers.
package rest

import (
	pkgrest "github.com/jeremyhahn/go-xkms/pkg/api/transport/rest"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	// ErrNotConnected is returned when the client is not connected.
	ErrNotConnected = pkgrest.ErrNotConnected
	// ErrNotSupported is returned when an operation is not supported.
	ErrNotSupported = pkgrest.ErrNotSupported
	// ErrConnectionFailed is returned when a connection fails.
	ErrConnectionFailed = pkgrest.ErrConnectionFailed
	// ErrNotImplemented is returned when an operation has not been implemented yet.
	ErrNotImplemented = pkgrest.ErrNotImplemented
)

// Transport is an alias for the canonical REST transport implementation.
type Transport = pkgrest.Transport

// New creates a new REST transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	return pkgrest.New(opts...)
}

// NewWithConfig creates a new REST transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkgrest.NewWithConfig(cfg)
}
