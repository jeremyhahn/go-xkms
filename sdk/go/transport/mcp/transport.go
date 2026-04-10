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

// Package mcp provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/mcp, preserving backward compatibility
// for SDK consumers.
package mcp

import (
	pkgmcp "github.com/jeremyhahn/go-xkms/pkg/api/transport/mcp"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	ErrNotConnected     = pkgmcp.ErrNotConnected
	ErrNotSupported     = pkgmcp.ErrNotSupported
	ErrConnectionFailed = pkgmcp.ErrConnectionFailed
	ErrNotImplemented   = pkgmcp.ErrNotImplemented
)

// Typed error re-exports.
type RPCError = pkgmcp.RPCError
type MarshalError = pkgmcp.MarshalError
type UnmarshalError = pkgmcp.UnmarshalError
type SendError = pkgmcp.SendError
type ReceiveError = pkgmcp.ReceiveError
type TLSSetupError = pkgmcp.TLSSetupError

// Transport is an alias for the canonical MCP transport implementation.
type Transport = pkgmcp.Transport

// New creates a new MCP transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	return pkgmcp.New(opts...)
}

// NewWithConfig creates a new MCP transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkgmcp.NewWithConfig(cfg)
}
