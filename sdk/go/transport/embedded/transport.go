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

// Package embedded provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/embedded, preserving backward
// compatibility for SDK consumers.
package embedded

import (
	pkgembed "github.com/jeremyhahn/go-xkms/pkg/api/transport/embedded"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	ErrNilService   = pkgembed.ErrNilService
	ErrNotConnected = pkgembed.ErrNotConnected
)

// Transport is an alias for the canonical embedded transport implementation.
type Transport = pkgembed.Transport

// New creates a new embedded transport with the given service.
func New(service XKMSServicer, opts ...transport.Option) (*Transport, error) {
	return pkgembed.New(service, opts...)
}

// NewWithConfig creates a new embedded transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkgembed.NewWithConfig(cfg)
}

// NewWithService creates a new embedded transport with the given service
// using default configuration.
func NewWithService(service XKMSServicer) (*Transport, error) {
	return pkgembed.NewWithService(service)
}
