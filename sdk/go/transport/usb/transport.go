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

// Package usb provides a thin re-export wrapper around the canonical
// implementation in pkg/api/transport/usb, preserving backward compatibility
// for SDK consumers.
package usb

import (
	pkgusb "github.com/jeremyhahn/go-xkms/pkg/api/transport/usb"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// Error sentinel re-exports.
var (
	ErrNotConnected       = pkgusb.ErrNotConnected
	ErrNotSupported       = pkgusb.ErrNotSupported
	ErrStreamNotSupported = pkgusb.ErrStreamNotSupported
	ErrNoiseNotConfigured = pkgusb.ErrNoiseNotConfigured
	ErrRequestFailed      = pkgusb.ErrRequestFailed
)

// Transport is an alias for the canonical USB transport implementation.
type Transport = pkgusb.Transport

// NoiseConfig is an alias for the canonical pairing key material type. It must
// be attached with Transport.WithNoiseConfig before connecting; the phone's USB
// responder speaks Noise XX and rejects a plaintext channel.
type NoiseConfig = pkgusb.NoiseConfig

// New creates a new USB transport with the given options.
func New(opts ...transport.Option) (*Transport, error) {
	return pkgusb.New(opts...)
}

// NewWithConfig creates a new USB transport with the given configuration.
func NewWithConfig(cfg *transport.Config) (*Transport, error) {
	return pkgusb.NewWithConfig(cfg)
}
