// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build !usb

package phone

import (
	"context"
	"log/slog"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// USB stub, mirroring the BLE transport's ble_transport_stub.go pattern:
// the real transport (usb_transport.go, build tag "usb") links google/gousb,
// whose libusb cgo dependency cannot be linked statically (libudev ships no
// .a) and has no CGO_ENABLED=0 fallback — so static release binaries and the
// FIPS lane build without it. Callers keep compiling against the identical
// exported surface; every operation fails with ErrUSBUnavailable.

// USB transport constants.
const (
	// DefaultUSBOperationTimeout mirrors the real transport's default
	// send/receive timeout.
	DefaultUSBOperationTimeout = 60 * time.Second

	// MaxUSBMessageSize mirrors the real transport's maximum message
	// payload size.
	MaxUSBMessageSize = 65535
)

// Compile-time interface check.
var _ pairing.Transport = (*USBTransport)(nil)

// USBTransportConfig configures the USB transport for phone communication.
type USBTransportConfig struct {
	// OperationTimeout is the timeout for individual send/receive operations.
	OperationTimeout time.Duration

	// Logger is the structured logger.
	Logger *slog.Logger
}

// DefaultUSBTransportConfig returns default configuration values.
func DefaultUSBTransportConfig() *USBTransportConfig {
	return &USBTransportConfig{
		OperationTimeout: DefaultUSBOperationTimeout,
		Logger:           slog.Default(),
	}
}

// USBTransport is the no-USB-support stand-in for the real AOA transport.
type USBTransport struct{}

// NewUSBTransport reports that USB phone transport support is not built in.
func NewUSBTransport(cfg *USBTransportConfig) (*USBTransport, error) {
	return nil, ErrUSBUnavailable
}

// Connect reports that USB phone transport support is not built in.
func (t *USBTransport) Connect(ctx context.Context) error { return ErrUSBUnavailable }

// Send reports that USB phone transport support is not built in.
func (t *USBTransport) Send(ctx context.Context, message []byte) error {
	return ErrUSBUnavailable
}

// Receive reports that USB phone transport support is not built in.
func (t *USBTransport) Receive(ctx context.Context) ([]byte, error) {
	return nil, ErrUSBUnavailable
}

// SendAndReceive reports that USB phone transport support is not built in.
func (t *USBTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	return nil, ErrUSBUnavailable
}

// IsConnected always reports false: there is no USB transport in this build.
func (t *USBTransport) IsConnected() bool { return false }

// Close is a no-op for the stub transport.
func (t *USBTransport) Close() error { return nil }
