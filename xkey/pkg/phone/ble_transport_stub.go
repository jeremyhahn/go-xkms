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

//go:build !ble

package phone

import (
	"context"
	"log/slog"
	"time"
)

// Compile-time interface checks.
var (
	_ Transport           = (*BLETransport)(nil)
	_ BLECapableTransport = (*BLETransport)(nil)
)

// BLETransportConfig configures the BLE transport.
type BLETransportConfig struct {
	// DeviceAddress is the specific device address to connect to.
	// If empty, will scan for xKey service.
	DeviceAddress string

	// ScanTimeout is the duration to scan for devices.
	ScanTimeout time.Duration

	// ConnectTimeout is the timeout for establishing a connection.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for individual operations.
	OperationTimeout time.Duration

	// MTU is the preferred Maximum Transmission Unit.
	MTU int

	// Logger is the structured logger for debug output.
	Logger *slog.Logger
}

// DefaultBLETransportConfig returns default configuration values.
func DefaultBLETransportConfig() *BLETransportConfig {
	return &BLETransportConfig{
		ScanTimeout:      ScanTimeout,
		ConnectTimeout:   ConnectTimeout,
		OperationTimeout: OperationTimeout,
		MTU:              DefaultMTU,
		Logger:           slog.Default(),
	}
}

// ScanResult represents a discovered BLE device.
type ScanResult struct {
	Address   string
	LocalName string
	RSSI      int16
}

// DisplayName returns a user-friendly name for the device.
func (s ScanResult) DisplayName() string {
	if s.LocalName != "" {
		return s.LocalName
	}
	if len(s.Address) >= 5 {
		return "xKey (" + s.Address[len(s.Address)-5:] + ")"
	}
	return "xKey"
}

// ScanAll searches for all xKey devices until timeout.
func (t *BLETransport) ScanAll(ctx context.Context) ([]ScanResult, error) {
	return nil, ErrBLEUnavailable
}

// BLETransport manages BLE communication with the xKey phone app.
// This is a stub implementation for platforms without BLE support.
type BLETransport struct {
	cfg         *BLETransportConfig
	fragmenter  *Fragmenter
	reassembler *Reassembler
}

// NewBLETransport creates a new BLE transport.
// On platforms without BLE support, this returns ErrBLEUnavailable.
func NewBLETransport(cfg *BLETransportConfig) (*BLETransport, error) {
	return nil, ErrBLEUnavailable
}

// Scan searches for xKey devices.
func (t *BLETransport) Scan(ctx context.Context) ([]ScanResult, error) {
	return nil, ErrBLEUnavailable
}

// Connect establishes a connection to a xKey device.
func (t *BLETransport) Connect(ctx context.Context, address string) error {
	return ErrBLEUnavailable
}

// Send transmits a message to the connected phone.
func (t *BLETransport) Send(ctx context.Context, message []byte) error {
	return ErrBLEUnavailable
}

// Receive waits for a complete response message.
func (t *BLETransport) Receive(ctx context.Context) ([]byte, error) {
	return nil, ErrBLEUnavailable
}

// SendAndReceive sends a message and waits for a response.
func (t *BLETransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	return nil, ErrBLEUnavailable
}

// Disconnect closes the BLE connection.
func (t *BLETransport) Disconnect() error {
	return nil
}

// IsConnected returns true if currently connected.
func (t *BLETransport) IsConnected() bool {
	return false
}

// Close closes the transport and releases resources.
func (t *BLETransport) Close() error {
	return nil
}

// StatusChannel returns the channel for status updates.
func (t *BLETransport) StatusChannel() <-chan []byte {
	return nil
}

// SetMTU updates the MTU for fragmentation.
func (t *BLETransport) SetMTU(mtu int) {}

// MTU returns the current MTU.
func (t *BLETransport) MTU() int {
	return DefaultMTU
}

// ConnectWithBondedAddress connects to a device at the scanned address.
// This is a stub - returns ErrBLEUnavailable on platforms without BLE support.
func (t *BLETransport) ConnectWithBondedAddress(ctx context.Context, address, bondedAddress string) error {
	return ErrBLEUnavailable
}

// ConnectedAddress returns the address of the currently connected device.
// This is a stub - always returns empty string on platforms without BLE support.
func (t *BLETransport) ConnectedAddress() string {
	return ""
}

// CleanStaleBlueZEntry removes stale BlueZ D-Bus cache entries for the given address.
// This is a stub - no-op on platforms without BLE support.
func (t *BLETransport) CleanStaleBlueZEntry(address string) {}

// DisconnectAndRemove disconnects and removes the device from BlueZ to clear stale D-Bus state.
// This is a stub - returns nil on platforms without BLE support.
func (t *BLETransport) DisconnectAndRemove() error {
	return nil
}
