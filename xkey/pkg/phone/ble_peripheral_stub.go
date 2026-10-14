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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// BLE Peripheral errors - defined in ble_peripheral.go for BLE builds.
// Re-declared here for stub builds.
var (
	ErrPeripheralAlreadyRunning = ErrBLEUnavailable
	ErrPeripheralNotRunning     = ErrBLEUnavailable
	ErrPeripheralStartFailed    = ErrBLEUnavailable
	ErrClientDisconnected       = ErrBLEUnavailable
)

// BLEPeripheralConfig configures the BLE peripheral (server) mode.
type BLEPeripheralConfig struct {
	// LocalStaticKey is the persistent local Noise static key, held in
	// protected memory. If nil, a new key will be generated.
	LocalStaticKey *pairing.StaticKey

	// OwnsStaticKey transfers ownership of LocalStaticKey to the peripheral.
	// Present here for API parity: a consumer writing against the documented
	// configuration must compile on a build without the ble tag, even though
	// this stub never starts a peripheral.
	OwnsStaticKey bool

	// ExpectedRemoteStatic is the expected phone's static public key.
	// If set, connection will fail if the phone's key doesn't match.
	ExpectedRemoteStatic []byte

	// DeviceName is the advertised device name.
	DeviceName string

	// MTU is the preferred Maximum Transmission Unit. Values below MinMTU
	// fall back to DefaultMTU.
	MTU int

	// AdapterID selects the local Bluetooth adapter (for example "hci1").
	// Empty uses the system default adapter.
	AdapterID string

	// Logger is the structured logger.
	Logger *slog.Logger

	// RequestHandler processes incoming requests from the phone.
	// If nil, requests are logged but not processed.
	RequestHandler PeripheralRequestHandler

	// LiveAttest is present here for API parity with the ble-tagged
	// configuration; this stub never starts a peripheral, so it is never
	// consulted. See ble_peripheral.go's BLEPeripheralConfig.LiveAttest.
	LiveAttest pairing.LiveAttestFunc

	// LiveAttestTimeout is present here for the same reason.
	LiveAttestTimeout time.Duration
}

// PeripheralRequestHandler handles incoming requests from phone.
type PeripheralRequestHandler interface {
	// HandleRequest processes a JSON-RPC request and returns a response.
	// Both may carry key material, so the peripheral wipes the request and
	// the returned response once Noise has encrypted the response: the
	// handler must return a slice it no longer needs and must not keep the
	// request.
	HandleRequest(ctx context.Context, request []byte) ([]byte, error)
}

// BLEPeripheral manages BLE peripheral (GATT server) mode.
// This is a stub implementation for platforms without BLE support; every
// method returns ErrBLEUnavailable, so it carries no state.
type BLEPeripheral struct{}

// NewBLEPeripheral creates a new BLE peripheral.
// On platforms without BLE support, this returns ErrBLEUnavailable.
func NewBLEPeripheral(cfg *BLEPeripheralConfig) (*BLEPeripheral, error) {
	return nil, ErrBLEUnavailable
}

// Start begins advertising and accepting connections.
func (p *BLEPeripheral) Start(ctx context.Context) error {
	return ErrBLEUnavailable
}

// AcceptConnection waits for and handles a client connection.
func (p *BLEPeripheral) AcceptConnection(ctx context.Context) error {
	return ErrBLEUnavailable
}

// Stop stops advertising and closes connections.
func (p *BLEPeripheral) Stop() error {
	return nil
}

// IsConnected returns true if a client is connected.
func (p *BLEPeripheral) IsConnected() bool {
	return false
}

// LocalStaticPublicKey returns the local static public key.
func (p *BLEPeripheral) LocalStaticPublicKey() []byte {
	return nil
}
