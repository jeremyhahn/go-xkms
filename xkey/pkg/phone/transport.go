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

package phone

import (
	"context"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// Transport is a type alias for pairing.Transport, maintaining backward
// compatibility for consumers that reference phone.Transport.
type Transport = pairing.Transport

// BLECapableTransport extends Transport with BLE-specific operations.
// Transports that support BLE scanning, bonded address handling, and
// BlueZ D-Bus management implement this interface. The PhoneKeyBackend
// uses type assertions to detect BLE-capable transports and execute
// BLE-specific connection logic (scan, connect with bonded address,
// stale cache cleanup).
type BLECapableTransport interface {
	pairing.Transport

	// Scan searches for xKey BLE devices and returns discovered devices.
	Scan(ctx context.Context) ([]ScanResult, error)

	// ConnectWithBondedAddress connects to a device at the scanned address.
	// The bondedAddress parameter is used for BlueZ IRK resolution when
	// Android has rotated its Resolvable Private Address (RPA).
	ConnectWithBondedAddress(ctx context.Context, address, bondedAddress string) error

	// Disconnect closes the BLE connection without closing the transport.
	Disconnect() error

	// ConnectedAddress returns the BLE address of the currently connected device.
	// This may differ from the configured/bonded address if Android rotated its RPA.
	// Returns empty string if not connected.
	ConnectedAddress() string

	// CleanStaleBlueZEntry removes stale BlueZ D-Bus cache entries for the
	// given address to prevent D-Bus errors during BLE connections.
	CleanStaleBlueZEntry(address string)

	// DisconnectAndRemove disconnects and removes the device from BlueZ to
	// clear all stale D-Bus GATT state (cached characteristic handles,
	// pending operations).
	DisconnectAndRemove() error
}
