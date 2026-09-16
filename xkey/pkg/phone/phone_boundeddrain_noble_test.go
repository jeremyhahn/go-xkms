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

import "testing"

// TestConstructorFailureWithOwnedNilKeyNoBLE covers the other reachable entry
// point: NewPhoneKeyBackend fails building the BLE transport and takes the
// same cleanup path. This is only deterministic on the stub BLE transport
// (ble_transport_stub.go), which always returns ErrBLEUnavailable, so the
// file carries the same "!ble" constraint as ble_stub_test.go. With the
// "ble" build tag, NewBLETransport succeeds whenever the host has a working
// Bluetooth adapter (ble_transport.go's adapter.Enable), which makes this
// failure path a hardware-dependent condition outside a unit test's remit.
func TestConstructorFailureWithOwnedNilKeyNoBLE(t *testing.T) {
	cfg := &PhoneKeyBackendConfig{
		OwnsStaticKey:   true,
		LocalStaticKey:  nil,
		TrustNewDevices: true,
	}

	if _, err := NewPhoneKeyBackend(cfg); err == nil {
		t.Fatal("expected the stub BLE transport to fail construction")
	}
	if cfg.LocalStaticKey != nil {
		t.Fatal("cleanup left a key on the config")
	}
}
