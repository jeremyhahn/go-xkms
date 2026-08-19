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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBLETransportStub_FailsClosed asserts that a build without the "ble" tag
// reports Bluetooth as unavailable on every I/O entry point instead of
// silently succeeding or panicking on a nil receiver. A stub that returned a
// nil error here would make callers believe a phone was reachable.
func TestBLETransportStub_FailsClosed(t *testing.T) {
	t.Parallel()

	transport, err := NewBLETransport(DefaultBLETransportConfig())
	require.ErrorIs(t, err, ErrBLEUnavailable)
	require.Nil(t, transport)

	// The stub type carries no state, so the zero value is the object the
	// interface assertions in transport.go bind to.
	stub := &BLETransport{}
	ctx := context.Background()

	tests := []struct {
		name string
		call func() error
	}{
		{"Scan", func() error { _, err := stub.Scan(ctx); return err }},
		{"ScanAll", func() error { _, err := stub.ScanAll(ctx); return err }},
		{"Connect", func() error { return stub.Connect(ctx, "AA:BB:CC:DD:EE:FF") }},
		{"ConnectWithBondedAddress", func() error {
			return stub.ConnectWithBondedAddress(ctx, "AA:BB:CC:DD:EE:FF", "11:22:33:44:55:66")
		}},
		{"Send", func() error { return stub.Send(ctx, []byte("payload")) }},
		{"Receive", func() error { _, err := stub.Receive(ctx); return err }},
		{"SendAndReceive", func() error { _, err := stub.SendAndReceive(ctx, []byte("payload")); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), ErrBLEUnavailable)
		})
	}

	// Teardown and status calls must be safe no-ops so callers can always
	// unwind without special-casing the no-BLE build.
	assert.NoError(t, stub.Disconnect())
	assert.NoError(t, stub.DisconnectAndRemove())
	assert.NoError(t, stub.Close())
	assert.False(t, stub.IsConnected())
	assert.Empty(t, stub.ConnectedAddress())
	assert.Nil(t, stub.StatusChannel())
	assert.Equal(t, DefaultMTU, stub.MTU())
	stub.SetMTU(23)
	assert.Equal(t, DefaultMTU, stub.MTU(), "the stub has no MTU state to change")
	stub.CleanStaleBlueZEntry("AA:BB:CC:DD:EE:FF")
}

// TestBLEPeripheralStub_FailsClosed asserts the peripheral (GATT server) stub
// refuses to advertise on a build without BLE support.
func TestBLEPeripheralStub_FailsClosed(t *testing.T) {
	t.Parallel()

	peripheral, err := NewBLEPeripheral(&BLEPeripheralConfig{DeviceName: "xkey"})
	assert.ErrorIs(t, err, ErrBLEUnavailable)
	assert.Nil(t, peripheral)

	stub := &BLEPeripheral{}
	ctx := context.Background()

	assert.ErrorIs(t, stub.Start(ctx), ErrBLEUnavailable)
	assert.ErrorIs(t, stub.AcceptConnection(ctx), ErrBLEUnavailable)
	assert.NoError(t, stub.Stop())
	assert.False(t, stub.IsConnected())
	assert.Nil(t, stub.LocalStaticPublicKey())
}

func TestScanResult_DisplayName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   ScanResult
		want string
	}{
		{"advertised local name wins", ScanResult{Address: "AA:BB:CC:DD:EE:FF", LocalName: "Pixel"}, "Pixel"},
		{"falls back to address suffix", ScanResult{Address: "AA:BB:CC:DD:EE:FF"}, "xKey (EE:FF)"},
		{"short address", ScanResult{Address: "AB"}, "xKey"},
		{"no address", ScanResult{}, "xKey"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.in.DisplayName())
		})
	}
}

// TestNewPhoneKeyBackend_FailsClosedWithoutBLE asserts that the backend
// constructor refuses to hand back a usable backend on a build without the
// "ble" tag, for both the default configuration and the nil-config path.
func TestNewPhoneKeyBackend_FailsClosedWithoutBLE(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *PhoneKeyBackendConfig
	}{
		{"default config", DefaultPhoneKeyBackendConfig()},
		{"nil config", nil},
		{"trust new devices", &PhoneKeyBackendConfig{TrustNewDevices: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend, err := NewPhoneKeyBackend(tt.cfg)
			assert.ErrorIs(t, err, ErrBLEUnavailable)
			assert.Nil(t, backend)
		})
	}
}
