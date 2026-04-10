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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsAOADevice(t *testing.T) {
	tests := []struct {
		name      string
		vendorID  uint16
		productID uint16
		expected  bool
	}{
		{
			name:      "AOA device without ADB",
			vendorID:  AOAVendorID,
			productID: AOAProductID,
			expected:  true,
		},
		{
			name:      "AOA device with ADB",
			vendorID:  AOAVendorID,
			productID: AOAProductIDADB,
			expected:  true,
		},
		{
			name:      "non-AOA Google device",
			vendorID:  AOAVendorID,
			productID: 0x4EE1,
			expected:  false,
		},
		{
			name:      "non-Google device",
			vendorID:  0x04E8, // Samsung
			productID: 0x6860,
			expected:  false,
		},
		{
			name:      "zero values",
			vendorID:  0,
			productID: 0,
			expected:  false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := IsAOADevice(tc.vendorID, tc.productID)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestNewUSBTransport_DefaultConfig(t *testing.T) {
	transport, err := NewUSBTransport(nil)
	require.NoError(t, err)
	require.NotNil(t, transport)

	assert.Equal(t, DefaultUSBOperationTimeout, transport.cfg.OperationTimeout)
	assert.NotNil(t, transport.cfg.Logger)
	assert.False(t, transport.IsConnected())
}

func TestNewUSBTransport_CustomConfig(t *testing.T) {
	cfg := &USBTransportConfig{
		OperationTimeout: 30_000_000_000, // 30s
	}

	transport, err := NewUSBTransport(cfg)
	require.NoError(t, err)
	require.NotNil(t, transport)

	assert.Equal(t, cfg.OperationTimeout, transport.cfg.OperationTimeout)
}

func TestUSBTransport_NotConnected(t *testing.T) {
	transport, err := NewUSBTransport(nil)
	require.NoError(t, err)

	assert.False(t, transport.IsConnected())

	// Send should fail when not connected.
	err = transport.Send(t.Context(), []byte("test"))
	assert.ErrorIs(t, err, ErrNotConnected)

	// Receive should fail when not connected.
	_, err = transport.Receive(t.Context())
	assert.ErrorIs(t, err, ErrNotConnected)

	// SendAndReceive should fail when not connected.
	_, err = transport.SendAndReceive(t.Context(), []byte("test"))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestUSBTransport_Close(t *testing.T) {
	transport, err := NewUSBTransport(nil)
	require.NoError(t, err)

	// Close should succeed even when not connected.
	err = transport.Close()
	assert.NoError(t, err)

	// Double close should not error.
	err = transport.Close()
	assert.NoError(t, err)

	// Operations after close should return ErrBackendClosed.
	err = transport.Send(t.Context(), []byte("test"))
	assert.ErrorIs(t, err, ErrBackendClosed)

	_, err = transport.Receive(t.Context())
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestUSBTransport_MessageTooLarge(t *testing.T) {
	transport, err := NewUSBTransport(nil)
	require.NoError(t, err)

	// Force connected state for this test.
	transport.connected.Store(true)

	largeMessage := make([]byte, MaxUSBMessageSize+1)
	err = transport.Send(t.Context(), largeMessage)
	assert.ErrorIs(t, err, ErrProtocolError)
}

func TestAOAConstants(t *testing.T) {
	// Verify AOA constants match the Android USB Accessory Mode specification.
	assert.Equal(t, uint16(0x18D1), uint16(AOAVendorID))
	assert.Equal(t, uint16(0x2D00), uint16(AOAProductID))
	assert.Equal(t, uint16(0x2D01), uint16(AOAProductIDADB))

	// Verify xKey identification strings match usb_accessory_filter.xml.
	assert.Equal(t, "xKey", XKeyAOAManufacturer)
	assert.Equal(t, "Desktop", XKeyAOAModel)
	assert.Equal(t, "1.0", XKeyAOAVersion)
}
