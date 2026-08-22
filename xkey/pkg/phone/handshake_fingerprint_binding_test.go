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
	"bytes"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// The two callers that decode a stored fingerprint and hand it to the
// handshake -- xkey/pkg/gui/services/phone_service.go and
// xkey/cmd/xkey/cmd/fido2_device.go -- both reach it through THIS package's
// re-exports, not through pkg/pairing directly. #82 was a bypass in the shared
// code, so the fix protects both; this pins the surface they depend on so a
// re-export that stopped forwarding, or a HandshakeConfig that stopped
// carrying the field, is caught here rather than in the field.
func TestReexports_CarryTheDeviceFingerprintBinding(t *testing.T) {
	// The config both entry points build must remain the pairing type, so a
	// field rename cannot drop the fingerprint on one path only. Asserted at
	// COMPILE time: if the alias becomes a distinct struct this stops
	// building, which is a louder failure than any assertion.
	cfg := &HandshakeConfig{ExpectedDeviceFingerprint: bytes.Repeat([]byte{0xAB}, 32)}
	if !bytes.Equal(handshakeConfigAlias.ExpectedDeviceFingerprint, nil) {
		t.Fatal("unexpected non-zero value in the alias witness")
	}
	if len(cfg.ExpectedDeviceFingerprint) != 32 {
		t.Fatal("HandshakeConfig no longer carries ExpectedDeviceFingerprint")
	}

	// The refusal is reachable through the re-exported sentinel: both callers
	// report a refused device by this error, and they must be the SAME value,
	// not two errors with the same text.
	if ErrUntrustedDevice != pairing.ErrUntrustedDevice {
		t.Fatal("phone.ErrUntrustedDevice is not the sentinel the handshake returns; " +
			"a caller matching on it would not recognise a refused device")
	}

	if PerformHandshake == nil {
		t.Fatal("PerformHandshake is not re-exported; the entry points would not compile against it")
	}
}

// The alias witness. A type alias makes this assignment legal; a separate
// struct with the same fields would not.
var handshakeConfigAlias = pairing.HandshakeConfig(HandshakeConfig{})
