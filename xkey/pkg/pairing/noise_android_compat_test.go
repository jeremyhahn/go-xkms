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

package pairing

import (
	"encoding/hex"
	"testing"

	"github.com/flynn/noise"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

// TestAndroidCompatibility tests what happens when Go receives a msg2
// from Android that is 80 bytes (without the empty payload tag)
// vs the 96 bytes that flynn/noise would send.
func TestAndroidCompatibility(t *testing.T) {
	// Generate Go's static key
	goStaticPriv, _ := hex.DecodeString("1000000000000000000000000000000000000000000000000000000000000001")
	goStaticPub, _ := curve25519.X25519(goStaticPriv, curve25519.Basepoint)
	t.Logf("Go static: pub=%x", goStaticPub)

	// Generate Android's static key (simulated)
	androidStaticPriv, _ := hex.DecodeString("2000000000000000000000000000000000000000000000000000000000000002")
	androidStaticPub, _ := curve25519.X25519(androidStaticPriv, curve25519.Basepoint)
	t.Logf("Android static: pub=%x", androidStaticPub)

	// Create Go's handshake state (initiator)
	goCipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	goConfig := noise.Config{
		CipherSuite: goCipherSuite,
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
		Prologue:    nil,
		StaticKeypair: noise.DHKey{
			Private: goStaticPriv,
			Public:  goStaticPub,
		},
	}
	goHS, err := noise.NewHandshakeState(goConfig)
	require.NoError(t, err)

	// Create Android's handshake state (responder) - using flynn/noise to generate valid encryption
	androidCipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	androidConfig := noise.Config{
		CipherSuite: androidCipherSuite,
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
		Prologue:    nil,
		StaticKeypair: noise.DHKey{
			Private: androidStaticPriv,
			Public:  androidStaticPub,
		},
	}
	androidHS, err := noise.NewHandshakeState(androidConfig)
	require.NoError(t, err)

	// Step 1: Go sends msg1
	msg1, _, _, err := goHS.WriteMessage(nil, nil)
	require.NoError(t, err)
	t.Logf("Go sends msg1 (%d bytes): %x", len(msg1), msg1)

	// Step 2: Android receives msg1
	_, _, _, err = androidHS.ReadMessage(nil, msg1)
	require.NoError(t, err)

	// Step 3: Android generates msg2 (full 96 bytes)
	msg2Full, _, _, err := androidHS.WriteMessage(nil, nil)
	require.NoError(t, err)
	require.Len(t, msg2Full, 96, "flynn/noise msg2 should be 96 bytes")
	t.Logf("Full msg2 (%d bytes): %x", len(msg2Full), msg2Full)

	// Simulate what Android actually sends: 80 bytes (without empty payload tag)
	msg2Android := msg2Full[:80]
	t.Logf("Android-style msg2 (%d bytes): %x", len(msg2Android), msg2Android)
	t.Logf("  - Truncated bytes (empty payload tag): %x", msg2Full[80:])

	// Step 4: Go tries to read the 80-byte msg2 from "Android"
	t.Log("Go attempting to read Android's 80-byte msg2...")
	_, _, _, err = goHS.ReadMessage(nil, msg2Android)
	if err != nil {
		t.Logf("Expected error: %v", err)
		t.Log("This confirms Go's flynn/noise cannot handle Android's 80-byte msg2")
		t.Log("")
		t.Log("=== ROOT CAUSE IDENTIFIED ===")
		t.Log("Android's Noise library sends 80-byte msg2 (e + encrypted_s)")
		t.Log("Go's flynn/noise expects 96-byte msg2 (e + encrypted_s + empty_payload_tag)")
		t.Log("")
		t.Log("FIX OPTIONS:")
		t.Log("1. Android side: Add empty payload encryption (16-byte tag)")
		t.Log("2. Go side: Modify NoiseSession to append 16 zero bytes if msg2 is 80 bytes")
	} else {
		t.Log("Unexpectedly succeeded! This means flynn/noise handles 80-byte msg2")
	}
}

// TestNoiseEmptyPayloadBehavior demonstrates the empty payload encryption behavior
func TestNoiseEmptyPayloadBehavior(t *testing.T) {
	// Create a simple XX handshake between two Go sides
	// and inspect the message structure

	cipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)

	// Initiator
	initKey, _ := noise.DH25519.GenerateKeypair(nil)
	initConfig := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     true,
		StaticKeypair: initKey,
	}
	initHS, err := noise.NewHandshakeState(initConfig)
	require.NoError(t, err)

	// Responder
	respKey, _ := noise.DH25519.GenerateKeypair(nil)
	respConfig := noise.Config{
		CipherSuite:   cipherSuite,
		Pattern:       noise.HandshakeXX,
		Initiator:     false,
		StaticKeypair: respKey,
	}
	respHS, err := noise.NewHandshakeState(respConfig)
	require.NoError(t, err)

	// msg1: initiator sends e
	msg1, _, _, err := initHS.WriteMessage(nil, nil)
	require.NoError(t, err)
	t.Logf("msg1 size: %d bytes (expected 32 for ephemeral)", len(msg1))

	// Responder reads msg1
	_, _, _, err = respHS.ReadMessage(nil, msg1)
	require.NoError(t, err)

	// msg2: responder sends e, ee, s, es, [payload]
	msg2, _, _, err := respHS.WriteMessage(nil, nil)
	require.NoError(t, err)
	t.Logf("msg2 size: %d bytes", len(msg2))
	t.Logf("  - e: 32 bytes")
	t.Logf("  - encrypted s: 48 bytes (32 + 16 tag)")
	t.Logf("  - encrypted empty payload: %d bytes", len(msg2)-80)

	// Try with explicit empty payload
	respHS2, _ := noise.NewHandshakeState(respConfig)
	respHS2.ReadMessage(nil, msg1)
	msg2WithEmptyPayload, _, _, err := respHS2.WriteMessage(nil, []byte{}) // Explicit empty slice
	require.NoError(t, err)
	t.Logf("msg2 with explicit empty payload: %d bytes", len(msg2WithEmptyPayload))

	// Both should be 96 bytes
	require.Equal(t, len(msg2), len(msg2WithEmptyPayload), "nil and empty payload should produce same size")

	t.Log("")
	t.Log("=== OBSERVATION ===")
	t.Log("flynn/noise ALWAYS encrypts the payload (even if empty/nil)")
	t.Log("This adds 16 bytes for the AEAD authentication tag")
	t.Log("Android's Noise library appears to NOT do this")
}
