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

// TestSimulatedLiveHandshake simulates what happens in a real BLE handshake
// where both Go (initiator) and Android (responder) generate fresh keys
func TestSimulatedLiveHandshake(t *testing.T) {
	// Generate Go's static key (like phone_pair.go does)
	goStaticKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Logf("Go static pub: %x", goStaticKey.Public)

	// Generate Android's static key (simulated)
	androidStaticKey, err := GenerateStaticKey()
	require.NoError(t, err)
	t.Logf("Android static pub: %x", androidStaticKey.Public)

	// Create Go's handshake state (initiator)
	goCipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	goConfig := noise.Config{
		CipherSuite: goCipherSuite,
		Pattern:     noise.HandshakeXX,
		Initiator:   true,
		Prologue:    nil, // Empty prologue
		StaticKeypair: noise.DHKey{
			Private: goStaticKey.Private,
			Public:  goStaticKey.Public,
		},
	}
	goHS, err := noise.NewHandshakeState(goConfig)
	require.NoError(t, err)

	// Create Android's handshake state (responder)
	androidCipherSuite := noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashSHA256)
	androidConfig := noise.Config{
		CipherSuite: androidCipherSuite,
		Pattern:     noise.HandshakeXX,
		Initiator:   false,
		Prologue:    nil, // Empty prologue - MUST match Go!
		StaticKeypair: noise.DHKey{
			Private: androidStaticKey.Private,
			Public:  androidStaticKey.Public,
		},
	}
	androidHS, err := noise.NewHandshakeState(androidConfig)
	require.NoError(t, err)

	// Step 1: Go sends msg1 (ephemeral public key)
	msg1, _, _, err := goHS.WriteMessage(nil, nil)
	require.NoError(t, err)
	require.Len(t, msg1, 32, "msg1 should be 32 bytes (ephemeral pub)")
	t.Logf("Go sends msg1: %x", msg1)
	t.Logf("Go ephemeral pub: %x", goHS.LocalEphemeral().Public)

	// Step 2: Android receives msg1 and sends msg2
	_, _, _, err = androidHS.ReadMessage(nil, msg1)
	require.NoError(t, err, "Android failed to read msg1")

	msg2, _, _, err := androidHS.WriteMessage(nil, nil)
	require.NoError(t, err, "Android failed to write msg2")
	// NOTE: flynn/noise adds 16-byte AEAD tag for empty payload
	// Real msg2 is: e (32) + encrypted_s (48) + encrypted_empty_payload (16) = 96 bytes
	require.Len(t, msg2, 96, "msg2 should be 96 bytes (32 + 48 + 16 empty payload tag)")
	t.Logf("Android sends msg2: %x", msg2)
	t.Logf("  - Android ephemeral: %x", msg2[:32])
	t.Logf("  - Encrypted static: %x", msg2[32:])
	t.Logf("Android ephemeral pub: %x", androidHS.LocalEphemeral().Public)

	// Verify ee computation matches
	goE := goHS.LocalEphemeral()
	androidE := msg2[:32]
	ee1, _ := curve25519.X25519(goE.Private, androidE)
	t.Logf("Go computes ee: %x", ee1)

	// Step 3: Go receives msg2 and sends msg3
	t.Log("Go attempting to read msg2...")
	_, _, _, err = goHS.ReadMessage(nil, msg2)
	if err != nil {
		t.Errorf("Go failed to read msg2: %v", err)
		t.Log("This is the bug we're investigating!")

		// Debug: verify remote static
		t.Logf("Go's view of Android static: %x", goHS.PeerStatic())
	} else {
		t.Log("Go successfully read msg2!")
		t.Logf("Go sees Android static: %x", goHS.PeerStatic())
		require.Equal(t, androidStaticKey.Public, goHS.PeerStatic(), "Static keys should match")

		msg3, cs1, cs2, err := goHS.WriteMessage(nil, nil)
		require.NoError(t, err)
		// msg3 is: encrypted_s (48) + encrypted_empty_payload (16) = 64 bytes
		require.Len(t, msg3, 64, "msg3 should be 64 bytes (48 + 16 empty payload tag)")
		t.Logf("Go sends msg3: %x", msg3)

		// Step 4: Android receives msg3
		_, cs3, cs4, err := androidHS.ReadMessage(nil, msg3)
		require.NoError(t, err, "Android failed to read msg3")
		require.NotNil(t, cs1, "Go should have cipher 1")
		require.NotNil(t, cs2, "Go should have cipher 2")
		require.NotNil(t, cs3, "Android should have cipher 3")
		require.NotNil(t, cs4, "Android should have cipher 4")

		t.Logf("Android sees Go static: %x", androidHS.PeerStatic())
		require.Equal(t, goStaticKey.Public, androidHS.PeerStatic(), "Go static should match")

		t.Log("✓ Full XX handshake completed successfully!")
	}
}

// TestAndroidLikeHandshake simulates Android's behavior more closely
// by using separate handshake state initialization (like a real Kotlin app would)
func TestAndroidLikeHandshake(t *testing.T) {
	// Go initiator setup (exactly like NoiseSession does)
	goStaticPriv, _ := hex.DecodeString("1000000000000000000000000000000000000000000000000000000000000001")
	goStaticPub, _ := curve25519.X25519(goStaticPriv, curve25519.Basepoint)
	t.Logf("Go static: pub=%x", goStaticPub)

	// Android responder setup (simulated)
	androidStaticPriv, _ := hex.DecodeString("2000000000000000000000000000000000000000000000000000000000000002")
	androidStaticPub, _ := curve25519.X25519(androidStaticPriv, curve25519.Basepoint)
	t.Logf("Android static: pub=%x", androidStaticPub)

	// Use our NoiseSession wrapper (Go side)
	goSession, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: &noise.DHKey{
			Private: goStaticPriv,
			Public:  goStaticPub,
		},
		IsInitiator: true,
	})
	require.NoError(t, err)

	err = goSession.InitHandshake()
	require.NoError(t, err)

	// Use our NoiseSession wrapper (Android side - simulated)
	androidSession, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: &noise.DHKey{
			Private: androidStaticPriv,
			Public:  androidStaticPub,
		},
		IsInitiator: false,
	})
	require.NoError(t, err)

	err = androidSession.InitHandshake()
	require.NoError(t, err)

	// Exchange messages
	t.Log("Step 1: Go sends msg1")
	msg1, done, err := goSession.HandshakeMessage(nil)
	require.NoError(t, err)
	require.False(t, done)
	require.Len(t, msg1, 32)
	t.Logf("msg1: %x", msg1)

	t.Log("Step 2: Android receives msg1, sends msg2")
	msg2, done, err := androidSession.HandshakeMessage(msg1)
	require.NoError(t, err)
	require.False(t, done)
	// NOTE: with flynn/noise, msg2 is 96 bytes (32 + 48 + 16 empty payload tag)
	// But real Android sends 80 bytes (no empty payload tag)!
	require.Len(t, msg2, 96, "msg2 should be 96 bytes with flynn/noise")
	t.Logf("msg2: %x", msg2)

	t.Log("Step 3: Go receives msg2, sends msg3")
	msg3, done, err := goSession.HandshakeMessage(msg2)
	if err != nil {
		t.Errorf("Go failed to process msg2: %v", err)
	} else {
		// msg3 is: encrypted_s (48) + encrypted_empty_payload (16) = 64 bytes
		require.Len(t, msg3, 64, "msg3 should be 64 bytes with flynn/noise")
		require.True(t, done, "Go should be done after msg3")
		t.Logf("msg3: %x", msg3)

		t.Log("Step 4: Android receives msg3")
		_, done, err = androidSession.HandshakeMessage(msg3)
		require.NoError(t, err)
		require.True(t, done, "Android should be done after msg3")

		// Verify keys exchanged correctly
		require.Equal(t, goStaticPub, androidSession.RemoteStaticPublicKey())
		require.Equal(t, androidStaticPub, goSession.RemoteStaticPublicKey())

		t.Log("✓ NoiseSession handshake completed successfully!")

		// Test encryption/decryption
		testMsg := []byte("Hello, secure world!")
		encrypted, err := goSession.Encrypt(testMsg)
		require.NoError(t, err)

		decrypted, err := androidSession.Decrypt(encrypted)
		require.NoError(t, err)
		require.Equal(t, testMsg, decrypted)

		t.Log("✓ Encryption/decryption verified!")
	}
}
