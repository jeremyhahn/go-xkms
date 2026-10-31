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

package fido2

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// simulatedHandler is a FIDO2Handler over one simulated authenticator, whose
// PIN is pin ("" for a key without one).
func simulatedHandler(t *testing.T, pin string) (*FIDO2Handler, *authenticatorSim) {
	t.Helper()
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	mockDev.sim.pin = pin
	enum := NewMockHIDDeviceEnumerator()
	enum.AddDevice(mockDev)
	config := DefaultConfig
	handler, err := NewHandler(&config, enum)
	require.NoError(t, err)
	return handler, mockDev.sim
}

// TestDeriveHMACSecret_ReturnsTheRawOutput proves the handler returns the
// authenticator's hmac-secret output itself -- HMAC-SHA-256(CredRandom,
// salt), computed inside the simulator from a secret that never leaves it --
// not a key derived from it, and that UnlockWithKey is that output run
// through GenerateDerivedKey.
func TestDeriveHMACSecret_ReturnsTheRawOutput(t *testing.T) {
	handler, sim := simulatedHandler(t, "")
	salt := bytes.Repeat([]byte{0x42}, 32)

	result, err := handler.DeriveHMACSecret(&AuthenticationConfig{
		RelyingPartyID: "kms.example.com",
		CredentialID:   sim.credentialID,
		Salt:           salt,
	})
	require.NoError(t, err)
	assert.Equal(t, sim.hmacOutput(salt), result.HMACSecret)
	assert.Len(t, result.HMACSecret, 32)

	key, err := handler.UnlockWithKey(&AuthenticationConfig{RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt})
	require.NoError(t, err)
	assert.Equal(t, expectedUnlockKey(t, sim, salt), key)
}

// TestHandler_DeriveHMACSecret covers DeriveHMACSecret through the Handler
// interface: it returns the raw 32-byte CTAP 2.1 §12.5 hmac-secret output,
// which is not the key UnlockWithKey derives from it, and it refuses a nil
// config and a salt that is not 32 bytes.
func TestHandler_DeriveHMACSecret(t *testing.T) {
	salt := bytes.Repeat([]byte{0x5a}, 32)

	t.Run("raw output", func(t *testing.T) {
		concrete, sim := simulatedHandler(t, "")
		var handler Handler = concrete
		config := &AuthenticationConfig{RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt}

		result, err := handler.DeriveHMACSecret(config)
		require.NoError(t, err)
		require.Len(t, result.HMACSecret, 32)
		assert.Equal(t, sim.hmacOutput(salt), result.HMACSecret)

		key, err := handler.UnlockWithKey(config)
		require.NoError(t, err)
		assert.NotEqual(t, result.HMACSecret, key)
	})

	t.Run("nil config", func(t *testing.T) {
		concrete, _ := simulatedHandler(t, "")
		var handler Handler = concrete
		_, err := handler.DeriveHMACSecret(nil)
		assert.ErrorIs(t, err, ErrAuthenticationConfigNil)
	})

	t.Run("bad salt length", func(t *testing.T) {
		concrete, sim := simulatedHandler(t, "")
		var handler Handler = concrete
		_, err := handler.DeriveHMACSecret(&AuthenticationConfig{
			RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt[:16],
		})
		assert.ErrorIs(t, err, ErrInvalidSalt)
	})
}

// TestDeriveHMACSecret_WithPIN covers a PIN-protected authenticator: the
// right PIN evaluates, a missing PIN and a wrong PIN are refused with the
// typed errors, and a wrong PIN reports the attempts left.
func TestDeriveHMACSecret_WithPIN(t *testing.T) {
	salt := bytes.Repeat([]byte{0x24}, 32)

	t.Run("right PIN", func(t *testing.T) {
		handler, sim := simulatedHandler(t, "123456")
		result, err := handler.DeriveHMACSecret(&AuthenticationConfig{
			RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt,
			PIN: testSecret(t, "123456"),
		})
		require.NoError(t, err)
		assert.Equal(t, sim.hmacOutput(salt), result.HMACSecret)
	})

	t.Run("missing PIN", func(t *testing.T) {
		handler, sim := simulatedHandler(t, "123456")
		_, err := handler.DeriveHMACSecret(&AuthenticationConfig{RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrPINRequired)
	})

	t.Run("wrong PIN", func(t *testing.T) {
		handler, sim := simulatedHandler(t, "123456")
		_, err := handler.DeriveHMACSecret(&AuthenticationConfig{
			RelyingPartyID: "kms.example.com", CredentialID: sim.credentialID, Salt: salt,
			PIN: testSecret(t, "000000"),
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, ErrInvalidPIN)
		var attempts *PINAttemptsError
		require.True(t, errors.As(err, &attempts))
		assert.Equal(t, uint64(defaultSimPINRetries-1), attempts.Retries)
	})

	t.Run("nil config", func(t *testing.T) {
		handler, _ := simulatedHandler(t, "")
		_, err := handler.DeriveHMACSecret(nil)
		assert.ErrorIs(t, err, ErrAuthenticationConfigNil)
	})
}

// TestEnrollKey_WithPIN covers enrolling on a PIN-protected authenticator:
// the PIN authorizes MakeCredential; without it, or with a wrong one, the
// key refuses.
func TestEnrollKey_WithPIN(t *testing.T) {
	enroll := func(handler *FIDO2Handler, pin string) (*EnrollmentResult, error) {
		cfg := DefaultEnrollmentConfig("alice")
		cfg.RelyingParty = RelyingParty{ID: "kms.example.com", Name: "xkms password vault"}
		cfg.PIN = testSecret(t, pin)
		return handler.EnrollKey(cfg)
	}

	t.Run("right PIN", func(t *testing.T) {
		handler, sim := simulatedHandler(t, "123456")
		result, err := enroll(handler, "123456")
		require.NoError(t, err)
		assert.Equal(t, sim.credentialID, result.CredentialID)
	})

	t.Run("missing PIN", func(t *testing.T) {
		handler, _ := simulatedHandler(t, "123456")
		_, err := enroll(handler, "")
		assert.ErrorIs(t, err, ErrPINRequired)
	})

	t.Run("wrong PIN", func(t *testing.T) {
		handler, _ := simulatedHandler(t, "123456")
		_, err := enroll(handler, "000000")
		assert.ErrorIs(t, err, ErrInvalidPIN)
	})

	t.Run("key without a PIN", func(t *testing.T) {
		handler, _ := simulatedHandler(t, "")
		_, err := enroll(handler, "")
		require.NoError(t, err)
	})

	t.Run("nil config", func(t *testing.T) {
		handler, _ := simulatedHandler(t, "")
		_, err := handler.EnrollKey(nil)
		assert.ErrorIs(t, err, ErrEnrollmentConfigNil)
	})
}
