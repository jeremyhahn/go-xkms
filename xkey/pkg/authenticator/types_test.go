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

package authenticator

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewAuthenticatorState(t *testing.T) {
	state := NewAuthenticatorState()

	require.NotNil(t, state)
	require.Equal(t, DefaultPINMaxRetries, state.PINRetries())
	require.Equal(t, DefaultUVRetries, state.UVRetries())
	require.False(t, state.PINSet)
	require.Nil(t, state.PINHash)
	require.Nil(t, state.AttestationKey)
	require.Nil(t, state.AttestationCert)
}

func TestAuthenticatorState_PINRetries(t *testing.T) {
	state := NewAuthenticatorState()

	t.Run("returns default value", func(t *testing.T) {
		require.Equal(t, DefaultPINMaxRetries, state.PINRetries())
	})

	t.Run("SetPINRetries changes value", func(t *testing.T) {
		state.SetPINRetries(5)
		require.Equal(t, 5, state.PINRetries())
	})

	t.Run("DecrementPINRetries decreases by one", func(t *testing.T) {
		state.SetPINRetries(5)
		newVal := state.DecrementPINRetries()
		require.Equal(t, 4, newVal)
		require.Equal(t, 4, state.PINRetries())
	})

	t.Run("DecrementPINRetries can go negative", func(t *testing.T) {
		state.SetPINRetries(0)
		newVal := state.DecrementPINRetries()
		require.Equal(t, -1, newVal)
	})

	t.Run("ResetPINRetries restores default", func(t *testing.T) {
		state.SetPINRetries(2)
		state.ResetPINRetries()
		require.Equal(t, DefaultPINMaxRetries, state.PINRetries())
	})
}

func TestAuthenticatorState_UVRetries(t *testing.T) {
	state := NewAuthenticatorState()

	t.Run("returns default value", func(t *testing.T) {
		require.Equal(t, DefaultUVRetries, state.UVRetries())
	})

	t.Run("SetUVRetries changes value", func(t *testing.T) {
		state.SetUVRetries(2)
		require.Equal(t, 2, state.UVRetries())
	})

	t.Run("DecrementUVRetries decreases by one", func(t *testing.T) {
		state.SetUVRetries(3)
		newVal := state.DecrementUVRetries()
		require.Equal(t, 2, newVal)
		require.Equal(t, 2, state.UVRetries())
	})

	t.Run("DecrementUVRetries can go negative", func(t *testing.T) {
		state.SetUVRetries(0)
		newVal := state.DecrementUVRetries()
		require.Equal(t, -1, newVal)
	})

	t.Run("ResetUVRetries restores default", func(t *testing.T) {
		state.SetUVRetries(1)
		state.ResetUVRetries()
		require.Equal(t, DefaultUVRetries, state.UVRetries())
	})
}

func TestAuthenticatorState_Concurrent(t *testing.T) {
	state := NewAuthenticatorState()
	done := make(chan bool)

	// Test concurrent PIN retry decrements
	for i := 0; i < 10; i++ {
		go func() {
			state.DecrementPINRetries()
			done <- true
		}()
	}

	for i := 0; i < 10; i++ {
		<-done
	}

	// Should have decremented 10 times from default
	expected := DefaultPINMaxRetries - 10
	require.Equal(t, expected, state.PINRetries())
}

func TestCredProtectConstants(t *testing.T) {
	// Verify credProtect constants match spec
	require.Equal(t, uint8(0), CredProtectNone)
	require.Equal(t, uint8(1), CredProtectUserVerificationOptional)
	require.Equal(t, uint8(2), CredProtectUserVerificationOptionalWithList)
	require.Equal(t, uint8(3), CredProtectUserVerificationRequired)
}

func TestDefaultUVRetries(t *testing.T) {
	// Verify default value is sane (CTAP2 typically uses 3)
	require.Equal(t, 3, DefaultUVRetries)
}
