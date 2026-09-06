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
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

// SetInitialPIN is the in-process way a first PIN comes into existence: the
// xkey daemon's --set-pin seeding and a first-run wizard both use it. It used
// to be SetPINForTesting (#377), a helper that wrote the hash directly and so
// skipped the two guarantees the CTAP setPIN path carries: it must not
// replace a PIN that already exists, and it must invalidate any outstanding
// pinUvAuthToken (#322). These tests pin both to the production API.

// TestSetInitialPIN_EstablishesPINWhenNoneSet is the ordinary path: the PIN
// becomes set, the retry counter is at its maximum, the state is persisted,
// and the real getPinUvAuthToken ceremony accepts the PIN afterwards.
func TestSetInitialPIN_EstablishesPINWhenNoneSet(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.False(t, auth.IsPINSet(), "precondition: fresh authenticator has no PIN")

	require.NoError(t, auth.SetInitialPIN("123456"))

	require.True(t, auth.IsPINSet())
	require.Equal(t, auth.config.PINMaxRetries, auth.PINRetries())

	persisted, err := auth.storage.LoadState()
	require.NoError(t, err)
	require.True(t, persisted.PINSet, "the established PIN must be persisted")
	wantHash := sha256.Sum256([]byte("123456"))
	require.Equal(t, wantHash[:PINHashSize], persisted.PINHash)

	mintTokenUnderPIN(t, auth, "123456")
}

// TestSetInitialPIN_InvalidatesOutstandingPinUvAuthToken carries #322's
// guarantee onto the in-process path: a token minted against built-in UV
// before any PIN existed must not survive the PIN's establishment, and its
// bytes must be wiped, not merely dropped.
func TestSetInitialPIN_InvalidatesOutstandingPinUvAuthToken(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)
	oldToken := append([]byte(nil), token...)

	require.NoError(t, auth.SetInitialPIN("123456"))

	require.Nil(t, auth.GetPinUvAuthToken(),
		"a token minted before the PIN existed must not survive SetInitialPIN")
	require.Equal(t, make([]byte, PINTokenSize), token,
		"the invalidated token's bytes must be wiped, not merely dropped")
	requireTokenRefused(t, auth, oldToken)

	// Minting under the new PIN still works, so this test cannot pass by
	// breaking token minting outright.
	mintTokenUnderPIN(t, auth, "123456")
}

// TestSetInitialPIN_RefusedWhenPINAlreadySet is the precondition: an
// existing PIN is replaced only through changePIN, which proves the current
// one. A refused call must leave the PIN hash, the retry counter and any
// outstanding token exactly as they were.
func TestSetInitialPIN_RefusedWhenPINAlreadySet(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN("123456"))

	// Spend some retries so a silent retry-counter reset is observable.
	auth.mu.Lock()
	auth.state.SetPINRetries(3)
	auth.mu.Unlock()

	beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)

	err := auth.SetInitialPIN("654321")
	require.ErrorIs(t, err, ErrPINAlreadySet)

	wantHash := sha256.Sum256([]byte("123456"))
	auth.mu.RLock()
	gotHash := append([]byte(nil), auth.state.PINHash...)
	auth.mu.RUnlock()
	require.Equal(t, wantHash[:PINHashSize], gotHash, "a refused call must not replace the PIN")
	require.Equal(t, 3, auth.PINRetries(), "a refused call must not reset the retry counter")
	require.Equal(t, token, auth.GetPinUvAuthToken(),
		"a refused call must not discard an outstanding token")
	requireTokenAuthorizes(t, auth, token)

	// The original PIN still works for the real ceremony.
	mintTokenUnderPIN(t, auth, "123456")
}

// TestSetInitialPIN_RefusesPolicyViolatingPIN proves the configured minimum
// length applies to the in-process path exactly as it does to setPIN, and
// that a refused call leaves no PIN and no token damage behind.
func TestSetInitialPIN_RefusesPolicyViolatingPIN(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.Equal(t, 4, auth.config.PINMinLength, "precondition: test config minimum")

	beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)

	err := auth.SetInitialPIN("123")
	require.ErrorIs(t, err, ErrPINPolicyViolation)

	require.False(t, auth.IsPINSet(), "a refused PIN must not be set")
	// Nothing was persisted: a fresh memory store has no state document at
	// all, and a store that has one must not show a PIN.
	if persisted, loadErr := auth.storage.LoadState(); loadErr == nil {
		require.False(t, persisted.PINSet, "a refused PIN must not be persisted")
	} else {
		require.ErrorIs(t, loadErr, ErrStateNotFound)
	}
	require.Equal(t, token, auth.GetPinUvAuthToken(),
		"a refused call must not discard an outstanding token")
	requireTokenAuthorizes(t, auth, token)
}

// TestSetInitialPIN_StorageFailureIsTyped proves a persistence failure is
// reported as ErrStorageError with the backend's cause attached, and that the
// outstanding token was already invalidated by then: the state the
// authenticator considers set must never sit behind a live token.
func TestSetInitialPIN_StorageFailureIsTyped(t *testing.T) {
	cause := errors.New("disk full")
	storage := &saveStateErrorStorage{storage: NewMemoryStorage(), saveStateErr: cause}
	config := &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
	}
	auth, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = auth.Close() }()

	beginPINCeremony(t, auth)
	installOutstandingToken(t, auth)

	err = auth.SetInitialPIN("123456")
	require.ErrorIs(t, err, ErrStorageError)
	require.ErrorIs(t, err, cause, "the backend's cause must be reachable through the typed error")
	require.Nil(t, auth.GetPinUvAuthToken(),
		"invalidation precedes persistence, so a storage failure leaves no live token")
}

// TestSetPINCeremonyAndSetInitialPINShareEstablishment proves the wire
// ceremony and the in-process API converge on one path: a PIN established
// over the wire refuses the in-process API with ErrPINAlreadySet, and the
// wire ceremony refuses a PIN the in-process API established.
func TestSetPINCeremonyAndSetInitialPINShareEstablishment(t *testing.T) {
	t.Run("wire then in-process", func(t *testing.T) {
		auth := createTestAuthenticatorWithPIN(t)
		defer func() { _ = auth.Close() }()

		ceremony := beginPINCeremony(t, auth)
		resp, err := auth.ProcessCBOR(CmdClientPIN, setPINRequest(t, ceremony, "123456"))
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])

		require.ErrorIs(t, auth.SetInitialPIN("654321"), ErrPINAlreadySet)
	})

	t.Run("in-process then wire", func(t *testing.T) {
		auth := createTestAuthenticatorWithPIN(t)
		defer func() { _ = auth.Close() }()

		require.NoError(t, auth.SetInitialPIN("123456"))

		ceremony := beginPINCeremony(t, auth)
		resp, err := auth.ProcessCBOR(CmdClientPIN, setPINRequest(t, ceremony, "654321"))
		require.Error(t, err)
		require.Equal(t, byte(StatusPINInvalid), resp[0],
			"CTAP setPIN on an authenticator with a PIN answers CTAP2_ERR_PIN_INVALID")
		mintTokenUnderPIN(t, auth, "123456")
	})
}
