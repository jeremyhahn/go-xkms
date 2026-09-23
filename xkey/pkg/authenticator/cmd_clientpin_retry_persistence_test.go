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
	"crypto/hmac"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// This file covers go-xkms#686: a failed PIN attempt must be recorded
// durably before it is ever compared, or the whole attempt must fail closed.
// Before the fix, DecrementPINRetries and SaveState ran AFTER the pinHash
// comparison, and the persist's own error was discarded with `_ =`, so a
// storage failure silently let the brute-force limit reset on restart.

// newRetryPersistenceTestAuthenticator builds an authenticator over a real
// MemoryStorage the test keeps a handle to, so state can be reloaded through
// a second Authenticator instance to prove durability, or swapped for a
// failing wrapper to prove fail-closed behavior.
func newRetryPersistenceTestAuthenticator(t *testing.T, maxRetries int) (*Authenticator, *MemoryStorage, *Config) {
	t.Helper()

	storage := NewMemoryStorage()
	config := &Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             storage,
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       maxRetries,
		SupportedAlgorithms: []int{COSEAlgES256},
	}

	auth, err := NewAuthenticator(config)
	require.NoError(t, err)

	require.NoError(t, auth.SetInitialPIN([]byte("1234")))
	require.NoError(t, initKeyAgreement(t, auth))

	return auth, storage, config
}

// sendGetPINTokenAttempt issues a getPinToken ClientPIN request for pin,
// generating a fresh platform ECDH key pair as a real platform would for
// each attempt.
func sendGetPINTokenAttempt(t *testing.T, auth *Authenticator, pin string) ([]byte, error) {
	t.Helper()

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
	}
	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	return auth.ProcessCBOR(CmdClientPIN, reqBytes)
}

// sendGetPinUvAuthTokenUsingPinWithPermissionsAttempt issues a
// getPinUvAuthTokenUsingPinWithPermissions request for pin.
func sendGetPinUvAuthTokenUsingPinWithPermissionsAttempt(t *testing.T, auth *Authenticator, pin string) ([]byte, error) {
	t.Helper()

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, pin)
	require.NoError(t, err)

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	}
	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	return auth.ProcessCBOR(CmdClientPIN, reqBytes)
}

// sendChangePINAttempt issues a changePIN request proving currentPIN and
// requesting newPIN.
func sendChangePINAttempt(t *testing.T, auth *Authenticator, currentPIN, newPIN string) ([]byte, error) {
	t.Helper()

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	newPinEnc, _, err := encryptNewPIN(sharedSecret, newPIN)
	require.NoError(t, err)
	pinHashEnc, err := encryptPINHash(sharedSecret, currentPIN)
	require.NoError(t, err)

	authData := make([]byte, 0, len(newPinEnc)+len(pinHashEnc))
	authData = append(authData, newPinEnc...)
	authData = append(authData, pinHashEnc...)
	mac := hmac.New(sha256.New, sharedSecret)
	mac.Write(authData)
	authParam := mac.Sum(nil)[:PINAuthSizeV1]

	req := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	}
	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	return auth.ProcessCBOR(CmdClientPIN, reqBytes)
}

// TestPINRetryConsumption_AllPINPathsFailClosedOnStorageFailure proves the
// requirement at the heart of #686 for all three ClientPIN subcommands that
// check a pinHashEnc: when the spent retry cannot be persisted, the
// operation fails closed with a typed storage error, and the CORRECT PIN is
// never observed to succeed. If any of these still compared the PIN before
// (or independent of) the persist, sending the correct PIN here would
// return StatusOK instead of StatusOtherError.
func TestPINRetryConsumption_AllPINPathsFailClosedOnStorageFailure(t *testing.T) {
	attempts := []struct {
		name string
		send func(t *testing.T, auth *Authenticator) ([]byte, error)
	}{
		{
			name: "changePIN",
			send: func(t *testing.T, auth *Authenticator) ([]byte, error) {
				return sendChangePINAttempt(t, auth, "1234", "5678")
			},
		},
		{
			name: "getPINToken",
			send: func(t *testing.T, auth *Authenticator) ([]byte, error) {
				return sendGetPINTokenAttempt(t, auth, "1234")
			},
		},
		{
			name: "getPinUvAuthTokenUsingPinWithPermissions",
			send: func(t *testing.T, auth *Authenticator) ([]byte, error) {
				return sendGetPinUvAuthTokenUsingPinWithPermissionsAttempt(t, auth, "1234")
			},
		},
	}

	for _, attempt := range attempts {
		t.Run(attempt.name, func(t *testing.T) {
			auth, storage, config := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
			defer func() { _ = auth.Close() }()

			// Swap in a storage that fails every SaveState, after the PIN
			// itself was durably established with the real store.
			cause := errors.New("disk full")
			auth.storage = &saveStateErrorStorage{storage: storage, saveStateErr: cause}

			resp, err := attempt.send(t, auth)

			require.Error(t, err)
			require.ErrorIs(t, err, ErrStorageError)
			require.ErrorIs(t, err, cause,
				"the backend's cause must be reachable through the typed error")
			require.Equal(t, byte(StatusOtherError), resp[0],
				"a persist failure on the correct PIN must report a storage error, "+
					"never success (StatusOK) or a compared mismatch (StatusPINInvalid)")

			persisted, loadErr := storage.LoadState()
			require.NoError(t, loadErr)
			require.Equal(t, config.PINMaxRetries, persisted.PINRetries(),
				"a failed persist must not be observable as a spent retry after reload")
		})
	}
}

// TestPINRetryConsumption_PersistsEveryAttemptAcrossReload proves every
// failed attempt is durable, not just the last one held in memory: a fresh
// Authenticator over the same storage (simulating a process restart) must
// see the full count of attempts spent before the restart.
func TestPINRetryConsumption_PersistsEveryAttemptAcrossReload(t *testing.T) {
	auth, _, config := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
	defer func() { _ = auth.Close() }()

	const failedAttempts = 3
	for i := 0; i < failedAttempts; i++ {
		resp, err := sendGetPINTokenAttempt(t, auth, "wrong")
		require.Error(t, err)
		require.Equal(t, byte(StatusPINInvalid), resp[0])
	}

	reloaded, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = reloaded.Close() }()

	require.Equal(t, config.PINMaxRetries-failedAttempts, reloaded.PINRetries(),
		"a reload must reflect every attempt spent before the restart")
}

// TestPINRetryConsumption_CorrectPINResetsDurably proves a successful PIN
// verification's retry-budget reset is itself persisted immediately, not
// left to whatever the caller happens to save afterward.
func TestPINRetryConsumption_CorrectPINResetsDurably(t *testing.T) {
	auth, _, config := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
	defer func() { _ = auth.Close() }()

	for i := 0; i < 2; i++ {
		_, err := sendGetPINTokenAttempt(t, auth, "wrong")
		require.Error(t, err)
	}
	require.Equal(t, config.PINMaxRetries-2, auth.PINRetries(),
		"precondition: two failed attempts spent")

	resp, err := sendGetPINTokenAttempt(t, auth, "1234")
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	reloaded, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = reloaded.Close() }()

	require.Equal(t, config.PINMaxRetries, reloaded.PINRetries(),
		"a correct PIN must reset the retry budget durably, not only in memory")
}

// TestPINRetryConsumption_LockoutAtZeroHoldsAcrossReload proves the terminal
// blocked state survives a restart and continues to refuse even the correct
// PIN, holding the lockout semantics CTAP 2.1 requires.
func TestPINRetryConsumption_LockoutAtZeroHoldsAcrossReload(t *testing.T) {
	auth, _, config := newRetryPersistenceTestAuthenticator(t, 2)
	defer func() { _ = auth.Close() }()

	for i := 0; i < 2; i++ {
		_, _ = sendGetPINTokenAttempt(t, auth, "wrong")
	}
	require.Equal(t, 0, auth.PINRetries(), "precondition: retry budget exhausted")

	reloaded, err := NewAuthenticator(config)
	require.NoError(t, err)
	defer func() { _ = reloaded.Close() }()

	require.Equal(t, 0, reloaded.PINRetries(), "the lockout must survive a reload")

	require.NoError(t, initKeyAgreement(t, reloaded))
	resp, err := sendGetPINTokenAttempt(t, reloaded, "1234")
	require.Error(t, err)
	require.Equal(t, byte(StatusPINBlocked), resp[0],
		"a reloaded authenticator must still refuse the correct PIN once locked out")
}
