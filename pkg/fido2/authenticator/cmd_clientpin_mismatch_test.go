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

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// This file covers the CTAP 2.1 §6.5.5.5 consecutive-mismatch rule for the
// user PIN: three mismatches in a row refuse every further attempt with
// CTAP2_ERR_PIN_AUTH_BLOCKED until a power cycle, whatever retries remain, and
// every mismatch regenerates the keyAgreement key.

// pinAttemptSenders are the three ClientPIN subcommands that check a
// pinHashEnc, each sending pin as the current PIN.
var pinAttemptSenders = []struct {
	name string
	send func(t *testing.T, auth *Authenticator, pin string) ([]byte, error)
}{
	{
		name: "changePIN",
		send: func(t *testing.T, auth *Authenticator, pin string) ([]byte, error) {
			return sendChangePINAttempt(t, auth, pin, "5678")
		},
	},
	{
		name: "getPINToken",
		send: sendGetPINTokenAttempt,
	},
	{
		name: "getPinUvAuthTokenUsingPinWithPermissions",
		send: sendGetPinUvAuthTokenUsingPinWithPermissionsAttempt,
	},
}

// getRetriesResponse issues getPINRetries and returns the decoded response.
func getRetriesResponse(t *testing.T, auth *Authenticator) map[int]interface{} {
	t.Helper()

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetRetries,
	})
	require.NoError(t, err)
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &respMap))
	return respMap
}

// keyAgreementX returns the X coordinate of the authenticator's current
// keyAgreement key, as a platform reads it through getKeyAgreement.
func keyAgreementX(t *testing.T, auth *Authenticator) []byte {
	t.Helper()

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetKeyAgreement,
	})
	require.NoError(t, err)
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var respMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &respMap))
	keyMap := cborMapToIntMap(t, respMap[clientPINResponseKeyKeyAgreement])
	x, ok := keyMap[coseKeyLabelX].([]byte)
	require.True(t, ok, "keyAgreement X coordinate must be a byte string")
	return x
}

func TestClientPIN_ThreeConsecutiveMismatchesBlockUntilPowerCycle(t *testing.T) {
	for _, sender := range pinAttemptSenders {
		t.Run(sender.name, func(t *testing.T) {
			auth, _, config := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
			t.Cleanup(func() { require.NoError(t, auth.Close()) })

			for i := 1; i < PINMaxConsecutiveFailures; i++ {
				resp, err := sender.send(t, auth, "wrong")
				require.ErrorIs(t, err, ErrPINInvalid, "attempt %d", i)
				require.Equal(t, byte(StatusPINInvalid), resp[0], "attempt %d", i)
			}

			resp, err := sender.send(t, auth, "wrong")
			require.ErrorIs(t, err, ErrPINAuthBlocked)
			require.Equal(t, byte(StatusPINAuthBlocked), resp[0],
				"the third consecutive mismatch must report PIN_AUTH_BLOCKED")
			retriesLeft := config.PINMaxRetries - PINMaxConsecutiveFailures
			require.Equal(t, retriesLeft, auth.PINRetries())
			require.Positive(t, retriesLeft, "the block must apply while retries remain")

			// Even the correct PIN is refused now, and the refusal spends no retry.
			resp, err = sender.send(t, auth, "1234")
			require.ErrorIs(t, err, ErrPINAuthBlocked)
			require.Equal(t, byte(StatusPINAuthBlocked), resp[0])
			require.Equal(t, retriesLeft, auth.PINRetries(),
				"a refusal under the block must not spend a retry")

			require.Equal(t, true, getRetriesResponse(t, auth)[clientPINResponseKeyPowerCycleState],
				"getPINRetries must report that a power cycle is required")
		})
	}
}

func TestClientPIN_CorrectPINResetsConsecutiveMismatches(t *testing.T) {
	for _, sender := range pinAttemptSenders {
		t.Run(sender.name, func(t *testing.T) {
			auth, _, _ := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
			t.Cleanup(func() { require.NoError(t, auth.Close()) })

			for i := 1; i < PINMaxConsecutiveFailures; i++ {
				_, err := sender.send(t, auth, "wrong")
				require.ErrorIs(t, err, ErrPINInvalid)
			}

			resp, err := sender.send(t, auth, "1234")
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])

			// changePIN replaced the PIN; the next guesses are wrong either way.
			for i := 1; i < PINMaxConsecutiveFailures; i++ {
				resp, err = sender.send(t, auth, "wrong")
				require.ErrorIs(t, err, ErrPINInvalid,
					"the correct PIN must have cleared the earlier mismatches (attempt %d)", i)
				require.Equal(t, byte(StatusPINInvalid), resp[0])
			}
			require.Equal(t, false, getRetriesResponse(t, auth)[clientPINResponseKeyPowerCycleState])
		})
	}
}

func TestClientPIN_MismatchRegeneratesKeyAgreement(t *testing.T) {
	auth, _, _ := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })

	before := keyAgreementX(t, auth)
	require.Equal(t, before, keyAgreementX(t, auth),
		"getKeyAgreement alone must not rotate the key")

	_, err := sendGetPINTokenAttempt(t, auth, "wrong")
	require.ErrorIs(t, err, ErrPINInvalid)

	require.NotEqual(t, before, keyAgreementX(t, auth),
		"a PIN mismatch must regenerate the keyAgreement key")
}

func TestClientPIN_MismatchKeepsExistingToken(t *testing.T) {
	auth, _, _ := newRetryPersistenceTestAuthenticator(t, DefaultPINMaxRetries)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })

	resp, err := sendGetPINTokenAttempt(t, auth, "1234")
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	auth.mu.RLock()
	token := append([]byte(nil), auth.pinState.protocol.pinUvAuthToken...)
	auth.mu.RUnlock()
	require.NotEmpty(t, token)

	_, err = sendGetPINTokenAttempt(t, auth, "wrong")
	require.ErrorIs(t, err, ErrPINInvalid)

	auth.mu.RLock()
	defer auth.mu.RUnlock()
	require.Equal(t, token, auth.pinState.protocol.pinUvAuthToken,
		"a wrong guess must not revoke the token a legitimate holder minted")
}
