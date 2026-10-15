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
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// A pinUvAuthToken must not outlive the PIN state it was minted under
// (CTAP 2.1 §6.5.2.1).
//
// setPIN is the reachable gap. It runs only when no PIN is set, which makes it
// look like no token could be outstanding -- but
// getPinUvAuthTokenUsingUvWithPermissions mints a token against the
// authenticator's built-in user verification and never asks whether a PIN
// exists, so on a key with a biometric backend a token can be live at exactly
// that moment.
//
// changePIN already dropped the token before this change, incidentally:
// regeneratePINProtocolKeys discards the whole pinProtocolState. The explicit
// invalidation added there wipes the token bytes (regeneration alone leaks
// them unwiped) and keeps the guarantee if key regeneration ever changes; the
// changePIN wipe assertions below are what detect its removal.

// pinCeremony carries the negotiated platform side of a ClientPIN exchange.
type pinCeremony struct {
	platformCOSE []byte
	sharedSecret []byte
}

// beginPINCeremony runs the key-agreement half of a ClientPIN exchange and
// returns what the platform needs to build setPIN and changePIN requests.
func beginPINCeremony(t *testing.T, auth *Authenticator) pinCeremony {
	t.Helper()

	require.NoError(t, initKeyAgreement(t, auth))

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	return pinCeremony{platformCOSE: platformCOSE, sharedSecret: sharedSecret}
}

// installOutstandingToken puts a usable pinUvAuthToken into the live protocol
// state, as a completed getPinUvAuthToken* ceremony would leave it, without
// disturbing the negotiated keys the pending request needs. It returns the
// live token slice, so a caller observes an in-place wipe through it.
func installOutstandingToken(t *testing.T, auth *Authenticator) []byte {
	t.Helper()

	token := authzTestToken()
	auth.mu.Lock()
	auth.beginUsingPinUvAuthTokenLocked(token, PINPermissionMakeCredential, "")
	auth.mu.Unlock()

	require.NotNil(t, auth.GetPinUvAuthToken(),
		"precondition: the token must be live before the PIN operation")
	return token
}

// requireTokenRefused asserts that authParams computed under token no longer
// authorize, with the exact CTAP error the spec requires:
// CTAP2_ERR_PIN_AUTH_INVALID (0x33), which ErrPINAuthInvalid maps to.
func requireTokenRefused(t *testing.T, auth *Authenticator, token []byte) {
	t.Helper()

	cdh := authzClientDataHash()
	err := auth.AuthorizePinUvAuthToken(cdh, pinUvAuthParamFor(token, cdh),
		PINPermissionMakeCredential, "example.com")
	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"an invalidated token must be refused with CTAP2_ERR_PIN_AUTH_INVALID")
}

// requireTokenAuthorizes asserts that authParams computed under token still
// authorize a makeCredential.
func requireTokenAuthorizes(t *testing.T, auth *Authenticator, token []byte) {
	t.Helper()

	cdh := authzClientDataHash()
	require.NoError(t, auth.AuthorizePinUvAuthToken(cdh, pinUvAuthParamFor(token, cdh),
		PINPermissionMakeCredential, "example.com"))
}

// mintTokenUnderPIN runs the real getPinUvAuthTokenUsingPinWithPermissions
// ceremony under pin, from a fresh key agreement, and asserts it succeeds and
// leaves a live token. It is what stops the invalidation tests passing by
// breaking token minting outright.
func mintTokenUnderPIN(t *testing.T, auth *Authenticator, pin string) {
	t.Helper()

	ceremony := beginPINCeremony(t, auth)
	pinHashEnc, err := encryptPINHash(ceremony.sharedSecret, pin)
	require.NoError(t, err)

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, ceremony.platformCOSE),
		clientPINKeyPinHashEnc:        pinHashEnc,
		clientPINKeyPermissions:       PINPermissionMakeCredential,
	})
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	require.NotNil(t, auth.GetPinUvAuthToken(),
		"a token minted under the current PIN must be live")
}

// setPINRequest builds a setPIN request for newPIN under the ceremony's keys.
func setPINRequest(t *testing.T, c pinCeremony, newPIN string) []byte {
	t.Helper()

	newPinEnc, authParam, err := encryptNewPIN(c.sharedSecret, newPIN)
	require.NoError(t, err)

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdSetPIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, c.platformCOSE),
		clientPINKeyPinUvAuthParam:    authParam,
		clientPINKeyNewPinEnc:         newPinEnc,
	})
	require.NoError(t, err)
	return reqBytes
}

// changePINRequest builds a changePIN request from currentPIN to newPIN.
func changePINRequest(t *testing.T, c pinCeremony, currentPIN, newPIN string) []byte {
	t.Helper()

	newPinEnc, _, err := encryptNewPIN(c.sharedSecret, newPIN)
	require.NoError(t, err)
	pinHashEnc, err := encryptPINHash(c.sharedSecret, currentPIN)
	require.NoError(t, err)

	authData := make([]byte, 0, len(newPinEnc)+len(pinHashEnc))
	authData = append(authData, newPinEnc...)
	authData = append(authData, pinHashEnc...)
	mac := hmac.New(sha256.New, c.sharedSecret)
	mac.Write(authData)

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: PINProtocol1,
		clientPINKeySubCommand:        ClientPINSubCmdChangePIN,
		clientPINKeyKeyAgreement:      rawCOSEToMap(t, c.platformCOSE),
		clientPINKeyPinUvAuthParam:    mac.Sum(nil)[:PINAuthSizeV1],
		clientPINKeyNewPinEnc:         newPinEnc,
		clientPINKeyPinHashEnc:        pinHashEnc,
	})
	require.NoError(t, err)
	return reqBytes
}

// TestSetPINInvalidatesOutstandingPinUvAuthToken is the fix: a token minted
// against built-in UV before any PIN existed must not survive setPIN, and a
// platform replaying it must get CTAP2_ERR_PIN_AUTH_INVALID.
func TestSetPINInvalidatesOutstandingPinUvAuthToken(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.False(t, auth.IsPINSet(), "setPIN is reachable only with no PIN set")

	ceremony := beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)
	oldToken := append([]byte(nil), token...)

	resp, err := auth.ProcessCBOR(CmdClientPIN, setPINRequest(t, ceremony, "123456"))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	require.True(t, auth.IsPINSet())

	require.Nil(t, auth.GetPinUvAuthToken(),
		"a token minted before the PIN existed must not survive setPIN")
	require.Equal(t, make([]byte, PINTokenSize), token,
		"the invalidated token's bytes must be wiped, not merely dropped")
	requireTokenRefused(t, auth, oldToken)

	// A token minted under the PIN that now exists works normally, so this
	// test cannot pass by breaking token minting outright.
	mintTokenUnderPIN(t, auth, "123456")
}

// TestSetPINWithNoOutstandingTokenSucceeds is the ordinary path: the
// invalidation must be a no-op when there is nothing to invalidate, rather
// than faulting on absent protocol state.
func TestSetPINWithNoOutstandingTokenSucceeds(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	ceremony := beginPINCeremony(t, auth)
	require.Nil(t, auth.GetPinUvAuthToken(), "precondition: no token outstanding")

	resp, err := auth.ProcessCBOR(CmdClientPIN, setPINRequest(t, ceremony, "123456"))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	require.True(t, auth.IsPINSet())
	require.Nil(t, auth.GetPinUvAuthToken())
}

// TestFailedSetPINLeavesOutstandingTokenUsable is the counterweight for
// setPIN: a rejected attempt must not become a way to destroy a token the
// caller could not otherwise reach.
func TestFailedSetPINLeavesOutstandingTokenUsable(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()

	ceremony := beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)

	// A PIN shorter than the configured minimum is refused by policy, after
	// the request authenticates and before any PIN state is accepted.
	resp, err := auth.ProcessCBOR(CmdClientPIN, setPINRequest(t, ceremony, "1"))
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), resp[0])
	require.False(t, auth.IsPINSet(), "a refused setPIN must not set a PIN")

	require.Equal(t, token, auth.GetPinUvAuthToken(),
		"a refused setPIN must not discard an outstanding token")
	requireTokenAuthorizes(t, auth, token)
}

// TestChangePINInvalidatesOutstandingPinUvAuthToken proves a token minted
// under the old PIN is refused after a successful changePIN with
// CTAP2_ERR_PIN_AUTH_INVALID, and that its bytes are wiped in place -- the
// wipe is what the explicit invalidation adds over the incidental discard
// that regeneratePINProtocolKeys already performed.
func TestChangePINInvalidatesOutstandingPinUvAuthToken(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN([]byte("1234")))

	ceremony := beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)
	oldToken := append([]byte(nil), token...)

	resp, err := auth.ProcessCBOR(CmdClientPIN, changePINRequest(t, ceremony, "1234", "5678"))
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	require.Nil(t, auth.GetPinUvAuthToken(),
		"a token minted under the old PIN must not survive changePIN")
	require.Equal(t, make([]byte, PINTokenSize), token,
		"the invalidated token's bytes must be wiped, not merely dropped")
	requireTokenRefused(t, auth, oldToken)

	// A token minted under the new PIN works normally, so this test cannot
	// pass by breaking token minting outright.
	mintTokenUnderPIN(t, auth, "5678")
}

// TestFailedChangePINLeavesOutstandingTokenUsable is the counterweight the
// fix would be dangerous without: if a wrong current PIN cleared the token,
// anyone able to send a changePIN they cannot authenticate would hold a
// denial-of-service primitive against the legitimate session.
func TestFailedChangePINLeavesOutstandingTokenUsable(t *testing.T) {
	auth := createTestAuthenticatorWithPIN(t)
	defer func() { _ = auth.Close() }()
	require.NoError(t, auth.SetInitialPIN([]byte("1234")))

	ceremony := beginPINCeremony(t, auth)
	token := installOutstandingToken(t, auth)

	resp, err := auth.ProcessCBOR(CmdClientPIN, changePINRequest(t, ceremony, "9999", "5678"))
	require.Error(t, err)
	require.NotEqual(t, byte(StatusOK), resp[0])

	require.Equal(t, token, auth.GetPinUvAuthToken(),
		"a changePIN with the wrong current PIN must not discard the token")
	requireTokenAuthorizes(t, auth, token)

	newPINHash := sha256.Sum256([]byte("5678"))
	require.NotEqual(t, newPINHash[:PINHashSize], auth.state.PINHash,
		"a refused changePIN must not have changed the PIN either")
}
