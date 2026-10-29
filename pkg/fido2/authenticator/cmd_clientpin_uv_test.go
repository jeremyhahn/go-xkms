// Copyright (c) 2025 Jeremy Hahn
// SPDX-License-Identifier: AGPL-3.0-or-later

package authenticator

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
)

// errUserNotVerified is what the verifying backend below answers when it is
// told to refuse.
var errUserNotVerified = errors.New("test: user not verified")

// verifyingKeyBackend is a key backend with a built-in user verification
// method (keybackend.UserVerifier, ruling 167). It records each call and the
// RP ID it was asked for, and answers with err.
type verifyingKeyBackend struct {
	mockUVKeyBackend
	err   error
	calls int
	rpID  string
}

var _ keybackend.UserVerifier = (*verifyingKeyBackend)(nil)

func (b *verifyingKeyBackend) VerifyUser(_ context.Context, rpID string) error {
	b.calls++
	b.rpID = rpID
	return b.err
}

func newVerifyingAuthenticator(t *testing.T, backend *verifyingKeyBackend) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		UserPresenceHandler: NewAutoGrantHandler(),
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		PINMinLength:        4,
		PINMaxRetries:       8,
		SupportedAlgorithms: []int{COSEAlgES256},
		KeyBackend:          backend,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })
	require.NoError(t, initKeyAgreement(t, auth))
	return auth
}

// uvTokenRequest builds a getPinUvAuthTokenUsingUvWithPermissions request
// under protocol and returns it with the key the token comes back under. An
// empty rpID leaves the optional rpId parameter out.
func uvTokenRequest(t *testing.T, auth *Authenticator, protocol uint8, permissions uint8, rpID string) ([]byte, []byte) {
	t.Helper()

	auth.mu.Lock()
	var platformCOSE, key []byte
	var err error
	if protocol == PINProtocol2 {
		platformCOSE, _, key, err = auth.generatePlatformKeyAgreementV2()
	} else {
		platformCOSE, key, err = auth.generatePlatformKeyAgreement()
	}
	auth.mu.Unlock()
	require.NoError(t, err)

	var platformCOSEMap map[int]interface{}
	require.NoError(t, cbor.Unmarshal(platformCOSE, &platformCOSEMap))

	request := map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: protocol,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:      platformCOSEMap,
		clientPINKeyPermissions:       permissions,
	}
	if rpID != "" {
		request[clientPINKeyPermissionsRPID] = rpID
	}
	reqBytes, err := cbor.Marshal(request)
	require.NoError(t, err)
	return reqBytes, key
}

// TestGetPinUvAuthTokenUsingUv_MintsAfterVerification is the working case:
// the backend verified the user, so a token is minted with the requested
// permissions and returned encrypted under the platform's shared secret.
func TestGetPinUvAuthTokenUsingUv_MintsAfterVerification(t *testing.T) {
	for _, protocol := range []uint8{PINProtocol1, PINProtocol2} {
		t.Run(fmt.Sprintf("protocol %d", protocol), func(t *testing.T) {
			backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
			auth := newVerifyingAuthenticator(t, backend)
			auth.state.SetUVRetries(1)

			reqBytes, key := uvTokenRequest(t, auth, protocol, PINPermissionCredentialMgmt, "example.com")
			resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, 1, backend.calls)
			require.Equal(t, "example.com", backend.rpID, "the user is asked on behalf of the token's RP (ruling 180)")

			var body map[int][]byte
			require.NoError(t, cbor.Unmarshal(resp[1:], &body))
			token, err := decryptData(key, protocol, body[clientPINResponseKeyPinUvAuthToken])
			require.NoError(t, err)
			require.Equal(t, auth.GetPinUvAuthToken(), token)

			auth.mu.RLock()
			perms := auth.pinState.protocol.tokenPermissions
			rpID := auth.pinState.protocol.tokenRPID
			verified := auth.pinState.protocol.tokenUserVerified
			auth.mu.RUnlock()
			require.Equal(t, uint8(PINPermissionCredentialMgmt), perms)
			require.Equal(t, "example.com", rpID)
			require.True(t, verified)
			require.Equal(t, DefaultUVRetries, auth.state.UVRetries(), "a verification resets uvRetries")
		})
	}
}

// TestGetPinUvAuthTokenUsingUv_AuthenticatorWidePermissionNamesNoRP pins the
// consent scope: a permission whose rpId CTAP 2.1 §6.5.5.7 ignores carries
// authenticator-wide authority, so the user is never asked on behalf of the
// RP the request names. A credentialMgmt token, which §6.8 scopes to its
// rpId, is still asked for on behalf of that RP.
func TestGetPinUvAuthTokenUsingUv_AuthenticatorWidePermissionNamesNoRP(t *testing.T) {
	tests := []struct {
		name        string
		permissions uint8
		wantRPID    string
	}{
		{"authenticatorConfig", PINPermissionAuthenticatorCfg, ""},
		{"largeBlobWrite", PINPermissionLargeBlobWrite, ""},
		{"credentialMgmt with authenticatorConfig", PINPermissionCredentialMgmt | PINPermissionAuthenticatorCfg, ""},
		{"makeCredential with authenticatorConfig", PINPermissionMakeCredential | PINPermissionAuthenticatorCfg, ""},
		{"credentialMgmt", PINPermissionCredentialMgmt, "example.com"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
			auth := newVerifyingAuthenticator(t, backend)

			reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, tt.permissions, "example.com")
			resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, 1, backend.calls)
			require.Equal(t, tt.wantRPID, backend.rpID)
		})
	}
}

// TestGetPinUvAuthTokenUsingUv_TokenDrivesCredentialManagementWithoutPIN
// spends a token minted by built-in user verification on an authenticator
// that has no PIN: credential management accepts it rather than answering
// CTAP2_ERR_PIN_NOT_SET before the token is ever checked.
func TestGetPinUvAuthTokenUsingUv_TokenDrivesCredentialManagementWithoutPIN(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
	auth := newVerifyingAuthenticator(t, backend)
	auth.config.EnableCredentialManagement = true
	require.False(t, auth.IsPINSet())

	cred := createCredMgmtTestCredential(t, "example.com", "Example", "user1", "alice", "Alice", true)
	require.NoError(t, auth.storage.Store(cred))

	reqBytes, key := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	var body map[int][]byte
	require.NoError(t, cbor.Unmarshal(resp[1:], &body))
	token, err := decryptData(key, PINProtocol2, body[clientPINResponseKeyPinUvAuthToken])
	require.NoError(t, err)

	data := buildCredMgmtRequestV2(t, token, CredMgmtDeleteCredential, map[int]interface{}{
		credMgmtParamCredentialID: map[string]interface{}{"type": "public-key", "id": cred.CredentialID},
	})
	resp, err = auth.ProcessCBOR(CmdCredentialManagement, data)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	_, err = auth.storage.Load(cred.CredentialID)
	require.ErrorIs(t, err, ErrCredentialNotFound)
}

// TestCredentialManagementWithoutPINOrToken keeps CTAP2_ERR_PIN_NOT_SET for a
// request no token can authorize on an authenticator with no PIN.
func TestCredentialManagementWithoutPINOrToken(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
	auth := newVerifyingAuthenticator(t, backend)
	auth.config.EnableCredentialManagement = true

	data := buildCredMgmtRequestV2(t, make([]byte, PINTokenSize), CredMgmtEnumerateRPsBegin, nil)
	resp, err := auth.ProcessCBOR(CmdCredentialManagement, data)
	require.ErrorIs(t, err, ErrPINNotSet)
	require.Equal(t, byte(StatusPINNotSet), resp[0])
}

// TestGetPinUvAuthTokenUsingUv_NoRPAsksWithoutOne pins that a request for
// permissions that are not RP-scoped, which carries no rpId, reaches the
// verifier with an empty RP ID rather than one the platform did not send.
func TestGetPinUvAuthTokenUsingUv_NoRPAsksWithoutOne(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
	auth := newVerifyingAuthenticator(t, backend)

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	require.Equal(t, 1, backend.calls)
	require.Empty(t, backend.rpID)
}

// TestGetPinUvAuthTokenUsingUv_RPScopedPermissionNeedsRPID pins that a
// request for makeCredential or getAssertion without an rpId is refused with
// CTAP2_ERR_MISSING_PARAMETER before the user is asked: the user would be
// consenting for no RP, and the token would bind to whichever RP used it
// first.
func TestGetPinUvAuthTokenUsingUv_RPScopedPermissionNeedsRPID(t *testing.T) {
	for _, permissions := range []uint8{
		PINPermissionMakeCredential,
		PINPermissionGetAssertion,
		PINPermissionGetAssertion | PINPermissionCredentialMgmt,
	} {
		t.Run(fmt.Sprintf("permissions %#x", permissions), func(t *testing.T) {
			backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
			auth := newVerifyingAuthenticator(t, backend)

			reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, permissions, "")
			resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

			require.ErrorIs(t, err, ErrMissingRPID)
			require.Equal(t, []byte{byte(StatusMissingParameter)}, resp)
			require.Zero(t, backend.calls, "the user is never asked for a token with no RP")
			require.Nil(t, auth.GetPinUvAuthToken())
			require.Equal(t, DefaultUVRetries, auth.state.UVRetries())
		})
	}

	t.Run("with an rpId", func(t *testing.T) {
		backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
		auth := newVerifyingAuthenticator(t, backend)

		reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionGetAssertion, "example.com")
		resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
		require.Equal(t, "example.com", backend.rpID)
		auth.mu.RLock()
		rpID := auth.pinState.protocol.tokenRPID
		auth.mu.RUnlock()
		require.Equal(t, "example.com", rpID, "the token is bound to the RP the user was asked for")
	})
}

// TestGetPinUvAuthTokenUsingUv_VerifierRefusalBlocksMinting pins that a
// refused verification mints nothing, answers CTAP2_ERR_UV_INVALID, spends a
// retry, and leaves an outstanding token as it was.
func TestGetPinUvAuthTokenUsingUv_VerifierRefusalBlocksMinting(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}, err: errUserNotVerified}
	auth := newVerifyingAuthenticator(t, backend)
	want := append([]byte(nil), installOutstandingToken(t, auth)...)

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

	require.ErrorIs(t, err, ErrUVInvalid)
	require.ErrorIs(t, err, errUserNotVerified)
	require.Equal(t, []byte{byte(StatusUVInvalid)}, resp)
	require.Equal(t, want, auth.GetPinUvAuthToken(), "a refusal must not replace the outstanding token")
	require.Equal(t, DefaultUVRetries-1, auth.state.UVRetries())
}

// TestGetPinUvAuthTokenUsingUv_Blocked pins the uvRetries counter: the last
// failed verification answers CTAP2_ERR_UV_BLOCKED, and once it is spent the
// user is never asked again.
func TestGetPinUvAuthTokenUsingUv_Blocked(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}, err: errUserNotVerified}
	auth := newVerifyingAuthenticator(t, backend)
	auth.state.SetUVRetries(1)

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
	_, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUVBlocked)

	backend.err = nil
	reqBytes, _ = uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUVBlocked)
	require.Equal(t, []byte{byte(StatusUVBlocked)}, resp)
	require.Equal(t, 1, backend.calls, "a blocked authenticator must not run the ceremony")
	require.Nil(t, auth.GetPinUvAuthToken())
}

// TestGetPinUvAuthTokenUsingUv_CancelSpendsNoRetry pins that a platform
// cancelling the request is not a failed verification.
func TestGetPinUvAuthTokenUsingUv_CancelSpendsNoRetry(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}, err: context.Canceled}
	auth := newVerifyingAuthenticator(t, backend)

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []byte{byte(StatusKeepaliveCancel)}, resp)
	require.Equal(t, DefaultUVRetries, auth.state.UVRetries())
	require.Nil(t, auth.GetPinUvAuthToken())
}

// TestGetPinUvAuthTokenUsingUv_UnavailableSpendsNoRetry pins that a verifier
// which could not reach a decision — the phone dropped, the exchange timed
// out, the revocation list was unreachable — mints nothing, answers
// CTAP1_ERR_OTHER, and spends no uvRetries, so an outage cannot block the
// ceremony. A refusal after it still spends one.
func TestGetPinUvAuthTokenUsingUv_UnavailableSpendsNoRetry(t *testing.T) {
	unavailable := &keybackend.SentinelCauseError{
		Sentinel: keybackend.ErrUserVerificationUnavailable,
		Cause:    errors.New("test: phone disconnected"),
	}
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}, err: unavailable}
	auth := newVerifyingAuthenticator(t, backend)
	auth.state.SetUVRetries(1)

	for range 3 {
		reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
		resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

		require.ErrorIs(t, err, keybackend.ErrUserVerificationUnavailable)
		require.NotErrorIs(t, err, ErrUVInvalid)
		require.NotErrorIs(t, err, ErrUVBlocked)
		require.Equal(t, []byte{byte(StatusOtherError)}, resp)
		require.Equal(t, 1, auth.state.UVRetries(), "an outage is not a failed verification")
		require.Nil(t, auth.GetPinUvAuthToken())
	}
	require.Equal(t, 3, backend.calls, "the user is still asked once the outage clears")

	backend.err = errUserNotVerified
	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt, "example.com")
	_, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUVBlocked, "a real refusal still spends the retry")
}

// TestGetPinUvAuthTokenUsingUv_MalformedRequestNeverPrompts pins that the
// checks before the ceremony run first: the user is not asked to verify for a
// request that cannot mint a token.
func TestGetPinUvAuthTokenUsingUv_MalformedRequestNeverPrompts(t *testing.T) {
	tests := []struct {
		name    string
		request map[int]interface{}
		want    error
	}{
		{
			name: "no permissions",
			request: map[int]interface{}{
				clientPINKeyPinUvAuthProtocol: PINProtocol2,
				clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
			},
			want: ErrInvalidParameter,
		},
		{
			name: "no key agreement",
			request: map[int]interface{}{
				clientPINKeyPinUvAuthProtocol: PINProtocol2,
				clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
				clientPINKeyPermissions:       PINPermissionCredentialMgmt,
			},
			want: ErrMissingKeyAgreement,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
			auth := newVerifyingAuthenticator(t, backend)

			reqBytes, err := cbor.Marshal(tt.request)
			require.NoError(t, err)
			_, err = auth.ProcessCBOR(CmdClientPIN, reqBytes)

			require.ErrorIs(t, err, tt.want)
			require.Zero(t, backend.calls)
			require.Nil(t, auth.GetPinUvAuthToken())
		})
	}
}

// TestGetInfo_UserVerifierAdvertisesUvWithToken pins that a key backend with
// a built-in user verification method advertises uv=true beside
// pinUvAuthToken, the CTAP 2.1 promise of
// getPinUvAuthTokenUsingUvWithPermissions (§6.4).
func TestGetInfo_UserVerifierAdvertisesUvWithToken(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
	auth, err := NewAuthenticator(&Config{
		UserPresenceHandler:        NewAutoGrantHandler(),
		Storage:                    NewMemoryStorage(),
		EnablePIN:                  true,
		EnableCredentialManagement: true,
		PINMinLength:               4,
		PINMaxRetries:              8,
		SupportedAlgorithms:        []int{COSEAlgES256},
		KeyBackend:                 backend,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, auth.Close()) })

	options := auth.getOptions()
	require.True(t, options["uv"])
	require.True(t, options["pinUvAuthToken"])
}
