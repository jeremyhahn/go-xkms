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
// method (keybackend.UserVerifier, ruling 167). It records each call and
// answers with err.
type verifyingKeyBackend struct {
	mockUVKeyBackend
	err   error
	calls int
}

var _ keybackend.UserVerifier = (*verifyingKeyBackend)(nil)

func (b *verifyingKeyBackend) VerifyUser(context.Context) error {
	b.calls++
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
// under protocol and returns it with the key the token comes back under.
func uvTokenRequest(t *testing.T, auth *Authenticator, protocol uint8, permissions uint8) ([]byte, []byte) {
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

	reqBytes, err := cbor.Marshal(map[int]interface{}{
		clientPINKeyPinUvAuthProtocol: protocol,
		clientPINKeySubCommand:        ClientPINSubCmdGetPinUvAuthTokenUsingUvWithPermissions,
		clientPINKeyKeyAgreement:      platformCOSEMap,
		clientPINKeyPermissions:       permissions,
		clientPINKeyPermissionsRPID:   "example.com",
	})
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

			reqBytes, key := uvTokenRequest(t, auth, protocol, PINPermissionCredentialMgmt)
			resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, 1, backend.calls)

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

// TestGetPinUvAuthTokenUsingUv_VerifierRefusalBlocksMinting pins that a
// refused verification mints nothing, answers CTAP2_ERR_UV_INVALID, spends a
// retry, and leaves an outstanding token as it was.
func TestGetPinUvAuthTokenUsingUv_VerifierRefusalBlocksMinting(t *testing.T) {
	backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}, err: errUserNotVerified}
	auth := newVerifyingAuthenticator(t, backend)
	want := append([]byte(nil), installOutstandingToken(t, auth)...)

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt)
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

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt)
	_, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.ErrorIs(t, err, ErrUVBlocked)

	backend.err = nil
	reqBytes, _ = uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt)
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

	reqBytes, _ := uvTokenRequest(t, auth, PINProtocol2, PINPermissionCredentialMgmt)
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)

	require.ErrorIs(t, err, context.Canceled)
	require.Equal(t, []byte{byte(StatusKeepaliveCancel)}, resp)
	require.Equal(t, DefaultUVRetries, auth.state.UVRetries())
	require.Nil(t, auth.GetPinUvAuthToken())
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
