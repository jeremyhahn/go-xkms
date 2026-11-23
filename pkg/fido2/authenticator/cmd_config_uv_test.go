package authenticator

import (
	"crypto/hmac"
	"crypto/sha256"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// uvConfigToken mints a pinUvAuthToken through built-in UV with permissions.
func uvConfigToken(t *testing.T, auth *Authenticator, permissions uint8) []byte {
	t.Helper()
	reqBytes, key := uvTokenRequest(t, auth, PINProtocol2, permissions, "")
	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])
	var body map[int][]byte
	require.NoError(t, cbor.Unmarshal(resp[1:], &body))
	token, err := decryptData(key, PINProtocol2, body[clientPINResponseKeyPinUvAuthToken])
	require.NoError(t, err)
	return token
}

// toggleAlwaysUVRequest encodes authenticatorConfig toggleAlwaysUv (0x02).
// A nil token omits pinUvAuthParam.
func toggleAlwaysUVRequest(t *testing.T, token []byte) []byte {
	t.Helper()
	req := map[int]interface{}{configKeySubCommand: AuthConfigCmdToggleAlwaysUv}
	if token != nil {
		msg := make([]byte, 0, 34)
		for i := 0; i < 32; i++ {
			msg = append(msg, 0xFF)
		}
		msg = append(msg, CmdConfig, uint8(AuthConfigCmdToggleAlwaysUv))
		mac := hmac.New(sha256.New, token)
		mac.Write(msg)
		req[configKeyPinUvAuthProtocol] = PINProtocol2
		req[configKeyPinUvAuthParam] = mac.Sum(nil)
	}
	data, err := cbor.Marshal(req)
	require.NoError(t, err)
	return data
}

// With built-in UV configured and no PIN set, authenticatorConfig must still
// demand a pinUvAuthToken carrying the authenticatorConfig permission: the
// phone-backed authenticator mints such tokens without a PIN, so a missing
// PIN is no reason to skip the check.
func TestConfig_BuiltInUVWithoutPINRequiresConfigToken(t *testing.T) {
	newAuth := func(t *testing.T) *Authenticator {
		backend := &verifyingKeyBackend{mockUVKeyBackend: mockUVKeyBackend{handlesUV: true}}
		auth := newVerifyingAuthenticator(t, backend)
		require.False(t, auth.IsPINSet())
		require.NotNil(t, auth.userVerifier())
		return auth
	}

	for name, tc := range map[string]struct {
		token func(t *testing.T, auth *Authenticator) []byte
		want  error
	}{
		"omitted pinUvAuthParam": {
			token: func(*testing.T, *Authenticator) []byte { return nil },
			want:  ErrPINAuthInvalid,
		},
		"invalid pinUvAuthParam": {
			token: func(t *testing.T, auth *Authenticator) []byte {
				uvConfigToken(t, auth, PINPermissionAuthenticatorCfg)
				return make([]byte, 32)
			},
			want: ErrPINAuthInvalid,
		},
		"token without authenticatorConfig permission": {
			token: func(t *testing.T, auth *Authenticator) []byte {
				return uvConfigToken(t, auth, PINPermissionCredentialMgmt)
			},
			want: ErrOperationDenied,
		},
	} {
		t.Run(name, func(t *testing.T) {
			auth := newAuth(t)
			before := auth.config.AlwaysUV
			_, err := auth.ProcessCBOR(CmdConfig, toggleAlwaysUVRequest(t, tc.token(t, auth)))
			require.ErrorIs(t, err, tc.want)
			require.Equal(t, before, auth.config.AlwaysUV, "alwaysUv must not change")
		})
	}

	t.Run("authenticatorConfig token toggles", func(t *testing.T) {
		auth := newAuth(t)
		before := auth.config.AlwaysUV
		token := uvConfigToken(t, auth, PINPermissionAuthenticatorCfg)
		resp, err := auth.ProcessCBOR(CmdConfig, toggleAlwaysUVRequest(t, token))
		require.NoError(t, err)
		require.Equal(t, byte(StatusOK), resp[0])
		require.NotEqual(t, before, auth.config.AlwaysUV)
	})
}
