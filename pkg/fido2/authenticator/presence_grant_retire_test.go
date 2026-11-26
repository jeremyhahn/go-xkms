package authenticator

import (
	"context"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func newGrantRetireAuthenticator(t *testing.T, h *selUPHandler) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		UserPresenceHandler: h,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = auth.Close() })
	require.NoError(t, auth.SetInitialPIN([]byte(consumptionTestPIN)))
	return auth
}

func grantRetireAssertionData(t *testing.T, label string, token []byte) []byte {
	t.Helper()
	clientDataHash := consumptionClientDataHash(label)
	params := map[int]interface{}{
		0x01: consumptionRPA,
		0x02: clientDataHash,
	}
	if token != nil {
		params[0x06] = pinUvAuthParamFor(token, clientDataHash)
		params[0x07] = PINProtocol1
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

func grantRetireMakeCredentialData(t *testing.T, label string, token []byte) []byte {
	t.Helper()
	clientDataHash := consumptionClientDataHash(label)
	params := map[int]interface{}{
		0x01: clientDataHash,
		0x02: map[string]interface{}{"id": consumptionRPA, "name": consumptionRPA},
		0x03: map[string]interface{}{"id": []byte{0x0a, 0x0b}, "name": "grant-user"},
		0x04: []map[string]interface{}{{"type": "public-key", "alg": -7}},
		0x08: pinUvAuthParamFor(token, clientDataHash),
		0x09: PINProtocol1,
	}
	data, err := cbor.Marshal(params)
	require.NoError(t, err)
	return data
}

// A PIN-authorized credential operation that skips the presence check still
// retires the Selection grant, so the next operation on the channel asks again.
func TestSelection_GrantRetiredByPINAuthorizedOperation(t *testing.T) {
	const ch = uint32(0x01000007)

	tests := []struct {
		name  string
		perm  uint8
		first func(t *testing.T, token []byte) (byte, []byte)
	}{
		{"GetAssertion", PINPermissionGetAssertion, func(t *testing.T, token []byte) (byte, []byte) {
			return CmdGetAssertion, grantRetireAssertionData(t, "grant-pin-ga", token)
		}},
		{"MakeCredential", PINPermissionMakeCredential, func(t *testing.T, token []byte) (byte, []byte) {
			return CmdMakeCredential, grantRetireMakeCredentialData(t, "grant-pin-mc", token)
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSelUPHandler()
			h.auto.Store(true)
			auth := newGrantRetireAuthenticator(t, h)
			auth.SetRequireUserPresence(false)

			regToken := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPA)
			require.NoError(t, registerWithToken(t, auth, consumptionRPA, "grant-register", regToken))
			token := mintScopedToken(t, auth, tt.perm, consumptionRPA)

			ctx := WithCTAPHIDChannel(context.Background(), ch)
			base := h.calls.Load()

			resp, err := auth.ProcessCBORWithContext(ctx, CmdSelection, nil)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, base+1, h.calls.Load())

			cmd, data := tt.first(t, token)
			resp, err = auth.ProcessCBORWithContext(ctx, cmd, data)
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, base+1, h.calls.Load(), "the PIN-authorized operation skips presence")

			resp, err = auth.ProcessCBORWithContext(ctx, CmdGetAssertion, grantRetireAssertionData(t, "grant-second", nil))
			require.NoError(t, err)
			require.Equal(t, byte(StatusOK), resp[0])
			require.Equal(t, base+2, h.calls.Load(), "the second GetAssertion must ask for presence again")
		})
	}
}
