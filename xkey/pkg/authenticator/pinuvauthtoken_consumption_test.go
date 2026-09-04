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
	"crypto/aes"
	"crypto/cipher"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// These tests cover the part of CTAP 2.1 that scoping and expiry alone do not
// reach: a pinUvAuthToken is spent by the credential operation it authorizes.
// §6.5.5.7 states that "when a pinUvAuthToken is used with an operation that
// tests user presence, it is updated to remove all permissions except lbw",
// which §6.1.2 step 14 implements for makeCredential, and §6.2.2 for
// getAssertion, by calling clearUserVerifiedFlag() and
// clearPinUvAuthTokenPermissionsExceptLbw().
//
// Without this, one PIN entry authorizes an unbounded number of registrations
// and assertions for as long as the usage timers keep being refreshed.
//
// The wire-level helpers below mint tokens through the real ClientPIN CBOR
// ceremony rather than installing a pinProtocolState directly, so the tests
// also cover what a platform actually receives.

const (
	consumptionTestPIN = "1234"
	consumptionRPA     = "a.example"
	consumptionRPB     = "b.example"
)

// newConsumptionAuthenticator builds a PIN-enabled authenticator with the PIN
// set and an auto-granting presence handler.
func newConsumptionAuthenticator(t *testing.T) *Authenticator {
	t.Helper()

	auth := newAuthzTestAuthenticator(t)
	t.Cleanup(func() { _ = auth.Close() })
	require.NoError(t, auth.SetPINForTesting(consumptionTestPIN))
	return auth
}

// mintTokenOverTheWire runs a complete ClientPIN token exchange and returns the
// pinUvAuthToken as the platform sees it, decrypted with the shared secret.
func mintTokenOverTheWire(t *testing.T, auth *Authenticator, req map[int]interface{}) []byte {
	t.Helper()

	require.NoError(t, initKeyAgreement(t, auth))

	auth.mu.Lock()
	platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
	auth.mu.Unlock()
	require.NoError(t, err)

	pinHashEnc, err := encryptPINHash(sharedSecret, consumptionTestPIN)
	require.NoError(t, err)

	req[clientPINKeyPinUvAuthProtocol] = PINProtocol1
	req[clientPINKeyKeyAgreement] = rawCOSEToMap(t, platformCOSE)
	req[clientPINKeyPinHashEnc] = pinHashEnc

	reqBytes, err := cbor.Marshal(req)
	require.NoError(t, err)

	resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
	require.NoError(t, err)
	require.Equal(t, byte(StatusOK), resp[0])

	var decoded map[int]interface{}
	require.NoError(t, cbor.Unmarshal(resp[1:], &decoded))
	encrypted, ok := decoded[clientPINResponseKeyPinUvAuthToken].([]byte)
	require.True(t, ok, "ClientPIN response must carry an encrypted pinUvAuthToken")

	block, err := aes.NewCipher(sharedSecret)
	require.NoError(t, err)
	token := make([]byte, len(encrypted))
	cipher.NewCBCDecrypter(block, make([]byte, AESBlockSize)).CryptBlocks(token, encrypted)
	require.Len(t, token, PINTokenSize)

	return token
}

// mintScopedToken mints a token through getPinUvAuthTokenUsingPinWithPermissions.
func mintScopedToken(t *testing.T, auth *Authenticator, permissions uint8, rpID string) []byte {
	t.Helper()

	req := map[int]interface{}{
		clientPINKeySubCommand:  ClientPINSubCmdGetPinUvAuthTokenUsingPinWithPermissions,
		clientPINKeyPermissions: permissions,
	}
	if rpID != "" {
		req[clientPINKeyPermissionsRPID] = rpID
	}
	return mintTokenOverTheWire(t, auth, req)
}

// mintLegacyToken mints a token through the superseded getPinToken subcommand,
// which grants the default mc and ga permissions with no permissions RP ID.
func mintLegacyToken(t *testing.T, auth *Authenticator) []byte {
	t.Helper()

	return mintTokenOverTheWire(t, auth, map[int]interface{}{
		clientPINKeySubCommand: ClientPINSubCmdGetPINToken,
	})
}

// consumptionClientDataHash returns a distinct hash per label, so a replayed
// pinUvAuthParam cannot accidentally satisfy a later request.
func consumptionClientDataHash(label string) []byte {
	hash := make([]byte, ClientDataHashSize)
	for i := range hash {
		hash[i] = byte(i) ^ label[i%len(label)]
	}
	return hash
}

// registerWithToken performs a makeCredential authorized by token.
func registerWithToken(t *testing.T, auth *Authenticator, rpID, label string, token []byte) error {
	t.Helper()

	clientDataHash := consumptionClientDataHash(label)
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: rpID, Name: rpID},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:           map[string]bool{"rk": true},
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})
	return err
}

// assertWithToken performs a getAssertion authorized by token. When userPresence
// is false the request carries up=false — the silent discovery mode that sets no
// "up" bit and therefore consumes nothing.
func assertWithToken(t *testing.T, auth *Authenticator, rpID, label string, token []byte, userPresence bool) error {
	t.Helper()

	clientDataHash := consumptionClientDataHash(label)
	opts := &GetAssertionOptions{
		PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
		PINUVAuthProtocol: PINProtocol1,
	}
	if !userPresence {
		opts.Options = map[string]bool{"up": false}
	}
	_, err := auth.GetAssertion(clientDataHash, rpID, nil, opts)
	return err
}

// --------------------------------------------------------------------------
// §6.1.2 step 14 / §6.2.2 — the credential operation spends the token
// --------------------------------------------------------------------------

// TestMakeCredentialConsumesTheToken proves a registration spends the token
// that authorized it. Scoping and expiry alone leave the token usable for an
// unbounded number of registrations inside its usage window.
func TestMakeCredentialConsumesTheToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)
	token := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPA)

	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "first", token),
		"positive control: a fresh, correctly scoped token must register")

	require.ErrorIs(t, registerWithToken(t, auth, consumptionRPA, "second", token),
		ErrPINAuthInvalid,
		"the token was spent by the first registration and must not authorize a second")
}

// TestGetAssertionConsumesTheToken proves an assertion that collects user
// presence spends the token that authorized it.
func TestGetAssertionConsumesTheToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	mcToken := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPA)
	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "register", mcToken))

	gaToken := mintScopedToken(t, auth, PINPermissionGetAssertion, consumptionRPA)
	require.NoError(t, assertWithToken(t, auth, consumptionRPA, "first", gaToken, true),
		"positive control: a fresh ga token must produce an assertion")

	require.ErrorIs(t, assertWithToken(t, auth, consumptionRPA, "second", gaToken, true),
		ErrPINAuthInvalid,
		"the token was spent by the first assertion and must not authorize a second")
}

// TestMakeCredentialAndGetAssertionCannotShareOneToken proves that a token
// carrying both mc and ga is still spent by whichever operation uses it first.
func TestMakeCredentialAndGetAssertionCannotShareOneToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)
	token := mintScopedToken(t, auth,
		PINPermissionMakeCredential|PINPermissionGetAssertion, consumptionRPA)

	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "register", token))

	require.ErrorIs(t, assertWithToken(t, auth, consumptionRPA, "assert", token, true),
		ErrPINAuthInvalid,
		"a registration spends the ga permission too — only lbw survives")
}

// TestLegacyPinTokenIsSpentByItsFirstCredentialOperation covers the superseded
// getPinToken subcommand, whose token carries the default mc and ga permissions
// and no permissions RP ID. One PIN entry buys one credential operation.
func TestLegacyPinTokenIsSpentByItsFirstCredentialOperation(t *testing.T) {
	auth := newConsumptionAuthenticator(t)
	token := mintLegacyToken(t, auth)

	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "legacy-first", token),
		"positive control: the default permissions must authorize one registration")

	require.ErrorIs(t, assertWithToken(t, auth, consumptionRPA, "legacy-second", token, true),
		ErrPINAuthInvalid,
		"a getPinToken token must not survive its first credential operation")
}

// TestSilentAssertionDoesNotConsumeTheToken is the counterweight: an assertion
// with up=false sets no "up" bit, so the CTAP 2.1 §6.2.2 clears never run and
// conditional UI can keep discovering credentials with the same token. Without
// this the fix would be indistinguishable from refusing everything after one
// use, and would break silent discovery.
func TestSilentAssertionDoesNotConsumeTheToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	mcToken := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPA)
	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "register", mcToken))

	gaToken := mintScopedToken(t, auth, PINPermissionGetAssertion, consumptionRPA)
	require.NoError(t, assertWithToken(t, auth, consumptionRPA, "silent-1", gaToken, false))
	require.NoError(t, assertWithToken(t, auth, consumptionRPA, "silent-2", gaToken, false),
		"a silent assertion must not spend the token")

	// The same token still authorizes one presence-testing assertion, which
	// then spends it.
	require.NoError(t, assertWithToken(t, auth, consumptionRPA, "loud", gaToken, true))
	require.ErrorIs(t, assertWithToken(t, auth, consumptionRPA, "after-loud", gaToken, false),
		ErrPINAuthInvalid)
}

// TestUnboundLegacyTokenBindsBeforeItIsSpent proves the RP-ID binding of
// §6.1.2 / §6.2.2 still happens for an unscoped token, using silent assertions
// so that binding can be observed separately from consumption.
func TestUnboundLegacyTokenBindsBeforeItIsSpent(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	mcTokenA := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPA)
	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "reg-a", mcTokenA))
	mcTokenB := mintScopedToken(t, auth, PINPermissionMakeCredential, consumptionRPB)
	require.NoError(t, registerWithToken(t, auth, consumptionRPB, "reg-b", mcTokenB))

	token := mintLegacyToken(t, auth)
	require.NoError(t, assertWithToken(t, auth, consumptionRPA, "bind-a", token, false),
		"the first use binds the unscoped token to RP A")
	require.ErrorIs(t, assertWithToken(t, auth, consumptionRPB, "bind-b", token, false),
		ErrPINAuthInvalid,
		"the bound token must not be replayed against RP B")
}

// TestConsumedTokenReportsNotUserVerified proves the non-consuming probe agrees
// with the authorizing call: once the token is spent, credProtect and
// excludeList decisions must stop treating the request as user-verified.
func TestConsumedTokenReportsNotUserVerified(t *testing.T) {
	auth := newConsumptionAuthenticator(t)
	token := mintScopedToken(t, auth,
		PINPermissionMakeCredential|PINPermissionGetAssertion, consumptionRPA)

	clientDataHash := consumptionClientDataHash("probe")
	require.NoError(t, auth.CanAuthorizePinUvAuthToken(clientDataHash,
		pinUvAuthParamFor(token, clientDataHash), PINPermissionGetAssertion, consumptionRPA),
		"positive control: a live token probes as authorized")

	require.NoError(t, registerWithToken(t, auth, consumptionRPA, "spend", token))

	require.ErrorIs(t, auth.CanAuthorizePinUvAuthToken(clientDataHash,
		pinUvAuthParamFor(token, clientDataHash), PINPermissionGetAssertion, consumptionRPA),
		ErrPINAuthInvalid,
		"a spent token must not probe as authorized")
}

// TestConsumePinUvAuthTokenIsNoOpWithoutToken verifies the bookkeeping is safe
// when no token is in use.
func TestConsumePinUvAuthTokenIsNoOpWithoutToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	auth.consumePinUvAuthToken()

	require.NoError(t, initKeyAgreement(t, auth))
	auth.consumePinUvAuthToken()
	require.Nil(t, auth.GetPinUvAuthToken())
}

// --------------------------------------------------------------------------
// §6.5.5.7.1 — getPinToken takes no permissions parameters
// --------------------------------------------------------------------------

// TestGetPinTokenRejectsPermissionParameters proves the superseded subcommand
// refuses the permissions and rpId parameters instead of silently ignoring a
// scope the platform believes it requested.
func TestGetPinTokenRejectsPermissionParameters(t *testing.T) {
	tests := []struct {
		name  string
		extra map[int]interface{}
	}{
		{
			name:  "permissions present",
			extra: map[int]interface{}{clientPINKeyPermissions: PINPermissionAuthenticatorCfg},
		},
		{
			name:  "permissions RP ID present",
			extra: map[int]interface{}{clientPINKeyPermissionsRPID: consumptionRPA},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			auth := newConsumptionAuthenticator(t)
			require.NoError(t, initKeyAgreement(t, auth))

			auth.mu.Lock()
			platformCOSE, sharedSecret, err := auth.generatePlatformKeyAgreement()
			auth.mu.Unlock()
			require.NoError(t, err)

			pinHashEnc, err := encryptPINHash(sharedSecret, consumptionTestPIN)
			require.NoError(t, err)

			req := map[int]interface{}{
				clientPINKeyPinUvAuthProtocol: PINProtocol1,
				clientPINKeySubCommand:        ClientPINSubCmdGetPINToken,
				clientPINKeyKeyAgreement:      rawCOSEToMap(t, platformCOSE),
				clientPINKeyPinHashEnc:        pinHashEnc,
			}
			for k, v := range tc.extra {
				req[k] = v
			}

			reqBytes, err := cbor.Marshal(req)
			require.NoError(t, err)

			resp, err := auth.ProcessCBOR(CmdClientPIN, reqBytes)
			require.ErrorIs(t, err, ErrInvalidParameter)
			require.Equal(t, byte(StatusInvalidParameter), resp[0])
			require.Nil(t, auth.GetPinUvAuthToken(),
				"a malformed getPinToken must not mint a token")
		})
	}
}

// --------------------------------------------------------------------------
// authenticatorConfig permission check must fail closed
// --------------------------------------------------------------------------

// TestConfigPermissionCheckFailsClosed proves the acfg permission check is not
// skipped when no pinUvAuthToken exists. The check used to run only when the
// PIN protocol state was non-nil, so an absent token bypassed it rather than
// being refused by it.
func TestConfigPermissionCheckFailsClosed(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	require.False(t, auth.tokenHasPermission(PINPermissionAuthenticatorCfg),
		"no token means no permissions")

	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionAuthenticatorCfg)
	require.True(t, auth.tokenHasPermission(PINPermissionAuthenticatorCfg),
		"positive control: an acfg-scoped token holds the permission")

	auth.mu.Lock()
	auth.stopUsingPinUvAuthTokenLocked()
	auth.mu.Unlock()
	require.False(t, auth.tokenHasPermission(PINPermissionAuthenticatorCfg),
		"a stopped token holds no permissions")
}

// TestStopUsingPinUvAuthTokenWipesTheToken proves expired or discarded key
// material is zeroed rather than merely dereferenced.
func TestStopUsingPinUvAuthTokenWipesTheToken(t *testing.T) {
	auth := newConsumptionAuthenticator(t)

	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	auth.mu.Lock()
	auth.stopUsingPinUvAuthTokenLocked()
	auth.mu.Unlock()

	require.Equal(t, make([]byte, PINTokenSize), token,
		"the token bytes must be wiped, not just unreferenced")
	require.Nil(t, auth.GetPinUvAuthToken())
}
