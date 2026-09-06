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
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// livePinTokenGrant returns a pinProtocolState holding token with the given
// permissions and no permissions RP ID, with the CTAP 2.1 §6.5.2.1 usage timers
// started as a completed clientPIN ceremony would leave them.
func livePinTokenGrant(token []byte, permissions uint8) *pinProtocolState {
	now := time.Now()
	return &pinProtocolState{
		pinUvAuthToken:    token,
		tokenPermissions:  permissions,
		tokenIssuedAt:     now,
		tokenLastUsed:     now,
		tokenUserVerified: true,
	}
}

// authzTestToken is a deterministic 32-byte pinUvAuthToken.
func authzTestToken() []byte {
	token := make([]byte, PINTokenSize)
	for i := range token {
		token[i] = byte(i + 1)
	}
	return token
}

// pinUvAuthParamFor computes the V1 pinUvAuthParam for clientDataHash under token.
func pinUvAuthParamFor(token, clientDataHash []byte) []byte {
	mac := hmac.New(sha256.New, token)
	mac.Write(clientDataHash)
	return mac.Sum(nil)[:PINAuthSizeV1]
}

// newAuthzTestAuthenticator builds an authenticator whose user presence handler
// auto-grants, so that any refusal a test observes comes from the authorization
// path under test and not from a declined gesture.
func newAuthzTestAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		UserPresenceHandler: NewAutoGrantHandler(),
	})
	require.NoError(t, err)
	return auth
}

func authzClientDataHash() []byte {
	hash := make([]byte, ClientDataHashSize)
	for i := range hash {
		hash[i] = byte(0xA0 + i%16)
	}
	return hash
}

func authzPubKeyCredParams() []PublicKeyCredentialParam {
	return []PublicKeyCredentialParam{{Type: "public-key", Alg: COSEAlgES256}}
}

func authzUser() User {
	return User{ID: []byte("user-id"), Name: "user", DisplayName: "User"}
}

// --------------------------------------------------------------------------
// #213 A — permissions and permissions RP ID must be enforced, not just stored
// --------------------------------------------------------------------------

// TestMakeCredentialRefusesTokenWithoutMakeCredentialPermission proves a token
// minted with only the ga permission cannot authorize a registration. Before
// the fix, VerifyPinUvAuthToken checked the HMAC alone and this succeeded.
func TestMakeCredentialRefusesTokenWithoutMakeCredentialPermission(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionGetAssertion)

	clientDataHash := authzClientDataHash()
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token without the mc permission must not authorize makeCredential")
}

// TestGetAssertionRefusesTokenWithoutGetAssertionPermission proves a token
// minted with only the mc permission cannot authorize an assertion.
func TestGetAssertionRefusesTokenWithoutGetAssertionPermission(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()

	// Register a credential the assertion can match, using an mc-permitted token.
	clientDataHash := authzClientDataHash()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:           map[string]bool{"rk": true},
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err)

	// The same token still carries only mc, so getAssertion must refuse it.
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	_, err = auth.GetAssertion(clientDataHash, "example.com", nil,
		&GetAssertionOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token without the ga permission must not authorize getAssertion")
}

// TestMakeCredentialRefusesTokenBoundToAnotherRP proves a token whose
// permissions RP ID names one RP cannot be replayed against a different RP.
func TestMakeCredentialRefusesTokenBoundToAnotherRP(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	auth.pinState.protocol.tokenRPID = "benign.example"

	clientDataHash := authzClientDataHash()
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "victim.example", Name: "Victim"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token scoped to benign.example must not authorize registration at victim.example")
}

// TestGetAssertionRefusesTokenBoundToAnotherRP proves the same for assertions.
func TestGetAssertionRefusesTokenBoundToAnotherRP(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	clientDataHash := authzClientDataHash()

	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "victim.example", Name: "Victim"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:           map[string]bool{"rk": true},
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err)

	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionGetAssertion)
	auth.pinState.protocol.tokenRPID = "benign.example"

	_, err = auth.GetAssertion(clientDataHash, "victim.example", nil,
		&GetAssertionOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token scoped to benign.example must not authorize assertions for victim.example")
}

// TestUnboundTokenBindsToFirstRPThenRefusesOthers proves the CTAP 2.1 §6.1.2
// binding rule: a token minted with no permissions RP ID takes the RP ID of its
// first use, and every later use must present that same RP.
func TestUnboundTokenBindsToFirstRPThenRefusesOthers(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token,
		PINPermissionMakeCredential|PINPermissionGetAssertion)

	clientDataHash := authzClientDataHash()
	param := pinUvAuthParamFor(token, clientDataHash)

	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "first.example", Name: "First"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{PINUVAuthParam: param, PINUVAuthProtocol: PINProtocol1})
	require.NoError(t, err, "first use of an unbound token must succeed")

	auth.mu.RLock()
	bound := auth.pinState.protocol.tokenRPID
	auth.mu.RUnlock()
	require.Equal(t, "first.example", bound, "first use must bind the permissions RP ID")

	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "second.example", Name: "Second"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{PINUVAuthParam: param, PINUVAuthProtocol: PINProtocol1})
	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token bound to first.example must not authorize second.example")
}

// --------------------------------------------------------------------------
// #213 B — the token must expire
// --------------------------------------------------------------------------

// TestPinUvAuthTokenExpiresAfterInactivity proves a token unused for longer than
// the CTAP 2.1 §6.5.2.1 initial usage time limit is refused, and is discarded
// rather than left usable.
func TestPinUvAuthTokenExpiresAfterInactivity(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	// Age the token past the inactivity limit without touching the clock.
	stale := time.Now().Add(-pinUvAuthTokenInactivityLimit - time.Second)
	auth.pinState.protocol.tokenLastUsed = stale

	clientDataHash := authzClientDataHash()
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid, "an inactive token must be refused")

	auth.mu.RLock()
	remaining := auth.pinState.protocol.pinUvAuthToken
	auth.mu.RUnlock()
	require.Nil(t, remaining, "an expired token must be discarded, not left in place")
}

// TestPinUvAuthTokenExpiresAtMaxUsagePeriod proves that continual use cannot
// extend a token past the 10-minute hard cap.
func TestPinUvAuthTokenExpiresAtMaxUsagePeriod(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	// Issued long ago but used a moment ago: only the hard cap can refuse this.
	auth.pinState.protocol.tokenIssuedAt = time.Now().Add(-pinUvAuthTokenMaxUsagePeriod - time.Second)

	clientDataHash := authzClientDataHash()
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token older than the max usage period must be refused however recently it was used")
}

// TestPinUvAuthTokenNotMintedThroughCeremonyIsRefused proves the lifetime check
// fails closed: a token installed without starting the usage timers is unusable
// rather than eternally valid.
func TestPinUvAuthTokenNotMintedThroughCeremonyIsRefused(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = &pinProtocolState{
		pinUvAuthToken:   token,
		tokenPermissions: PINPermissionMakeCredential,
	}

	clientDataHash := authzClientDataHash()
	err := auth.AuthorizePinUvAuthToken(clientDataHash,
		pinUvAuthParamFor(token, clientDataHash), PINPermissionMakeCredential, "example.com")

	require.ErrorIs(t, err, ErrPINAuthInvalid,
		"a token with no issuance time must be treated as expired, not as valid forever")
}

// TestAuthorizePinUvAuthTokenRefusesWrongHMAC keeps the HMAC check honest while
// the permission and RP ID checks are added around it.
func TestAuthorizePinUvAuthTokenRefusesWrongHMAC(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	clientDataHash := authzClientDataHash()
	wrong := pinUvAuthParamFor([]byte("a different token entirely"), clientDataHash)

	err := auth.AuthorizePinUvAuthToken(clientDataHash, wrong, PINPermissionMakeCredential, "example.com")
	require.ErrorIs(t, err, ErrPINAuthInvalid)

	auth.mu.RLock()
	bound := auth.pinState.protocol.tokenRPID
	auth.mu.RUnlock()
	require.Empty(t, bound, "a rejected request must not bind the permissions RP ID")
}

// TestAuthorizePinUvAuthTokenSucceedsForGrantedPermission is the positive case:
// a live token carrying the required permission authorizes the command and the
// inactivity timer is refreshed.
func TestAuthorizePinUvAuthTokenSucceedsForGrantedPermission(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionGetAssertion)
	auth.pinState.protocol.tokenLastUsed = time.Now().Add(-pinUvAuthTokenInactivityLimit / 2)

	clientDataHash := authzClientDataHash()
	require.NoError(t, auth.AuthorizePinUvAuthToken(clientDataHash,
		pinUvAuthParamFor(token, clientDataHash), PINPermissionGetAssertion, "example.com"))

	auth.mu.RLock()
	lastUsed := auth.pinState.protocol.tokenLastUsed
	auth.mu.RUnlock()
	require.WithinDuration(t, time.Now(), lastUsed, time.Second,
		"a successful authorization must refresh the inactivity timer")
}

// TestGetPinTokenGrantsMakeCredentialAndGetAssertion proves the superseded
// getPinToken subcommand leaves a token that is actually usable for the two
// commands CTAP 2.1 §6.5.5.7.1 grants it, and that it does not inherit
// permissions from a previous token.
func TestGetPinTokenGrantsMakeCredentialAndGetAssertion(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	require.NoError(t, auth.SetInitialPIN("1234"))

	// A previous ceremony left a config-scoped token bound to another RP.
	auth.pinState.protocol = livePinTokenGrant(authzTestToken(), PINPermissionAuthenticatorCfg)
	auth.pinState.protocol.tokenRPID = "stale.example"

	token := authzTestToken()
	auth.mu.Lock()
	auth.beginUsingPinUvAuthTokenLocked(token,
		PINPermissionMakeCredential|PINPermissionGetAssertion, "")
	auth.mu.Unlock()

	auth.mu.RLock()
	perms := auth.pinState.protocol.tokenPermissions
	rpID := auth.pinState.protocol.tokenRPID
	auth.mu.RUnlock()

	require.Equal(t, uint8(PINPermissionMakeCredential|PINPermissionGetAssertion), perms)
	require.Empty(t, rpID, "a new token must not inherit the previous token's RP binding")
	require.Zero(t, perms&PINPermissionAuthenticatorCfg,
		"a new token must not inherit the previous token's permissions")
}

// --------------------------------------------------------------------------
// #214 H/G — UP and UV must not be signed without the interaction they assert
// --------------------------------------------------------------------------

// TestGetAssertionInternalPINHashDoesNotSetUV proves the in-process
// InternalPINHash path no longer asserts user verification to the relying
// party. Before the fix it compared the stored PIN hash against a copy of
// itself supplied by an in-process caller and set the UV flag on the result.
func TestGetAssertionInternalPINHashDoesNotSetUV(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	require.NoError(t, auth.SetInitialPIN("1234"))

	clientDataHash := authzClientDataHash()
	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	_, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:           map[string]bool{"rk": true},
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err)

	// The caller reads the expected value straight back out of the
	// authenticator, exactly as the autofill service does.
	resp, err := auth.GetAssertion(clientDataHash, "example.com", nil,
		&GetAssertionOptions{
			Options:         map[string]bool{"up": true, "uv": true},
			InternalPINHash: auth.GetState().PINHash,
		})
	require.NoError(t, err)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.False(t, authData.UserVerified(),
		"UV must not be asserted for a caller that verified no one")
	require.True(t, authData.UserPresent(),
		"the presence gate must still run and its result must be reported")
}

// TestMakeCredentialInternalPINHashDoesNotSetUV proves the same for registration.
func TestMakeCredentialInternalPINHashDoesNotSetUV(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)
	require.NoError(t, auth.SetInitialPIN("1234"))

	clientDataHash := authzClientDataHash()
	resp, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:         map[string]bool{"rk": true, "uv": true},
			InternalPINHash: auth.GetState().PINHash,
		})
	require.NoError(t, err)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	require.False(t, authData.UserVerified(),
		"UV must not be asserted for a caller that verified no one")
}

// TestGoAPIMakeCredentialHonoursRequireUserPresence proves the Go API collects
// the gesture RequireUserPresence demands even when PIN auth already succeeded.
// Before the fix it skipped the gate and set the UP flag anyway.
func TestGoAPIMakeCredentialHonoursRequireUserPresence(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		RequireUserPresence: true,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	clientDataHash := authzClientDataHash()
	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err)

	require.Equal(t, 1, presence.calls(),
		"RequireUserPresence must collect a gesture even when pinUvAuthParam was valid")
}

// TestGoAPIMakeCredentialDoesNotSetUPWhenPresenceDenied proves a denied gesture
// fails the operation rather than producing a credential asserting UP.
func TestGoAPIMakeCredentialDoesNotSetUPWhenPresenceDenied(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: false}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		RequireUserPresence: true,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	token := authzTestToken()
	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)

	clientDataHash := authzClientDataHash()
	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    pinUvAuthParamFor(token, clientDataHash),
			PINUVAuthProtocol: PINProtocol1,
		})

	require.Error(t, err, "a denied presence gesture must fail the registration")
	require.Equal(t, 1, presence.calls())
}

// TestSetUserPresenceHandlerReturnsPrevious proves a service can put back the
// handler it replaced instead of forcing an auto-grant handler on an
// authenticator it shares with other consumers.
func TestSetUserPresenceHandlerReturnsPrevious(t *testing.T) {
	original := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		UserPresenceHandler: original,
	})
	require.NoError(t, err)

	replacement := &countingUserPresenceHandler{approve: true}
	previous := auth.SetUserPresenceHandler(replacement)
	require.Same(t, original, previous, "the replaced handler must be returned")
	require.Same(t, replacement, auth.UserPresenceHandler())

	require.Same(t, replacement, auth.SetUserPresenceHandler(previous))
	require.Same(t, original, auth.UserPresenceHandler(),
		"restoring the previous handler must not leave an auto-grant handler behind")
}

// --------------------------------------------------------------------------
// #217 — the excludeList must not answer before the user presence gate
// --------------------------------------------------------------------------

// TestExcludeListMatchRequiresUserPresence proves that discovering a credential
// through the excludeList costs a user gesture. Before the fix the check ran
// before any gating and returned immediately, letting any process that could
// reach the CTAP interface enumerate credentials silently.
func TestExcludeListMatchRequiresUserPresence(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnableResidentKey:   true,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	clientDataHash := authzClientDataHash()
	resp, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{Options: map[string]bool{"rk": true}})
	require.NoError(t, err)

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)
	registrationCalls := presence.calls()

	// A second registration whose excludeList names the credential just created.
	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			ExcludeList: []CredentialDescriptor{{Type: "public-key", ID: authData.CredentialID}},
		})

	require.ErrorIs(t, err, ErrCredentialExcluded)
	require.Equal(t, registrationCalls+1, presence.calls(),
		"an excludeList match must cost the same gesture as an ordinary registration")
}

// TestExcludeListNonMatchAlsoCostsUserPresence proves the two outcomes are
// indistinguishable by observation: a non-matching excludeList collects exactly
// the same single gesture, so the status code is not a free oracle.
func TestExcludeListNonMatchAlsoCostsUserPresence(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnableResidentKey:   true,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	clientDataHash := authzClientDataHash()
	unknown := make([]byte, 32)
	for i := range unknown {
		unknown[i] = 0xEE
	}

	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:     map[string]bool{"rk": true},
			ExcludeList: []CredentialDescriptor{{Type: "public-key", ID: unknown}},
		})

	require.NoError(t, err)
	require.Equal(t, 1, presence.calls(),
		"a non-matching excludeList must cost exactly the gesture a match costs")
}

// TestExcludeListDeniedPresenceStillReportsExcluded proves the outcome does not
// depend on the user's answer, per CTAP 2.1 §6.1.2: the operation ends in
// CTAP2_ERR_CREDENTIAL_EXCLUDED either way, so declining reveals nothing extra.
func TestExcludeListDeniedPresenceStillReportsExcluded(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnableResidentKey:   true,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	clientDataHash := authzClientDataHash()
	resp, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{Options: map[string]bool{"rk": true}})
	require.NoError(t, err)
	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)

	presence.setApprove(false)

	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			ExcludeList: []CredentialDescriptor{{Type: "public-key", ID: authData.CredentialID}},
		})

	require.ErrorIs(t, err, ErrCredentialExcluded,
		"the excludeList answer must not depend on whether the user approved")
}

// TestExcludeListMatchCostsPresenceEvenWhenPINAuthSkippedTheGate covers the
// case a token holder could otherwise use as a cheap oracle: with valid PIN
// auth and RequireUserPresence off, the ordinary registration path collects no
// gesture at all. An excludeList match must still cost one, so probing the
// device is no quieter than registering with it.
func TestExcludeListMatchCostsPresenceEvenWhenPINAuthSkippedTheGate(t *testing.T) {
	presence := &countingUserPresenceHandler{approve: true}
	auth, err := NewAuthenticator(&Config{
		Storage:             NewMemoryStorage(),
		EnablePIN:           true,
		EnableResidentKey:   true,
		RequireUserPresence: false,
		UserPresenceHandler: presence,
	})
	require.NoError(t, err)

	token := authzTestToken()
	clientDataHash := authzClientDataHash()
	param := pinUvAuthParamFor(token, clientDataHash)

	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	resp, err := auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			Options:           map[string]bool{"rk": true},
			PINUVAuthParam:    param,
			PINUVAuthProtocol: PINProtocol1,
		})
	require.NoError(t, err)
	require.Zero(t, presence.calls(),
		"precondition: valid PIN auth without RequireUserPresence collects no gesture")

	authData, err := ParseAuthData(resp.AuthData)
	require.NoError(t, err)

	auth.pinState.protocol = livePinTokenGrant(token, PINPermissionMakeCredential)
	_, err = auth.MakeCredential(clientDataHash,
		RelyingParty{ID: "example.com", Name: "Example"},
		authzUser(), authzPubKeyCredParams(),
		&MakeCredentialOptions{
			PINUVAuthParam:    param,
			PINUVAuthProtocol: PINProtocol1,
			ExcludeList:       []CredentialDescriptor{{Type: "public-key", ID: authData.CredentialID}},
		})

	require.ErrorIs(t, err, ErrCredentialExcluded)
	require.Equal(t, 1, presence.calls(),
		"an excludeList match must collect a gesture even when the registration path would not")
}

// TestExcludeListHidesCredProtectLevel3WithoutUV proves a level-3 credential
// does not leak through the exclude-list oracle: without user verification the
// authenticator must behave as though it does not hold the credential.
func TestExcludeListHidesCredProtectLevel3WithoutUV(t *testing.T) {
	auth := newAuthzTestAuthenticator(t)

	protected := &StoredCredential{
		CredentialID: []byte("protected-credential-id-32bytes!"),
		RPID:         "example.com",
		UserID:       []byte("user-id"),
		CredProtect:  CredProtectUserVerificationRequired,
	}
	require.NoError(t, auth.storage.Store(protected))

	excludeList := []CredentialDescriptor{{Type: "public-key", ID: protected.CredentialID}}

	require.False(t, auth.excludeListMatches(excludeList, "example.com", false),
		"a credProtect level 3 credential must stay invisible without user verification")
	require.True(t, auth.excludeListMatches(excludeList, "example.com", true),
		"user verification makes the same credential visible to the excludeList")
}

// countingUserPresenceHandler records how many presence gestures were collected
// and answers each one with a configurable verdict.
type countingUserPresenceHandler struct {
	mu      sync.Mutex
	count   int
	approve bool
}

func (h *countingUserPresenceHandler) RequestUserPresence(
	ctx context.Context, req *UserPresenceRequest) (*UserPresenceResult, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.count++
	return &UserPresenceResult{Approved: h.approve}, nil
}

// RequestUserVerification is not exercised by these tests; the authorization
// paths under test collect verification through the clientPIN ceremony.
func (h *countingUserPresenceHandler) RequestUserVerification(
	ctx context.Context, req *UserVerificationRequest) (*UserVerificationResult, error) {
	return nil, ErrUserVerificationDenied
}

func (h *countingUserPresenceHandler) calls() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.count
}

func (h *countingUserPresenceHandler) setApprove(approve bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.approve = approve
}
