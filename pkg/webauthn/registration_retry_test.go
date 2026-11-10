package webauthn

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// registrationHandle returns the WebAuthn user handle a registration
// ceremony hands the authenticator.
func registrationHandle(t *testing.T, options *protocol.CredentialCreation) []byte {
	t.Helper()
	handle, ok := options.Response.User.ID.(protocol.URLEncodedBase64)
	require.True(t, ok, "user handle has type %T", options.Response.User.ID)
	return handle
}

// An abandoned public registration must leave no account behind, so the same
// email can begin again (ruling 417(2)).
func TestBeginRegistration_AbandonedCeremonyDoesNotBlockRetry(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, true)

	_, _, err := svc.BeginRegistration(ctx, "retry@example.com", "Retry")
	require.NoError(t, err)

	_, err = users.GetByEmail(ctx, "retry@example.com")
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err), "begin must not create the account, got %v", err)

	options, sessionID, err := svc.BeginRegistration(ctx, "retry@example.com", "Retry")
	require.NoError(t, err, "a retry after an abandoned ceremony must begin")
	require.NotNil(t, options)
	assert.NotEmpty(t, sessionID)
}

func TestBeginRegistration_HandleIsRandomPerRegistration(t *testing.T) {
	ctx := context.Background()
	svc, _ := newServiceWithPublicRegistration(t, true)

	first, _, err := svc.BeginRegistration(ctx, "first@example.com", "First")
	require.NoError(t, err)
	second, _, err := svc.BeginRegistration(ctx, "second@example.com", "Second")
	require.NoError(t, err)

	firstHandle := registrationHandle(t, first)
	secondHandle := registrationHandle(t, second)
	assert.Len(t, firstHandle, 64)
	assert.Len(t, secondHandle, 64)
	assert.NotEqual(t, firstHandle, secondHandle)
}

func TestRegistration_FinishCreatesTheAccountAndPasskeyLoginResolvesIt(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
		ResidentKeyRequirement:  "preferred",
	}
	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "finish@example.com", "Finish User")
	require.NoError(t, err)
	handle := registrationHandle(t, regOptions)

	regOptionsJSON, err := json.Marshal(regOptions.Response)
	require.NoError(t, err)
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, err := parseAttestationResponse(attestationResponse)
	require.NoError(t, err)
	_, _, err = svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)

	account, err := users.GetByEmail(ctx, "finish@example.com")
	require.NoError(t, err, "finish must create the account")
	assert.NotEqual(t, handle, account.WebAuthnID(), "the account keeps its own ID; the handle is per registration")

	// A passkey login asserts the handle the authenticator was given at
	// registration.
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)
	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)
	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	discoverableAuth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: handle,
	})
	discoverableAuth.AddCredential(credential)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, discoverableAuth, credential, *parsedLoginOptions)
	parsedAssertResponse, err := parseAssertionResponse(assertionResponse)
	require.NoError(t, err)

	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, nil, parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, loggedInUser)
	// The token subject is user.WebAuthnID(): it must be the account's ID.
	assert.Equal(t, account.WebAuthnID(), loggedInUser.WebAuthnID())
	assert.Equal(t, "finish@example.com", loggedInUser.Email())
}
