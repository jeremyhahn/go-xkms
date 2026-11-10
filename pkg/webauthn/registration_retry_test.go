package webauthn

import (
	"context"
	"encoding/json"
	"go/token"
	"reflect"
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

// publicPasskey is an account enrolled through public registration, with the
// virtual authenticator credential that holds its passkey.
type publicPasskey struct {
	svc        *Service
	rp         virtualwebauthn.RelyingParty
	credential virtualwebauthn.Credential
	handle     []byte
	account    User
}

func registerPublicPasskey(t *testing.T, email string) *publicPasskey {
	t.Helper()
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

	p := &publicPasskey{
		svc:        svc,
		rp:         virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
		credential: newEC2Credential(t),
	}
	options, sessionID, err := svc.BeginRegistration(ctx, email, email)
	require.NoError(t, err)
	p.handle = registrationHandle(t, options)
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(p.rp, virtualwebauthn.NewAuthenticator(), p.credential, *parsedOptions)
	parsed, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, p.account, err = svc.FinishRegistration(ctx, sessionID, parsed)
	require.NoError(t, err)
	return p
}

// identifiedLogin runs a login that names the account up front, with the
// authenticator presenting userHandle.
func (p *publicPasskey) identifiedLogin(t *testing.T, userHandle []byte) (User, error) {
	t.Helper()
	ctx := context.Background()
	options, sessionID, err := p.svc.BeginLogin(ctx, p.account.WebAuthnID())
	require.NoError(t, err)
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	require.NoError(t, err)
	authenticator := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{UserHandle: userHandle})
	authenticator.AddCredential(p.credential)
	assertion := virtualwebauthn.CreateAssertionResponse(p.rp, authenticator, p.credential, *parsedOptions)
	parsed, err := parseAssertionResponse(assertion)
	require.NoError(t, err)
	_, user, err := p.svc.FinishLogin(ctx, sessionID, p.account.WebAuthnID(), parsed)
	return user, err
}

func TestRegistration_IdentifiedLoginWithTheRegistrationHandle(t *testing.T) {
	p := registerPublicPasskey(t, "identified@example.com")

	user, err := p.identifiedLogin(t, p.handle)
	require.NoError(t, err, "an identified login presenting the registration handle must succeed")
	require.NotNil(t, user)
	assert.Equal(t, p.account.WebAuthnID(), user.WebAuthnID(), "the identity is the account's own ID")
}

func TestRegistration_IdentifiedLoginRejectsAMismatchedHandle(t *testing.T) {
	p := registerPublicPasskey(t, "mismatch@example.com")

	other := make([]byte, len(p.handle))
	copy(other, p.handle)
	other[0] ^= 0xff
	_, err := p.identifiedLogin(t, other)
	require.Error(t, err, "a handle that is neither the account ID nor the credential's registration handle must be refused")
}

// Public registration carries its email and display name through the
// exported SessionStore contract, so a store that cannot carry them fails to
// compile instead of silently refusing every signup.
func TestNewService_SessionStoreWithoutRegistrationMetadata(t *testing.T) {
	contract := reflect.TypeOf((*SessionStore)(nil)).Elem()

	save, ok := contract.MethodByName("SaveRegistration")
	require.True(t, ok, "SessionStore must declare SaveRegistration")
	require.Equal(t, 3, save.Type.NumIn())
	pending := save.Type.In(2)
	require.Equal(t, reflect.Pointer, pending.Kind(), "the registration metadata is passed by pointer")
	require.True(t, pending.Elem().Name() != "" && token.IsExported(pending.Elem().Name()), "the registration metadata is an exported type")

	take, ok := contract.MethodByName("TakeRegistration")
	require.True(t, ok, "SessionStore must declare TakeRegistration")
	require.Equal(t, 3, take.Type.NumOut())
	assert.Equal(t, pending, take.Type.Out(1), "TakeRegistration hands back what SaveRegistration stored")

	// An external store persists the metadata, so it must survive JSON.
	value := reflect.New(pending.Elem())
	for i := 0; i < pending.Elem().NumField(); i++ {
		field := value.Elem().Field(i)
		require.True(t, field.CanSet(), "field %s is exported", pending.Elem().Field(i).Name)
		if field.Kind() == reflect.String {
			field.SetString("v")
		}
	}
	encoded, err := json.Marshal(value.Interface())
	require.NoError(t, err)
	decoded := reflect.New(pending.Elem())
	require.NoError(t, json.Unmarshal(encoded, decoded.Interface()))
	assert.Equal(t, value.Interface(), decoded.Interface())
}
