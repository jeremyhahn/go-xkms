package xkms

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	waprotocol "github.com/go-webauthn/webauthn/protocol"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newConfiguredWebAuthnService builds a WebAuthn relying-party service backed
// by in-memory stores, suitable for driving a full registration ceremony in a
// unit test without any hardware or browser.
func newConfiguredWebAuthnService(t *testing.T) *webauthn.Service {
	t.Helper()
	svc, _ := newConfiguredWebAuthnServiceAndStores(t)
	return svc
}

// newConfiguredWebAuthnServiceAndStores also returns the stores behind the
// service, for tests that change an account's qrdb record mid-ceremony.
func newConfiguredWebAuthnServiceAndStores(t *testing.T) (*webauthn.Service, *webauthntest.Stores) {
	t.Helper()

	allowRegistration := true
	cfg := &webauthn.Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: &allowRegistration,
	}

	stores := webauthntest.NewStores(t)
	svc, err := webauthn.NewService(webauthn.ServiceParams{
		Config:          cfg,
		UserStore:       stores.Users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err)
	return svc, stores
}

// TestRegistrationCeremony_EndToEnd proves the FIDO2/WebAuthn registration
// ceremony works end-to-end through the XKMSService transport surface using the
// in-repo mock authenticator — no hardware required.
//
// Flow:
//  1. SetWebAuthn wires a real in-memory-backed WebAuthn service onto the XKMSService.
//  2. XKMSService.BeginRegistration returns an opaque session ID + the JSON-marshaled
//     WebAuthn options (CredentialCreation).
//  3. The options JSON is parsed to recover the server challenge.
//  4. The mock authenticator produces a valid attestation for that challenge.
//  5. The attestation's PublicKeyCredential JSON is fed to XKMSService.FinishRegistration
//     together with the session ID.
//  6. The response reports success + the credential ID, and the credential is now
//     persisted (GetCredentials / IsRegistered observe it).
func TestRegistrationCeremony_EndToEnd(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	waSvc := newConfiguredWebAuthnService(t)
	svc.SetWebAuthn(waSvc)

	ctx := context.Background()
	const (
		email       = "ceremony@example.com"
		displayName = "Ceremony User"
		rpID        = "example.com"
		origin      = "https://example.com"
	)

	// Step 1: Begin registration through the XKMSService transport surface.
	beginResp, err := svc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       email,
		DisplayName: displayName,
	})
	require.NoError(t, err)
	require.NotEmpty(t, beginResp.SessionID)
	require.NotEmpty(t, beginResp.OptionsJSON)

	// Step 2: Parse the options JSON to recover the WebAuthn challenge.
	var options waprotocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options))
	require.NotEmpty(t, options.Response.Challenge)

	// The ceremony runs under a random per-registration handle; the account
	// is created at finish (ruling 417(2)).
	handleText, ok := options.Response.User.ID.(string)
	require.True(t, ok)
	handle, err := base64.RawURLEncoding.DecodeString(handleText)
	require.NoError(t, err)

	// Step 4: Drive the mock authenticator to produce a valid attestation for
	// the server-issued challenge.
	mockAuth, err := webauthn.NewMockAuthenticator(rpID)
	require.NoError(t, err)

	attestation, err := mockAuth.CreateAttestationObject(
		options.Response.Challenge,
		handle,
		origin,
	)
	require.NoError(t, err)

	// Step 5: Marshal the raw PublicKeyCredential (the navigator.credentials.create
	// response shape) so FinishRegistration can re-parse it exactly as the browser
	// handler does.
	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)

	finishResp, err := svc.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(attestationJSON),
	})
	require.NoError(t, err)
	assert.True(t, finishResp.Success)
	assert.NotEmpty(t, finishResp.CredentialID)
	assert.NotEmpty(t, finishResp.Token)

	// Step 6: Prove the credential was actually persisted by the ceremony,
	// on the account finish created.
	user, err := waSvc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	creds, err := waSvc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, creds, 1)

	registered, err := waSvc.IsRegistered(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.True(t, registered)
}

// TestBeginRegistrationWithNoDisplayNameAcceptsALongEmail proves a request
// with no display name, for which the email stands in, is not refused by the
// display-name limit when the email is valid and longer than 64 bytes.
func TestBeginRegistrationWithNoDisplayNameAcceptsALongEmail(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetWebAuthn(newConfiguredWebAuthnService(t))

	email := strings.Repeat("a", 100-len("@example.com")) + "@example.com"
	require.Len(t, email, 100)

	beginResp, err := svc.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{
		Email: email,
	})
	require.NoError(t, err)
	require.NotEmpty(t, beginResp.SessionID)
	require.NotEmpty(t, beginResp.OptionsJSON)
}

// registerCredentialForLogin drives the full registration ceremony so a
// credential exists for a subsequent authentication ceremony. It returns the
// mock authenticator (whose CredentialID the assertion will reference) and the
// registered user's WebAuthn ID. It mirrors TestRegistrationCeremony_EndToEnd.
func registerCredentialForLogin(t *testing.T, svc *XKMSService, waSvc *webauthn.Service, email, displayName, rpID, origin string) (*webauthn.MockAuthenticator, []byte) {
	t.Helper()
	ctx := context.Background()

	beginResp, err := svc.BeginRegistration(ctx, &transport.BeginRegistrationRequest{
		Email:       email,
		DisplayName: displayName,
	})
	require.NoError(t, err)

	var options waprotocol.CredentialCreation
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options))

	// The ceremony runs under a random per-registration handle; the account
	// is created at finish (ruling 417(2)).
	handleText, ok := options.Response.User.ID.(string)
	require.True(t, ok)
	handle, err := base64.RawURLEncoding.DecodeString(handleText)
	require.NoError(t, err)

	mockAuth, err := webauthn.NewMockAuthenticator(rpID)
	require.NoError(t, err)

	attestation, err := mockAuth.CreateAttestationObject(
		options.Response.Challenge,
		handle,
		origin,
	)
	require.NoError(t, err)

	attestationJSON, err := json.Marshal(attestation.Raw)
	require.NoError(t, err)

	finishResp, err := svc.FinishRegistration(ctx, &transport.FinishRegistrationRequest{
		SessionID:       beginResp.SessionID,
		AttestationJSON: string(attestationJSON),
	})
	require.NoError(t, err)
	require.True(t, finishResp.Success)

	user, err := waSvc.GetUserByEmail(ctx, email)
	require.NoError(t, err)
	return mockAuth, user.WebAuthnID()
}

// TestAuthenticationCeremony_EndToEnd proves the FIDO2/WebAuthn authentication
// (login) ceremony works end-to-end through the XKMSService transport surface
// using the in-repo mock authenticator — no hardware required. It is symmetric
// to TestRegistrationCeremony_EndToEnd.
//
// Flow:
//  1. SetWebAuthn wires a real in-memory-backed WebAuthn service.
//  2. A credential is registered (reusing the registration ceremony) so the
//     user has something to assert.
//  3. XKMSService.BeginAuthentication resolves the username and returns an
//     opaque session ID + the JSON-marshaled assertion options.
//  4. The options JSON is parsed to recover the login challenge.
//  5. The same mock authenticator produces a valid assertion for that challenge.
//  6. The assertion's PublicKeyCredential JSON is fed to FinishAuthentication
//     together with the session ID, yielding Success + a non-empty token.
func TestAuthenticationCeremony_EndToEnd(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	waSvc := newConfiguredWebAuthnService(t)
	svc.SetWebAuthn(waSvc)

	ctx := context.Background()
	const (
		email       = "login@example.com"
		displayName = "Login User"
		rpID        = "example.com"
		origin      = "https://example.com"
	)

	// Step 1+2: register a credential so the user can authenticate.
	mockAuth, userID := registerCredentialForLogin(t, svc, waSvc, email, displayName, rpID, origin)

	// Step 3: Begin authentication through the XKMSService transport surface.
	beginResp, err := svc.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{
		Email: email,
	})
	require.NoError(t, err)
	require.NotEmpty(t, beginResp.SessionID)
	require.NotEmpty(t, beginResp.OptionsJSON)

	// Step 4: Parse the options JSON to recover the WebAuthn login challenge.
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options))
	require.NotEmpty(t, options.Response.Challenge)

	// Step 5: Drive the same mock authenticator to produce a valid assertion for
	// the server-issued challenge, binding the user handle.
	assertion, err := mockAuth.CreateAssertionResponse(
		options.Response.Challenge,
		userID,
		origin,
	)
	require.NoError(t, err)

	// Marshal the raw PublicKeyCredential (the navigator.credentials.get response
	// shape) so FinishAuthentication can re-parse it exactly as the browser does.
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)

	// Step 6: Finish authentication and assert success + non-empty token.
	finishResp, err := svc.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     beginResp.SessionID,
		Email:         email,
		AssertionJSON: string(assertionJSON),
	})
	require.NoError(t, err)
	assert.True(t, finishResp.Success)
	assert.NotEmpty(t, finishResp.Token)
	assert.Equal(t, email, finishResp.Username)
}

// TestBeginAuthentication_UnknownUser ensures authenticating an unregistered
// email is answered like a registered one — well-formed options and a
// session — so the verb does not reveal whether the account exists
// (go-xkms#1296).
func TestBeginAuthentication_UnknownUser(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetWebAuthn(newConfiguredWebAuthnService(t))

	resp, err := svc.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{
		Email: "nobody@example.com",
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.SessionID)
	assert.Contains(t, resp.OptionsJSON, "allowCredentials")
}

// TestBeginAuthentication_EmptyEmail is a malformed request, refused with a
// wrapped ceremony error.
func TestBeginAuthentication_EmptyEmail(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetWebAuthn(newConfiguredWebAuthnService(t))

	_, err = svc.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	require.Error(t, err)
	var ceremonyErr *ErrWebAuthnCeremony
	assert.True(t, errors.As(err, &ceremonyErr))
}

// TestFinishAuthentication_DecoySessionFailsVerification proves an unknown
// email cannot be told apart at finish either: a real authenticator's
// assertion against the decoy ceremony fails verification, exactly like a
// wrong assertion, instead of failing to "resolve" the email (go-xkms#1296).
func TestFinishAuthentication_DecoySessionFailsVerification(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	waSvc := newConfiguredWebAuthnService(t)
	svc.SetWebAuthn(waSvc)

	ctx := context.Background()
	const origin = "https://example.com"
	mockAuth, userID := registerCredentialForLogin(t, svc, waSvc, "real@example.com", "Real", "example.com", origin)

	beginResp, err := svc.BeginAuthentication(ctx, &transport.BeginAuthenticationRequest{Email: "nobody@example.com"})
	require.NoError(t, err)
	var options waprotocol.CredentialAssertion
	require.NoError(t, json.Unmarshal([]byte(beginResp.OptionsJSON), &options))

	assertion, err := mockAuth.CreateAssertionResponse(options.Response.Challenge, userID, origin)
	require.NoError(t, err)
	assertionJSON, err := json.Marshal(assertion.Raw)
	require.NoError(t, err)

	_, err = svc.FinishAuthentication(ctx, &transport.FinishAuthenticationRequest{
		SessionID:     beginResp.SessionID,
		Email:         "nobody@example.com",
		AssertionJSON: string(assertionJSON),
	})
	require.ErrorIs(t, err, webauthn.ErrVerificationFailed)
}

// TestFinishAuthentication_InvalidAssertion ensures malformed assertion JSON is
// rejected with a wrapped ceremony error rather than a panic or success.
func TestFinishAuthentication_InvalidAssertion(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetWebAuthn(newConfiguredWebAuthnService(t))

	_, err = svc.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{
		SessionID:     "does-not-exist",
		Email:         "someone@example.com",
		AssertionJSON: "{not valid assertion json",
	})
	require.Error(t, err)
	var ceremonyErr *ErrWebAuthnCeremony
	assert.True(t, errors.As(err, &ceremonyErr))
}

// TestFinishRegistration_InvalidAttestation ensures malformed attestation JSON
// is rejected with a wrapped ceremony error rather than a panic or success.
func TestFinishRegistration_InvalidAttestation(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	svc.SetWebAuthn(newConfiguredWebAuthnService(t))

	_, err = svc.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{
		SessionID:       "does-not-exist",
		AttestationJSON: "{not valid attestation json",
	})
	require.Error(t, err)
	var ceremonyErr *ErrWebAuthnCeremony
	assert.True(t, errors.As(err, &ceremonyErr))
}

func TestBeginRegistration_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BeginRegistration(context.Background(), &transport.BeginRegistrationRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestFinishRegistration_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.FinishRegistration(context.Background(), &transport.FinishRegistrationRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestBeginAuthentication_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.BeginAuthentication(context.Background(), &transport.BeginAuthenticationRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestFinishAuthentication_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.FinishAuthentication(context.Background(), &transport.FinishAuthenticationRequest{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}
