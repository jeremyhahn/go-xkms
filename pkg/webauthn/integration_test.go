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

package webauthn

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newEC2Credential returns a virtualwebauthn EC2 credential whose P-256 public
// key has full-length (32-byte) X and Y coordinates. virtualwebauthn encodes
// coordinates with big.Int.Bytes(), which strips leading zero bytes (~1/128 of
// random keys); the go-webauthn COSE parser correctly rejects short coordinates
// per the WebAuthn/COSE spec, so a real authenticator always zero-pads. Regenerating
// until both coordinates are full-length keeps these tests deterministic without
// weakening the (correct) parser.
func newEC2Credential(t *testing.T) virtualwebauthn.Credential {
	t.Helper()
	for i := 0; i < 128; i++ {
		cred := virtualwebauthn.NewCredential(virtualwebauthn.KeyTypeEC2)
		parsed, err := x509.ParsePKCS8PrivateKey(cred.Key.Data)
		if err != nil {
			t.Fatalf("parse EC2 credential key: %v", err)
		}
		priv, ok := parsed.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("expected *ecdsa.PrivateKey, got %T", parsed)
		}
		size := (priv.Curve.Params().BitSize + 7) / 8 // 32 bytes for P-256
		if len(priv.X.Bytes()) == size && len(priv.Y.Bytes()) == size {
			return cred
		}
	}
	t.Fatal("could not generate EC2 credential with full-length coordinates")
	return virtualwebauthn.Credential{}
}

// TestIntegration_FullRegistrationFlow tests the complete WebAuthn registration
// flow using a virtual authenticator.
func TestIntegration_FullRegistrationFlow(t *testing.T) {
	ctx := context.Background()

	// Set up the WebAuthn service
	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}

	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	// Set up virtual authenticator
	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// Step 1: Begin registration
	options, sessionID, err := svc.BeginRegistration(ctx, "testuser@example.com", "Test User")
	require.NoError(t, err)
	require.NotNil(t, options)
	require.NotEmpty(t, sessionID)

	// Verify options structure
	assert.Equal(t, cfg.RPID, options.Response.RelyingParty.ID)
	assert.Equal(t, cfg.RPDisplayName, options.Response.RelyingParty.Name)
	assert.Equal(t, "testuser@example.com", options.Response.User.Name)
	assert.Equal(t, "Test User", options.Response.User.DisplayName)
	assert.NotEmpty(t, options.Response.Challenge)

	// Step 2: Create attestation response using virtual authenticator
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)

	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedOptions)

	// Step 3: Parse the attestation response (simulating what the browser sends)
	parsedResponse, err := parseAttestationResponse(attestationResponse)
	require.NoError(t, err)

	// Step 4: Finish registration
	token, user, err := svc.FinishRegistration(ctx, sessionID, parsedResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, user)

	// Add credential to virtual authenticator for future logins
	authenticator.AddCredential(credential)

	// Verify user was created correctly
	assert.Equal(t, "testuser@example.com", user.Email())
	assert.Equal(t, "Test User", user.DisplayName())

	// Verify credential was stored
	stored, err := svc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, stored, 1)

	// Verify user is now registered
	registered, err := svc.IsRegistered(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.True(t, registered)
}

// TestIntegration_FullLoginFlow tests the complete WebAuthn login flow
// using a virtual authenticator after registration.
func TestIntegration_FullLoginFlow(t *testing.T) {
	ctx := context.Background()

	// Set up the WebAuthn service
	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}

	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	// Set up virtual authenticator
	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// === REGISTRATION PHASE ===

	// Begin registration
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "logintest@example.com", "Login Test User")
	require.NoError(t, err)

	// Create attestation response
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	require.NoError(t, err)

	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)

	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)

	parsedAttResponse, err := parseAttestationResponse(attestationResponse)
	require.NoError(t, err)

	// Finish registration
	_, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)

	// Add credential to authenticator
	authenticator.AddCredential(credential)

	// === LOGIN PHASE ===

	// Step 1: Begin login
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.NotNil(t, loginOptions)
	require.NotEmpty(t, loginSessionID)

	// Verify login options
	assert.NotEmpty(t, loginOptions.Response.Challenge)
	assert.Equal(t, cfg.RPID, loginOptions.Response.RelyingPartyID)

	// Step 2: Create assertion response using virtual authenticator
	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)

	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedLoginOptions)

	// Step 3: Parse the assertion response
	parsedAssertResponse, err := parseAssertionResponse(assertionResponse)
	require.NoError(t, err)

	// Step 4: Finish login
	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, loggedInUser)

	// Verify logged in user matches
	assert.Equal(t, user.WebAuthnID(), loggedInUser.WebAuthnID())
	assert.Equal(t, "logintest@example.com", loggedInUser.Email())
}

// TestIntegration_DiscoverableCredentialFlow tests passkey/discoverable credential flow.
func TestIntegration_DiscoverableCredentialFlow(t *testing.T) {
	ctx := context.Background()

	// Set up the WebAuthn service with resident key requirement
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

	// Set up virtual authenticator with resident key support
	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// === REGISTRATION ===
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "passkey@example.com", "Passkey User")
	require.NoError(t, err)

	regOptionsJSON, _ := json.Marshal(regOptions.Response)
	parsedRegOptions, _ := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, _ := parseAttestationResponse(attestationResponse)

	_, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)

	authenticator.AddCredential(credential)

	// === DISCOVERABLE LOGIN (no user ID provided) ===

	// Begin discoverable login
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)
	require.NotNil(t, loginOptions)

	// For discoverable login, allowCredentials should be empty
	assert.Empty(t, loginOptions.Response.AllowedCredentials)

	// Create assertion response with user handle for discoverable credentials
	loginOptionsJSON, _ := json.Marshal(loginOptions.Response)
	parsedLoginOptions, _ := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))

	// Create authenticator with user handle for discoverable credential flow
	discoverableAuth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: user.WebAuthnID(),
	})
	discoverableAuth.AddCredential(credential)

	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, discoverableAuth, credential, *parsedLoginOptions)
	parsedAssertResponse, _ := parseAssertionResponse(assertionResponse)

	// Finish discoverable login (no user ID)
	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, nil, parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, loggedInUser)

	assert.Equal(t, "passkey@example.com", loggedInUser.Email())
}

// TestIntegration_MultipleCredentials tests registering multiple credentials for a user.
func TestIntegration_MultipleCredentials(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
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

	// Create two authenticators (simulating different security keys)
	authenticator1 := virtualwebauthn.NewAuthenticator()
	credential1 := newEC2Credential(t)

	authenticator2 := virtualwebauthn.NewAuthenticator()
	credential2 := newEC2Credential(t)

	// Register first credential
	regOptions1, regSessionID1, err := svc.BeginRegistration(ctx, "multicred@example.com", "Multi Cred User")
	require.NoError(t, err)

	regOptionsJSON1, _ := json.Marshal(regOptions1.Response)
	parsedRegOptions1, _ := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON1))
	attestationResponse1 := virtualwebauthn.CreateAttestationResponse(rp, authenticator1, credential1, *parsedRegOptions1)
	parsedAttResponse1, _ := parseAttestationResponse(attestationResponse1)

	_, user, err := svc.FinishRegistration(ctx, regSessionID1, parsedAttResponse1)
	require.NoError(t, err)
	authenticator1.AddCredential(credential1)

	// A second credential cannot be added through the public ceremony
	// (go-xkms#1294); it takes a session authenticated as the account.
	_, _, err = svc.BeginRegistration(ctx, "multicred@example.com", "Multi Cred User")
	require.ErrorIs(t, err, ErrRegistrationRefused)

	regOptions2, regSessionID2, err := svc.BeginAddCredential(ctx, SessionAccount{
		UserID:   user.WebAuthnID(),
		Email:    "multicred@example.com",
		TenantID: "system",
	})
	require.NoError(t, err)

	// Verify exclude list contains first credential
	assert.Len(t, regOptions2.Response.CredentialExcludeList, 1)

	regOptionsJSON2, _ := json.Marshal(regOptions2.Response)
	parsedRegOptions2, _ := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON2))
	attestationResponse2 := virtualwebauthn.CreateAttestationResponse(rp, authenticator2, credential2, *parsedRegOptions2)
	parsedAttResponse2, _ := parseAttestationResponse(attestationResponse2)

	_, _, err = svc.FinishRegistration(ctx, regSessionID2, parsedAttResponse2)
	require.NoError(t, err)
	authenticator2.AddCredential(credential2)

	// Verify user has two credentials
	stored, err := svc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, stored, 2)

	// Login with first authenticator
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)

	loginOptionsJSON, _ := json.Marshal(loginOptions.Response)
	parsedLoginOptions, _ := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator1, credential1, *parsedLoginOptions)
	parsedAssertResponse, _ := parseAssertionResponse(assertionResponse)

	token, _, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)

	// Login with second authenticator
	loginOptions2, loginSessionID2, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)

	loginOptionsJSON2, _ := json.Marshal(loginOptions2.Response)
	parsedLoginOptions2, _ := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON2))
	assertionResponse2 := virtualwebauthn.CreateAssertionResponse(rp, authenticator2, credential2, *parsedLoginOptions2)
	parsedAssertResponse2, _ := parseAssertionResponse(assertionResponse2)

	token2, _, err := svc.FinishLogin(ctx, loginSessionID2, user.WebAuthnID(), parsedAssertResponse2)
	require.NoError(t, err)
	require.NotEmpty(t, token2)
}

// TestIntegration_SignCountValidation tests that sign count is properly updated.
// The virtualwebauthn library increments the counter automatically on each assertion.
func TestIntegration_SignCountValidation(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
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

	// Register
	regOptions, regSessionID, _ := svc.BeginRegistration(ctx, "signcount@example.com", "Sign Count User")
	regOptionsJSON, _ := json.Marshal(regOptions.Response)
	parsedRegOptions, _ := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, _ := parseAttestationResponse(attestationResponse)

	_, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)
	authenticator.AddCredential(credential)

	// Get initial sign count (should be 0 after registration)
	stored, _ := svc.GetCredentials(ctx, user.WebAuthnID())
	initialSignCount := stored[0].Authenticator.SignCount
	assert.Equal(t, uint32(0), initialSignCount, "Initial sign count should be 0")

	// Login multiple times - the virtual authenticator increments Counter on each CreateAssertionResponse
	numLogins := 3
	for i := 0; i < numLogins; i++ {
		// Manually increment the credential counter to simulate real authenticator behavior
		credential.Counter++

		loginOptions, loginSessionID, _ := svc.BeginLogin(ctx, user.WebAuthnID())
		loginOptionsJSON, _ := json.Marshal(loginOptions.Response)
		parsedLoginOptions, _ := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
		assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedLoginOptions)
		parsedAssertResponse, _ := parseAssertionResponse(assertionResponse)

		_, _, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
		require.NoError(t, err)
	}

	// Verify sign count increased to match our logins
	stored, _ = svc.GetCredentials(ctx, user.WebAuthnID())
	finalSignCount := stored[0].Authenticator.SignCount
	assert.Equal(t, uint32(numLogins), finalSignCount, "Sign count should match number of logins")
}

// TestIntegration_WithJWTGenerator tests registration and login with a custom JWT generator.
func TestIntegration_WithJWTGenerator(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}

	// Custom JWT generator
	jwtGen := &testJWTGenerator{prefix: "test-jwt-"}

	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
		JWTGenerator:    jwtGen,
	})
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}

	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// Register
	regOptions, regSessionID, _ := svc.BeginRegistration(ctx, "jwt@example.com", "JWT User")
	regOptionsJSON, _ := json.Marshal(regOptions.Response)
	parsedRegOptions, _ := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, _ := parseAttestationResponse(attestationResponse)

	token, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)
	assert.True(t, len(token) > len("test-jwt-"))
	assert.Contains(t, token, "test-jwt-")

	authenticator.AddCredential(credential)

	// Login
	loginOptions, loginSessionID, _ := svc.BeginLogin(ctx, user.WebAuthnID())
	loginOptionsJSON, _ := json.Marshal(loginOptions.Response)
	parsedLoginOptions, _ := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedLoginOptions)
	parsedAssertResponse, _ := parseAssertionResponse(assertionResponse)

	loginToken, _, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
	require.NoError(t, err)
	assert.Contains(t, loginToken, "test-jwt-")
}

// testJWTGenerator is a mock JWT generator for testing.
type testJWTGenerator struct {
	prefix string
}

func (g *testJWTGenerator) GenerateToken(ctx context.Context, user User) (string, error) {
	return g.prefix + string(user.WebAuthnID()), nil
}

// TestIntegration_UserIdentifiedLogin_PopulatesAllowCredentials is the
// authoritative regression for the email-first (non-discoverable) login
// ceremony. When BeginLogin is called with a known user's WebAuthn handle the
// returned assertion MUST enumerate that user's registered credential(s) in
// allowCredentials. An empty allowCredentials list is the discoverable-ceremony
// signature that triggers the browser's native passkey account-picker — wrong
// for an email-identified login (see the quicbaas XKMSWebAuthnManager bug where
// BeginLogin was dispatched with a nil user handle). The test also drives the
// assertion through FinishLogin with the same handle to prove the user-identified
// begin→finish pair completes, and asserts the unknown-user begin fails closed.
func TestIntegration_UserIdentifiedLogin_PopulatesAllowCredentials(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
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

	// Register a credential for the user.
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "picker@example.com", "Picker User")
	require.NoError(t, err)
	regOptionsJSON, err := json.Marshal(regOptions.Response)
	require.NoError(t, err)
	parsedRegOptions, err := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
	require.NoError(t, err)
	attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
	parsedAttResponse, err := parseAttestationResponse(attestationResponse)
	require.NoError(t, err)
	_, user, err := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
	require.NoError(t, err)
	authenticator.AddCredential(credential)

	// Resolve the registered credential id the begin response MUST advertise.
	storedCreds, err := svc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.Len(t, storedCreds, 1)
	wantCredID := base64.RawURLEncoding.EncodeToString(storedCreds[0].ID)

	// User-identified begin: allowCredentials MUST be non-empty and list the
	// registered credential. This is the picker-bug guard.
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)
	require.NotEmpty(t, loginOptions.Response.AllowedCredentials,
		"user-identified BeginLogin must populate allowCredentials; an empty list triggers the native passkey picker")

	gotIDs := make([]string, 0, len(loginOptions.Response.AllowedCredentials))
	for _, desc := range loginOptions.Response.AllowedCredentials {
		gotIDs = append(gotIDs, base64.RawURLEncoding.EncodeToString(desc.CredentialID))
	}
	assert.Contains(t, gotIDs, wantCredID,
		"allowCredentials must contain the user's registered credential id")

	// The user-identified begin→finish pair completes against the SAME handle.
	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)
	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticator, credential, *parsedLoginOptions)
	parsedAssertResponse, err := parseAssertionResponse(assertionResponse)
	require.NoError(t, err)
	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	assert.Equal(t, user.WebAuthnID(), loggedInUser.WebAuthnID())

	// Unknown user handle fails closed before emitting a ceremony.
	_, _, err = svc.BeginLogin(ctx, []byte("no-such-user-handle"))
	require.Error(t, err, "BeginLogin for an unknown user must fail closed")
}

// parseAttestationResponse parses a virtual authenticator attestation response
// into the format expected by go-webauthn.
func parseAttestationResponse(attestation string) (*protocol.ParsedCredentialCreationData, error) {
	var ccr protocol.CredentialCreationResponse
	if err := json.Unmarshal([]byte(attestation), &ccr); err != nil {
		return nil, err
	}
	return ccr.Parse()
}

// parseAssertionResponse parses a virtual authenticator assertion response
// into the format expected by go-webauthn.
func parseAssertionResponse(assertion string) (*protocol.ParsedCredentialAssertionData, error) {
	var car protocol.CredentialAssertionResponse
	if err := json.Unmarshal([]byte(assertion), &car); err != nil {
		return nil, err
	}
	return car.Parse()
}
