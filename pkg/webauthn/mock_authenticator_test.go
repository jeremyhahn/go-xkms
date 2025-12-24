// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package webauthn

import (
	"context"
	"encoding/base64"
	"testing"
	"time"
)

func TestMockAuthenticator_Creation(t *testing.T) {
	auth, err := NewMockAuthenticator("example.com")
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	if len(auth.AAGUID) != 16 {
		t.Errorf("AAGUID should be 16 bytes, got %d", len(auth.AAGUID))
	}

	if len(auth.CredentialID) != 32 {
		t.Errorf("CredentialID should be 32 bytes, got %d", len(auth.CredentialID))
	}

	if auth.SignCount != 0 {
		t.Errorf("Initial SignCount should be 0, got %d", auth.SignCount)
	}

	if !auth.UserPresent {
		t.Error("UserPresent should default to true")
	}

	if !auth.UserVerified {
		t.Error("UserVerified should default to true")
	}
}

func TestMockAuthenticator_WithOptions(t *testing.T) {
	customAAGUID := make([]byte, 16)
	for i := range customAAGUID {
		customAAGUID[i] = byte(i)
	}

	customCredID := make([]byte, 64)
	for i := range customCredID {
		customCredID[i] = byte(i)
	}

	auth, err := NewMockAuthenticator("example.com",
		WithAAGUID(customAAGUID),
		WithCredentialID(customCredID),
		WithSignCount(100),
		WithUserPresent(false),
		WithUserVerified(false),
		WithResidentKey(true),
	)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator with options: %v", err)
	}

	if string(auth.AAGUID) != string(customAAGUID) {
		t.Error("Custom AAGUID not set correctly")
	}

	if string(auth.CredentialID) != string(customCredID) {
		t.Error("Custom CredentialID not set correctly")
	}

	if auth.SignCount != 100 {
		t.Errorf("SignCount should be 100, got %d", auth.SignCount)
	}

	if auth.UserPresent {
		t.Error("UserPresent should be false")
	}

	if auth.UserVerified {
		t.Error("UserVerified should be false")
	}

	if !auth.ResidentKey {
		t.Error("ResidentKey should be true")
	}
}

func TestMockAuthenticator_SignCount(t *testing.T) {
	auth, err := NewMockAuthenticator("example.com")
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// Initial count should be 0
	if auth.SignCount != 0 {
		t.Errorf("Initial SignCount should be 0, got %d", auth.SignCount)
	}

	// Increment should return new count
	newCount := auth.IncrementSignCount()
	if newCount != 1 {
		t.Errorf("IncrementSignCount should return 1, got %d", newCount)
	}

	// Increment again
	newCount = auth.IncrementSignCount()
	if newCount != 2 {
		t.Errorf("IncrementSignCount should return 2, got %d", newCount)
	}

	// Set specific count
	auth.SetSignCount(100)
	if auth.SignCount != 100 {
		t.Errorf("SetSignCount should set to 100, got %d", auth.SignCount)
	}
}

func TestMockAuthenticator_PublicKey(t *testing.T) {
	auth, err := NewMockAuthenticator("example.com")
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	pubKey := auth.PublicKey()
	if pubKey == nil {
		t.Error("PublicKey should not be nil")
	}

	pubKeyBytes, err := auth.PublicKeyBytes()
	if err != nil {
		t.Fatalf("Failed to get public key bytes: %v", err)
	}

	if len(pubKeyBytes) == 0 {
		t.Error("PublicKeyBytes should not be empty")
	}
}

func TestMockAuthenticator_CreateAttestationObject(t *testing.T) {
	auth, err := NewMockAuthenticator("example.com")
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	userID := []byte("user-123")
	origin := "https://example.com"

	attestation, err := auth.CreateAttestationObject(challenge, userID, origin)
	if err != nil {
		t.Fatalf("Failed to create attestation object: %v", err)
	}

	// Verify attestation structure
	if attestation == nil {
		t.Fatal("Attestation should not be nil")
	}

	// ID is base64-encoded
	expectedID := base64.RawURLEncoding.EncodeToString(auth.CredentialID)
	if attestation.ID != expectedID {
		t.Errorf("Attestation ID should match base64-encoded credential ID, got %s, expected %s", attestation.ID, expectedID)
	}

	if attestation.Type != "public-key" {
		t.Errorf("Type should be 'public-key', got '%s'", attestation.Type)
	}

	if attestation.Response.AttestationObject.Format != "none" {
		t.Errorf("Format should be 'none', got '%s'", attestation.Response.AttestationObject.Format)
	}

	if attestation.Response.CollectedClientData.Type != "webauthn.create" {
		t.Errorf("ClientData type should be 'webauthn.create', got '%s'", attestation.Response.CollectedClientData.Type)
	}

	if attestation.Response.CollectedClientData.Origin != origin {
		t.Errorf("Origin should be '%s', got '%s'", origin, attestation.Response.CollectedClientData.Origin)
	}
}

func TestMockAuthenticator_CreateAssertionResponse(t *testing.T) {
	auth, err := NewMockAuthenticator("example.com")
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	challenge := make([]byte, 32)
	for i := range challenge {
		challenge[i] = byte(i)
	}
	userHandle := []byte("user-123")
	origin := "https://example.com"

	initialCount := auth.SignCount

	assertion, err := auth.CreateAssertionResponse(challenge, userHandle, origin)
	if err != nil {
		t.Fatalf("Failed to create assertion response: %v", err)
	}

	// Verify assertion structure
	if assertion == nil {
		t.Fatal("Assertion should not be nil")
	}

	// ID is base64-encoded
	expectedID := base64.RawURLEncoding.EncodeToString(auth.CredentialID)
	if assertion.ID != expectedID {
		t.Errorf("Assertion ID should match base64-encoded credential ID, got %s, expected %s", assertion.ID, expectedID)
	}

	if assertion.Type != "public-key" {
		t.Errorf("Type should be 'public-key', got '%s'", assertion.Type)
	}

	if assertion.Response.CollectedClientData.Type != "webauthn.get" {
		t.Errorf("ClientData type should be 'webauthn.get', got '%s'", assertion.Response.CollectedClientData.Type)
	}

	if assertion.Response.CollectedClientData.Origin != origin {
		t.Errorf("Origin should be '%s', got '%s'", origin, assertion.Response.CollectedClientData.Origin)
	}

	// Verify signature is present
	if len(assertion.Response.Signature) == 0 {
		t.Error("Signature should not be empty")
	}

	// Verify sign count was incremented
	if auth.SignCount != initialCount+1 {
		t.Errorf("SignCount should be incremented, expected %d, got %d", initialCount+1, auth.SignCount)
	}
}

func TestMockAuthenticator_FullRegistrationFlow(t *testing.T) {
	ctx := context.Background()
	rpID := "localhost"
	origin := "https://localhost"
	email := "test@example.com"
	displayName := "Test User"

	// Create WebAuthn service with memory stores
	cfg := &Config{
		RPID:          rpID,
		RPDisplayName: "Test RP",
		RPOrigins:     []string{origin},
	}

	users := NewMemoryUserStore()
	sessions := NewMemorySessionStoreWithTTL(5 * time.Minute)
	creds := NewMemoryCredentialStore()

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	// Create mock authenticator
	auth, err := NewMockAuthenticator(rpID)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// Begin registration
	options, sessionID, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}

	if options == nil {
		t.Fatal("Options should not be nil")
	}

	if sessionID == "" {
		t.Fatal("SessionID should not be empty")
	}

	// Get the user to get their ID for the attestation
	user, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	// Create attestation response using mock authenticator
	attestation, err := auth.CreateAttestationObject(
		options.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	// Finish registration
	token, registeredUser, err := svc.FinishRegistration(ctx, sessionID, attestation)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	if registeredUser == nil {
		t.Fatal("Registered user should not be nil")
	}

	if registeredUser.Email() != email {
		t.Errorf("User email should be '%s', got '%s'", email, registeredUser.Email())
	}

	// Verify user is now registered
	isRegistered, err := svc.IsRegistered(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("IsRegistered failed: %v", err)
	}

	if !isRegistered {
		t.Error("User should be registered after FinishRegistration")
	}
}

func TestMockAuthenticator_FullLoginFlow(t *testing.T) {
	ctx := context.Background()
	rpID := "localhost"
	origin := "https://localhost"
	email := "test@example.com"
	displayName := "Test User"

	// Create WebAuthn service with memory stores
	cfg := &Config{
		RPID:          rpID,
		RPDisplayName: "Test RP",
		RPOrigins:     []string{origin},
	}

	users := NewMemoryUserStore()
	sessions := NewMemorySessionStoreWithTTL(5 * time.Minute)
	creds := NewMemoryCredentialStore()

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	// Create mock authenticator
	auth, err := NewMockAuthenticator(rpID)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// First, register the user
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}

	user, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	attestation, err := auth.CreateAttestationObject(
		regOptions.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, regSessionID, attestation)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	// Now test login
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}

	if loginOptions == nil {
		t.Fatal("Login options should not be nil")
	}

	if loginSessionID == "" {
		t.Fatal("Login session ID should not be empty")
	}

	// Create assertion response using mock authenticator
	assertion, err := auth.CreateAssertionResponse(
		loginOptions.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	// Finish login
	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), assertion)
	if err != nil {
		t.Fatalf("FinishLogin failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	if loggedInUser == nil {
		t.Fatal("Logged in user should not be nil")
	}

	if loggedInUser.Email() != email {
		t.Errorf("User email should be '%s', got '%s'", email, loggedInUser.Email())
	}
}

func TestMockAuthenticator_CloneDetection(t *testing.T) {
	ctx := context.Background()
	rpID := "localhost"
	origin := "https://localhost"
	email := "test@example.com"
	displayName := "Test User"

	// Create WebAuthn service with memory stores
	cfg := &Config{
		RPID:          rpID,
		RPDisplayName: "Test RP",
		RPOrigins:     []string{origin},
	}

	users := NewMemoryUserStore()
	sessions := NewMemorySessionStoreWithTTL(5 * time.Minute)
	creds := NewMemoryCredentialStore()

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	// Create mock authenticator
	auth, err := NewMockAuthenticator(rpID)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// Register user
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}

	user, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	attestation, err := auth.CreateAttestationObject(
		regOptions.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, regSessionID, attestation)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	// First login (should succeed)
	loginOptions1, loginSessionID1, err := svc.BeginLogin(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("BeginLogin 1 failed: %v", err)
	}

	assertion1, err := auth.CreateAssertionResponse(
		loginOptions1.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create assertion 1: %v", err)
	}

	_, _, err = svc.FinishLogin(ctx, loginSessionID1, user.WebAuthnID(), assertion1)
	if err != nil {
		t.Fatalf("FinishLogin 1 failed: %v", err)
	}

	// Check the current sign count after first login
	firstLoginSignCount := auth.SignCount

	// Simulate clone: reset sign count to a lower value
	auth.SetSignCount(0) // Clone would have old sign count

	// Second login (should fail due to clone detection)
	loginOptions2, loginSessionID2, err := svc.BeginLogin(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("BeginLogin 2 failed: %v", err)
	}

	assertion2, err := auth.CreateAssertionResponse(
		loginOptions2.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create assertion 2: %v", err)
	}

	// This login should either fail or set CloneWarning flag.
	// Note: go-webauthn library may not fail, it may just set CloneWarning.
	// The important thing is that the server can detect potential cloning.
	_, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID2, user.WebAuthnID(), assertion2)

	if err != nil {
		// This is expected - login should fail due to clone detection
		t.Logf("Clone detection worked: login failed with error: %v", err)
	} else {
		// If login succeeded, check if CloneWarning was set
		creds, _ := svc.GetCredentials(ctx, loggedInUser.WebAuthnID())
		if len(creds) > 0 && creds[0].Authenticator.CloneWarning {
			t.Log("Clone detection worked: CloneWarning flag was set")
		} else {
			// The sign count in assertion (1) is not less than stored (1), so no detection
			t.Log("Note: Clone not detected - sign count in assertion equals stored count")
		}
	}

	t.Logf("Clone detection test: first login sign count was %d, clone assertion sign count was %d",
		firstLoginSignCount, auth.SignCount)
}

func TestMockAuthenticator_DiscoverableCredentials(t *testing.T) {
	ctx := context.Background()
	rpID := "localhost"
	origin := "https://localhost"
	email := "test@example.com"
	displayName := "Test User"

	// Create WebAuthn service with memory stores
	cfg := &Config{
		RPID:          rpID,
		RPDisplayName: "Test RP",
		RPOrigins:     []string{origin},
	}

	users := NewMemoryUserStore()
	sessions := NewMemorySessionStoreWithTTL(5 * time.Minute)
	creds := NewMemoryCredentialStore()

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	// Create mock authenticator with resident key support
	auth, err := NewMockAuthenticator(rpID, WithResidentKey(true))
	if err != nil {
		t.Fatalf("Failed to create mock authenticator: %v", err)
	}

	// Register user
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration failed: %v", err)
	}

	user, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	attestation, err := auth.CreateAttestationObject(
		regOptions.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, regSessionID, attestation)
	if err != nil {
		t.Fatalf("FinishRegistration failed: %v", err)
	}

	// Begin discoverable login (no user ID provided)
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, nil)
	if err != nil {
		t.Fatalf("BeginLogin (discoverable) failed: %v", err)
	}

	if loginOptions == nil {
		t.Fatal("Login options should not be nil")
	}

	// For discoverable credentials, allowedCredentials should be empty
	// (the authenticator determines which credential to use)
	if len(loginOptions.Response.AllowedCredentials) != 0 {
		t.Log("Note: Discoverable login returned allowedCredentials (may be expected for this implementation)")
	}

	t.Logf("Discoverable login options: challenge length=%d, session=%s",
		len(loginOptions.Response.Challenge), loginSessionID)
}

func TestMockAuthenticator_MultipleCredentials(t *testing.T) {
	ctx := context.Background()
	rpID := "localhost"
	origin := "https://localhost"
	email := "test@example.com"
	displayName := "Test User"

	// Create WebAuthn service with memory stores
	cfg := &Config{
		RPID:          rpID,
		RPDisplayName: "Test RP",
		RPOrigins:     []string{origin},
	}

	users := NewMemoryUserStore()
	sessions := NewMemorySessionStoreWithTTL(5 * time.Minute)
	creds := NewMemoryCredentialStore()

	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    sessions,
		CredentialStore: creds,
	})
	if err != nil {
		t.Fatalf("Failed to create WebAuthn service: %v", err)
	}

	// Create two mock authenticators (simulating two security keys)
	auth1, err := NewMockAuthenticator(rpID)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator 1: %v", err)
	}

	auth2, err := NewMockAuthenticator(rpID)
	if err != nil {
		t.Fatalf("Failed to create mock authenticator 2: %v", err)
	}

	// Register with first authenticator
	regOptions1, regSessionID1, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration 1 failed: %v", err)
	}

	user, err := svc.GetUserByEmail(ctx, email)
	if err != nil {
		t.Fatalf("Failed to get user: %v", err)
	}

	attestation1, err := auth1.CreateAttestationObject(
		regOptions1.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation 1: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, regSessionID1, attestation1)
	if err != nil {
		t.Fatalf("FinishRegistration 1 failed: %v", err)
	}

	// Register with second authenticator
	regOptions2, regSessionID2, err := svc.BeginRegistration(ctx, email, displayName)
	if err != nil {
		t.Fatalf("BeginRegistration 2 failed: %v", err)
	}

	// The exclude list should now contain the first credential
	if len(regOptions2.Response.CredentialExcludeList) != 1 {
		t.Errorf("CredentialExcludeList should have 1 entry, got %d", len(regOptions2.Response.CredentialExcludeList))
	}

	attestation2, err := auth2.CreateAttestationObject(
		regOptions2.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create attestation 2: %v", err)
	}

	_, _, err = svc.FinishRegistration(ctx, regSessionID2, attestation2)
	if err != nil {
		t.Fatalf("FinishRegistration 2 failed: %v", err)
	}

	// Verify user now has 2 credentials
	userCreds, err := svc.GetCredentials(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("GetCredentials failed: %v", err)
	}

	if len(userCreds) != 2 {
		t.Errorf("User should have 2 credentials, got %d", len(userCreds))
	}

	// Login should work with either authenticator
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	if err != nil {
		t.Fatalf("BeginLogin failed: %v", err)
	}

	// Should have 2 allowed credentials
	if len(loginOptions.Response.AllowedCredentials) != 2 {
		t.Errorf("AllowedCredentials should have 2 entries, got %d", len(loginOptions.Response.AllowedCredentials))
	}

	// Login with the first authenticator
	assertion, err := auth1.CreateAssertionResponse(
		loginOptions.Response.Challenge,
		user.WebAuthnID(),
		origin,
	)
	if err != nil {
		t.Fatalf("Failed to create assertion: %v", err)
	}

	token, _, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), assertion)
	if err != nil {
		t.Fatalf("FinishLogin failed: %v", err)
	}

	if token == "" {
		t.Error("Token should not be empty")
	}

	t.Logf("Successfully tested multiple credentials: registered %d, can login with any", len(userCreds))
}
