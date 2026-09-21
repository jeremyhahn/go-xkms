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
	"encoding/json"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFinishLogin_DiscoverableSession_CallerSuppliedHandle_Succeeds is the
// regression for go-xkms#558: a discoverable (usernameless) ceremony must
// complete even when the caller re-derives a user handle after the fact and
// passes it to FinishLogin — exactly what pkg/auth_factors's Verify does once
// it has resolved the qrdb factor to a user.
//
// Before the fix, finishLoginUser only consulted session.UserID when the
// caller-supplied handle was empty, so this non-empty, correctly-resolved
// handle routed the ceremony into the user-identified branch. go-webauthn's
// ValidateLogin then compared it against the empty session.UserID left by
// BeginDiscoverableLogin and rejected every discoverable login with "ID
// mismatch for User and Session".
func TestFinishLogin_DiscoverableSession_CallerSuppliedHandle_Succeeds(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
		ResidentKeyRequirement:  "preferred",
	}
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       NewMemoryUserStore(),
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}
	authenticator := virtualwebauthn.NewAuthenticator()
	credential := newEC2Credential(t)

	// Register the user and their credential.
	regOptions, regSessionID, err := svc.BeginRegistration(ctx, "discoverable@example.com", "Discoverable User")
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

	// Begin a discoverable (usernameless) ceremony: no user handle at all.
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, loginOptions.Response.AllowedCredentials, "a discoverable ceremony must not scope allowCredentials")

	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)
	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	// The authenticator reports the user handle in the assertion, as a real
	// passkey does for a client-side discoverable credential.
	discoverableAuth := virtualwebauthn.NewAuthenticatorWithOptions(virtualwebauthn.AuthenticatorOptions{
		UserHandle: user.WebAuthnID(),
	})
	discoverableAuth.AddCredential(credential)
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, discoverableAuth, credential, *parsedLoginOptions)
	parsedAssertResponse, err := parseAssertionResponse(assertionResponse)
	require.NoError(t, err)

	// Finish with a non-nil, correctly-resolved handle — the caller-supplied
	// value pkg/auth_factors's Verify derives from the qrdb factor. The
	// session recorded a discoverable ceremony, so it must win regardless.
	token, loggedInUser, err := svc.FinishLogin(ctx, loginSessionID, user.WebAuthnID(), parsedAssertResponse)
	require.NoError(t, err)
	require.NotEmpty(t, token)
	require.NotNil(t, loggedInUser)
	assert.Equal(t, user.WebAuthnID(), loggedInUser.WebAuthnID())
}

// TestFinishLogin_IdentifiedSession_MismatchedHandle_FailsVerification is the
// companion error-path regression: a session begun user-identified must
// still reject an assertion for a credential the session's user does not
// own, even though the fix now ignores whatever handle the caller passes to
// FinishLogin in favor of the session's own record. The session — not the
// caller — decides which user the ceremony is bound to, so a client cannot
// launder a different user's assertion through a mismatched handle.
func TestFinishLogin_IdentifiedSession_MismatchedHandle_FailsVerification(t *testing.T) {
	ctx := context.Background()

	cfg := &Config{
		RPID:                    "example.com",
		RPDisplayName:           "Example Corp",
		RPOrigins:               []string{"https://example.com"},
		AllowPublicRegistration: openRegistration(),
	}
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       NewMemoryUserStore(),
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)

	rp := virtualwebauthn.RelyingParty{
		Name:   cfg.RPDisplayName,
		ID:     cfg.RPID,
		Origin: cfg.RPOrigins[0],
	}

	registerUser := func(email string) (User, virtualwebauthn.Authenticator, virtualwebauthn.Credential) {
		authenticator := virtualwebauthn.NewAuthenticator()
		credential := newEC2Credential(t)

		regOptions, regSessionID, rErr := svc.BeginRegistration(ctx, email, email)
		require.NoError(t, rErr)
		regOptionsJSON, rErr := json.Marshal(regOptions.Response)
		require.NoError(t, rErr)
		parsedRegOptions, rErr := virtualwebauthn.ParseAttestationOptions(string(regOptionsJSON))
		require.NoError(t, rErr)
		attestationResponse := virtualwebauthn.CreateAttestationResponse(rp, authenticator, credential, *parsedRegOptions)
		parsedAttResponse, rErr := parseAttestationResponse(attestationResponse)
		require.NoError(t, rErr)
		_, u, rErr := svc.FinishRegistration(ctx, regSessionID, parsedAttResponse)
		require.NoError(t, rErr)
		authenticator.AddCredential(credential)
		return u, authenticator, credential
	}

	userA, _, _ := registerUser("victim@example.com")
	_, authenticatorB, credentialB := registerUser("attacker@example.com")

	// Begin an identified ceremony scoped to user A.
	loginOptions, loginSessionID, err := svc.BeginLogin(ctx, userA.WebAuthnID())
	require.NoError(t, err)

	loginOptionsJSON, err := json.Marshal(loginOptions.Response)
	require.NoError(t, err)
	parsedLoginOptions, err := virtualwebauthn.ParseAssertionOptions(string(loginOptionsJSON))
	require.NoError(t, err)

	// Sign the assertion with user B's credential — never enrolled to A.
	assertionResponse := virtualwebauthn.CreateAssertionResponse(rp, authenticatorB, credentialB, *parsedLoginOptions)
	parsedAssertResponse, err := parseAssertionResponse(assertionResponse)
	require.NoError(t, err)

	// FinishLogin must reject this regardless of which handle the caller
	// passes: the session, bound to user A at BeginLogin, is authoritative.
	_, _, err = svc.FinishLogin(ctx, loginSessionID, userA.WebAuthnID(), parsedAssertResponse)
	require.Error(t, err)
	assert.True(t, IsVerificationFailed(err), "expected a typed verification error, got %T: %v", err, err)
}
