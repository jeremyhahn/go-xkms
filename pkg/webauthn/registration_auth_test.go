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
	"encoding/base64"
	"encoding/json"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// enrollFixture is a relying-party service plus a virtual authenticator
// that can complete real registration ceremonies against it.
type enrollFixture struct {
	svc      *Service
	users    UserStore
	creds    CredentialStore
	accounts *fakeUserClient
	rp       virtualwebauthn.RelyingParty
}

// newEnrollFixture builds a service over memory stores with public
// registration set to allow.
func newEnrollFixture(t *testing.T, allow bool) *enrollFixture {
	t.Helper()
	cfg := validTestConfig()
	cfg.AllowPublicRegistration = &allow
	users, creds, accounts := newTestAdapter(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)
	return &enrollFixture{
		svc:      svc,
		users:    users,
		creds:    creds,
		accounts: accounts,
		rp:       virtualwebauthn.RelyingParty{Name: cfg.RPDisplayName, ID: cfg.RPID, Origin: cfg.RPOrigins[0]},
	}
}

// attest completes the registration ceremony begun with options/sessionID
// using credential, returning FinishRegistration's result.
func (f *enrollFixture) attest(t *testing.T, options *protocol.CredentialCreation, sessionID string, credential virtualwebauthn.Credential) (User, error) {
	t.Helper()
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), credential, *parsedOptions)
	parsed, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	_, user, err := f.svc.FinishRegistration(context.Background(), sessionID, parsed)
	return user, err
}

// attestInvite completes the invite-authorized registration ceremony begun
// with options/sessionID using credential, returning FinishInviteRegistration's
// result. Unlike attest, it does not mint a token: invite redemption does not
// authenticate a session, it enrolls a credential.
func (f *enrollFixture) attestInvite(t *testing.T, options *protocol.CredentialCreation, sessionID string, credential virtualwebauthn.Credential) (User, error) {
	t.Helper()
	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAttestationOptions(string(optionsJSON))
	require.NoError(t, err)
	attestation := virtualwebauthn.CreateAttestationResponse(f.rp, virtualwebauthn.NewAuthenticator(), credential, *parsedOptions)
	parsed, err := parseAttestationResponse(attestation)
	require.NoError(t, err)
	return f.svc.FinishInviteRegistration(context.Background(), sessionID, parsed)
}

// enroll registers a first passkey for email through the public ceremony.
func (f *enrollFixture) enroll(t *testing.T, email string) (User, virtualwebauthn.Credential) {
	t.Helper()
	options, sessionID, err := f.svc.BeginRegistration(context.Background(), email, email)
	require.NoError(t, err)
	credential := newEC2Credential(t)
	user, err := f.attest(t, options, sessionID, credential)
	require.NoError(t, err)
	return user, credential
}

// sessionFor is the session account a WebAuthn-minted token carries for user.
func sessionFor(user User) SessionAccount {
	return SessionAccount{UserID: user.WebAuthnID(), Email: user.Email()}
}

// TestBeginRegistration_RefusesAccountWithCredentials is go-xkms#1294: the
// unauthenticated ceremony must not add a passkey to an account that already
// has one, whether or not public registration is open.
func TestBeginRegistration_RefusesAccountWithCredentials(t *testing.T) {
	for _, allow := range []bool{true, false} {
		// Enroll with registration open, then apply the mode under test.
		f := newEnrollFixture(t, true)
		ctx := context.Background()
		victim, _ := f.enroll(t, "victim@example.com")
		f.svc.config.AllowPublicRegistration = &allow

		options, sessionID, err := f.svc.BeginRegistration(ctx, "victim@example.com", "Attacker")
		require.ErrorIs(t, err, ErrRegistrationRefused, "allow_public_registration=%v", allow)
		assert.Nil(t, options)
		assert.Empty(t, sessionID)

		creds, err := f.creds.GetByUserID(ctx, victim.WebAuthnID())
		require.NoError(t, err)
		assert.Len(t, creds, 1, "a refused registration must not touch the account")
	}
}

// TestBeginAddCredential_AddsPasskeyToSessionAccount proves the authenticated
// path: the account's own session adds a second passkey, excluding the first.
func TestBeginAddCredential_AddsPasskeyToSessionAccount(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	user, first := f.enroll(t, "owner@example.com")

	options, sessionID, err := f.svc.BeginAddCredential(ctx, sessionFor(user))
	require.NoError(t, err)
	require.NotEmpty(t, sessionID)

	gotID, ok := options.Response.User.ID.(protocol.URLEncodedBase64)
	require.True(t, ok, "user ID should be protocol.URLEncodedBase64, got %T", options.Response.User.ID)
	assert.Equal(t, user.WebAuthnID(), []byte(gotID), "the ceremony must bind to the session's account")
	require.Len(t, options.Response.CredentialExcludeList, 1)
	assert.Equal(t, first.ID, []byte(options.Response.CredentialExcludeList[0].CredentialID))

	enrolled, err := f.attest(t, options, sessionID, newEC2Credential(t))
	require.NoError(t, err)
	assert.Equal(t, user.WebAuthnID(), enrolled.WebAuthnID())

	creds, err := f.creds.GetByUserID(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 2)
}

// TestBeginAddCredential_OtherSessionCannotAdd proves a session can only ever
// add a passkey to its own account: another user's session binds the ceremony
// to that other user, and a session whose email does not match the handle it
// names is refused.
func TestBeginAddCredential_OtherSessionCannotAdd(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	victim, _ := f.enroll(t, "victim@example.com")
	attacker, _ := f.enroll(t, "attacker@example.com")

	// The attacker's own session only ever reaches the attacker's account.
	options, sessionID, err := f.svc.BeginAddCredential(ctx, sessionFor(attacker))
	require.NoError(t, err)
	enrolled, err := f.attest(t, options, sessionID, newEC2Credential(t))
	require.NoError(t, err)
	assert.Equal(t, attacker.WebAuthnID(), enrolled.WebAuthnID())

	victimCreds, err := f.creds.GetByUserID(ctx, victim.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, victimCreds, 1, "another session must not add to the victim's account")

	// A session naming the victim's handle with another email is refused.
	_, _, err = f.svc.BeginAddCredential(ctx, SessionAccount{UserID: victim.WebAuthnID(), Email: attacker.Email()})
	require.ErrorIs(t, err, ErrSessionAccountMismatch)
}

// TestBeginAddCredential_RefusesUnresolvableSession covers the session shapes
// that name no account.
func TestBeginAddCredential_RefusesUnresolvableSession(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	user, _ := f.enroll(t, "someone@example.com")

	cases := map[string]SessionAccount{
		"empty":          {},
		"no email":       {UserID: user.WebAuthnID()},
		"no handle":      {Email: user.Email()},
		"unknown handle": {UserID: []byte("12345678"), Email: user.Email()},
	}
	for name, acct := range cases {
		_, sessionID, err := f.svc.BeginAddCredential(ctx, acct)
		require.ErrorIs(t, err, ErrSessionAccountMismatch, name)
		assert.Empty(t, sessionID, name)
	}
}

// TestBeginAddCredential_NotConfigured covers the zero-value service.
func TestBeginAddCredential_NotConfigured(t *testing.T) {
	_, _, err := (&Service{}).BeginAddCredential(context.Background(), SessionAccount{})
	require.ErrorIs(t, err, ErrNotConfigured)
}

// TestBeginRegistration_RefusesPreexistingZeroCredentialAccount pins the
// go-xkms#1294 part B closure: an account that existed before the call —
// even with zero credentials — is refused by the public BeginRegistration
// entry point in both registration modes. Its first credential enrolls only
// through BeginInviteRegistration
// (TestBeginInviteRegistration_EnrollsPendingAccount).
func TestBeginRegistration_RefusesPreexistingZeroCredentialAccount(t *testing.T) {
	for _, allow := range []bool{true, false} {
		f := newEnrollFixture(t, allow)
		_, err := f.users.Create(context.Background(), "new@example.com", "New Hire")
		require.NoError(t, err)

		options, sessionID, err := f.svc.BeginRegistration(context.Background(), "new@example.com", "New Hire")
		require.ErrorIs(t, err, ErrRegistrationRefused, "allow_public_registration=%v", allow)
		assert.Nil(t, options)
		assert.Empty(t, sessionID)
	}
}

// TestBeginInviteRegistration_EnrollsPendingAccount is the invite-authorized
// replacement for the unauthenticated first-passkey path
// TestBeginRegistration_RefusesPreexistingZeroCredentialAccount closes: a
// PENDING account with zero credentials enrolls its first passkey through
// BeginInviteRegistration/FinishInviteRegistration.
func TestBeginInviteRegistration_EnrollsPendingAccount(t *testing.T) {
	f := newEnrollFixture(t, false)
	ctx := context.Background()
	provisioned, err := f.users.Create(ctx, "new@example.com", "New Hire")
	require.NoError(t, err)
	f.setStanding(t, "new@example.com", qrdbsdk.LifecyclePending, nil)

	options, sessionID, err := f.svc.BeginInviteRegistration(ctx, "new@example.com")
	require.NoError(t, err)
	enrolled, err := f.attestInvite(t, options, sessionID, newEC2Credential(t))
	require.NoError(t, err)
	assert.Equal(t, provisioned.WebAuthnID(), enrolled.WebAuthnID())
}

// TestBeginRegistration_RefusalsAreIndistinguishable is go-xkms#1296: with
// public registration off, an unknown email and an account that already has
// a passkey are refused with the very same error.
func TestBeginRegistration_RefusalsAreIndistinguishable(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	f.enroll(t, "known@example.com")
	f.svc.config.AllowPublicRegistration = new(bool)

	_, _, knownErr := f.svc.BeginRegistration(ctx, "known@example.com", "Known")
	_, _, unknownErr := f.svc.BeginRegistration(ctx, "unknown@example.com", "Unknown")

	require.ErrorIs(t, knownErr, ErrRegistrationRefused)
	require.ErrorIs(t, unknownErr, ErrRegistrationRefused)
	assert.Equal(t, knownErr.Error(), unknownErr.Error())
}

// TestSessionAccountFromIdentity pins the inverse of the WebAuthn token
// mapping: base64url subject handle plus the email metadata.
func TestSessionAccountFromIdentity(t *testing.T) {
	handle := []byte{0, 0, 0, 0, 0, 0, 0, 42}
	id := &auth.Identity{
		Subject:  base64.RawURLEncoding.EncodeToString(handle),
		Metadata: map[string]string{"email": "a@example.com"},
	}
	acct, err := SessionAccountFromIdentity(id)
	require.NoError(t, err)
	assert.Equal(t, handle, acct.UserID)
	assert.Equal(t, "a@example.com", acct.Email)
}

// TestSessionAccountFromIdentity_Rejects covers identities that name no
// WebAuthn account.
func TestSessionAccountFromIdentity_Rejects(t *testing.T) {
	cases := map[string]*auth.Identity{
		"nil":           nil,
		"empty subject": {Metadata: map[string]string{"email": "a@example.com"}},
		"not base64url": {Subject: "not base64!", Metadata: map[string]string{"email": "a@example.com"}},
		"no email":      {Subject: base64.RawURLEncoding.EncodeToString([]byte("12345678"))},
	}
	for name, id := range cases {
		_, err := SessionAccountFromIdentity(id)
		require.ErrorIs(t, err, ErrSessionAccountMismatch, name)
	}
}
