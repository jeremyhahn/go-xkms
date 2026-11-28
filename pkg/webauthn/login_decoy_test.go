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
	"errors"
	"testing"

	"github.com/descope/virtualwebauthn"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// allowedIDs lists the credential IDs a login ceremony advertises.
func allowedIDs(options *protocol.CredentialAssertion) [][]byte {
	ids := make([][]byte, len(options.Response.AllowedCredentials))
	for i, desc := range options.Response.AllowedCredentials {
		ids[i] = desc.CredentialID
	}
	return ids
}

// TestBeginLoginForEmail_UnknownEmailGetsStableDecoy is go-xkms#1296: an
// unknown email is answered with a well-formed ceremony whose credential
// descriptors are the same on every probe, as a real account's would be.
func TestBeginLoginForEmail_UnknownEmailGetsStableDecoy(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()

	first, firstSession, err := f.svc.BeginLoginForEmail(ctx, "nobody@example.com")
	require.NoError(t, err)
	second, secondSession, err := f.svc.BeginLoginForEmail(ctx, "nobody@example.com")
	require.NoError(t, err)

	require.NotEmpty(t, first.Response.AllowedCredentials)
	assert.Equal(t, allowedIDs(first), allowedIDs(second), "repeated probes must see the same descriptors")
	for _, desc := range first.Response.AllowedCredentials {
		assert.Equal(t, protocol.PublicKeyCredentialType, desc.Type)
		assert.NotEmpty(t, desc.Transport)
	}
	assert.NotEqual(t, first.Response.Challenge, second.Response.Challenge, "every ceremony gets a fresh challenge")
	assert.NotEmpty(t, firstSession)
	assert.NotEqual(t, firstSession, secondSession)

	other, _, err := f.svc.BeginLoginForEmail(ctx, "someone-else@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, allowedIDs(first), allowedIDs(other), "different emails must derive different decoys")
}

// TestBeginLoginForEmail_DecoyShapedLikeRealCeremony compares a decoy with a
// real ceremony field by field, apart from the per-ceremony challenge and the
// account's own descriptors.
func TestBeginLoginForEmail_DecoyShapedLikeRealCeremony(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	f.enroll(t, "real@example.com")

	genuine, _, err := f.svc.BeginLoginForEmail(ctx, "real@example.com")
	require.NoError(t, err)
	decoy, _, err := f.svc.BeginLoginForEmail(ctx, "decoy@example.com")
	require.NoError(t, err)

	normalize := func(options *protocol.CredentialAssertion) map[string]any {
		raw, err := json.Marshal(options)
		require.NoError(t, err)
		var out map[string]any
		require.NoError(t, json.Unmarshal(raw, &out))
		publicKey := out["publicKey"].(map[string]any)
		delete(publicKey, "challenge")
		delete(publicKey, "allowCredentials")
		return out
	}
	assert.Equal(t, normalize(genuine), normalize(decoy))
}

// TestBeginLoginForEmail_RealAccount advertises the account's credential.
func TestBeginLoginForEmail_RealAccount(t *testing.T) {
	f := newEnrollFixture(t, true)
	_, credential := f.enroll(t, "real@example.com")

	options, sessionID, err := f.svc.BeginLoginForEmail(context.Background(), "real@example.com")
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)
	assert.Equal(t, [][]byte{credential.ID}, allowedIDs(options))
}

// TestBeginLoginForEmail_AccountWithoutCredentialsGetsDecoy proves a
// provisioned account that has not enrolled is not revealed either.
func TestBeginLoginForEmail_AccountWithoutCredentialsGetsDecoy(t *testing.T) {
	f := newEnrollFixture(t, false)
	ctx := context.Background()
	_, err := f.users.Create(ctx, "pending@example.com", "Pending")
	require.NoError(t, err)

	options, sessionID, err := f.svc.BeginLoginForEmail(ctx, "pending@example.com")
	require.NoError(t, err, "an account without credentials must not answer ErrNoCredentials")
	assert.NotEmpty(t, sessionID)
	assert.NotEmpty(t, options.Response.AllowedCredentials)
}

// TestBeginLoginForHandle_UnknownHandleGetsDecoy covers the user-ID form.
func TestBeginLoginForHandle_UnknownHandleGetsDecoy(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()
	handle := HandleFromUserID(424242)

	first, _, err := f.svc.BeginLoginForHandle(ctx, handle)
	require.NoError(t, err)
	second, _, err := f.svc.BeginLoginForHandle(ctx, handle)
	require.NoError(t, err)
	require.NotEmpty(t, first.Response.AllowedCredentials)
	assert.Equal(t, allowedIDs(first), allowedIDs(second))
}

// TestBeginLoginForHandle_RealAccount advertises the account's credential.
func TestBeginLoginForHandle_RealAccount(t *testing.T) {
	f := newEnrollFixture(t, true)
	user, credential := f.enroll(t, "real@example.com")

	options, _, err := f.svc.BeginLoginForHandle(context.Background(), user.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, [][]byte{credential.ID}, allowedIDs(options))
}

// TestFinishLogin_DecoySessionFailsVerification proves a decoy cannot be
// told apart at finish either: an assertion against it fails exactly like a
// wrong assertion against a real account.
func TestFinishLogin_DecoySessionFailsVerification(t *testing.T) {
	f := newEnrollFixture(t, true)
	ctx := context.Background()

	options, sessionID, err := f.svc.BeginLoginForEmail(ctx, "nobody@example.com")
	require.NoError(t, err)

	optionsJSON, err := json.Marshal(options.Response)
	require.NoError(t, err)
	parsedOptions, err := virtualwebauthn.ParseAssertionOptions(string(optionsJSON))
	require.NoError(t, err)
	credential := newEC2Credential(t)
	authenticator := virtualwebauthn.NewAuthenticator()
	authenticator.AddCredential(credential)
	assertion := virtualwebauthn.CreateAssertionResponse(f.rp, authenticator, credential, *parsedOptions)
	parsed, err := parseAssertionResponse(assertion)
	require.NoError(t, err)

	_, _, err = f.svc.FinishLogin(ctx, sessionID, nil, parsed)
	require.ErrorIs(t, err, ErrVerificationFailed)
}

// TestBeginLoginForEmail_StoreFault is not answered with a decoy: only "not
// found" is.
func TestBeginLoginForEmail_StoreFault(t *testing.T) {
	cfg := validTestConfig()
	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       &faultingUserStore{UserStore: users},
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	_, _, err = svc.BeginLoginForEmail(context.Background(), "any@example.com")
	require.ErrorIs(t, err, errUserStoreFault)
	_, _, err = svc.BeginLoginForHandle(context.Background(), HandleFromUserID(1))
	require.ErrorIs(t, err, errUserStoreFault)
}

// TestBeginLoginFor_EmptySubject is a malformed request, not an account
// lookup.
func TestBeginLoginFor_EmptySubject(t *testing.T) {
	f := newEnrollFixture(t, true)
	_, _, err := f.svc.BeginLoginForEmail(context.Background(), "")
	require.ErrorIs(t, err, ErrInvalidRequest)
	_, _, err = f.svc.BeginLoginForHandle(context.Background(), nil)
	require.ErrorIs(t, err, ErrInvalidRequest)
}

// TestBeginLoginFor_NotConfigured covers the zero-value service.
func TestBeginLoginFor_NotConfigured(t *testing.T) {
	_, _, err := (&Service{}).BeginLoginForEmail(context.Background(), "a@example.com")
	require.ErrorIs(t, err, ErrNotConfigured)
	_, _, err = (&Service{}).BeginLoginForHandle(context.Background(), HandleFromUserID(1))
	require.ErrorIs(t, err, ErrNotConfigured)
}

// TestDecoyKey_PerProcess documents the key's scope: two services draw
// different keys, so their decoys for one email differ.
func TestDecoyKey_PerProcess(t *testing.T) {
	a := newEnrollFixture(t, true)
	b := newEnrollFixture(t, true)

	fromA, _, err := a.svc.BeginLoginForEmail(context.Background(), "nobody@example.com")
	require.NoError(t, err)
	fromB, _, err := b.svc.BeginLoginForEmail(context.Background(), "nobody@example.com")
	require.NoError(t, err)
	assert.NotEqual(t, allowedIDs(fromA), allowedIDs(fromB))
}

var errUserStoreFault = errors.New("user store fault")

// faultingUserStore fails every lookup with a store fault.
type faultingUserStore struct {
	UserStore
}

func (s *faultingUserStore) GetByEmail(ctx context.Context, email string) (User, error) {
	return nil, errUserStoreFault
}

func (s *faultingUserStore) GetByUsername(ctx context.Context, username string) (User, error) {
	return nil, errUserStoreFault
}

func (s *faultingUserStore) GetByID(ctx context.Context, userID []byte) (User, error) {
	return nil, errUserStoreFault
}
