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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newServiceWithPublicRegistration builds a service whose relying party either
// accepts or refuses open sign-up.
func newServiceWithPublicRegistration(t *testing.T, allow bool) (*Service, UserStore) {
	t.Helper()

	cfg := validTestConfig()
	cfg.AllowPublicRegistration = &allow

	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)
	return svc, users
}

// TestPublicRegistrationDefaultsToDisabled pins the secure default ruled in
// go-xkms#184: an unset allow_public_registration means registration is
// CLOSED, consistent with the stack-wide registration model
// (iam.self_service_registration.enabled defaults off). The nil case is
// asserted directly rather than inferred from the struct definition because
// this default silently opening would be exactly the defect the ruling
// designs away.
func TestPublicRegistrationDefaultsToDisabled(t *testing.T) {
	cfg := validTestConfig()
	require.Nil(t, cfg.AllowPublicRegistration, "the test config must not set the field")

	assert.False(t, cfg.PublicRegistrationAllowed(),
		"an unset allow_public_registration must mean closed registration")

	// SetDefaults must not fill the field in: nil records "the operator never
	// considered this", which compliance profiles and the composed-host
	// projection both rely on.
	cfg.SetDefaults()
	assert.Nil(t, cfg.AllowPublicRegistration, "SetDefaults must leave the field unset")
	assert.False(t, cfg.PublicRegistrationAllowed(), "SetDefaults must not open registration")

	// A nil Config must not panic and must fail closed.
	var nilCfg *Config
	assert.False(t, nilCfg.PublicRegistrationAllowed(), "a nil Config must read as closed")
}

// TestPublicRegistrationExplicitValues pins the two explicit states: the
// operator's (or the composing host's) decision is applied verbatim in both
// directions.
func TestPublicRegistrationExplicitValues(t *testing.T) {
	open, closed := true, false

	cfg := validTestConfig()
	cfg.AllowPublicRegistration = &open
	assert.True(t, cfg.PublicRegistrationAllowed(), "explicit true must open registration")

	cfg.AllowPublicRegistration = &closed
	assert.False(t, cfg.PublicRegistrationAllowed(), "explicit false must close registration")
}

// TestPublicRegistrationDefault_RefusesUnknownUser proves the default is
// enforced at the BeginRegistration entry point, not only in the config
// accessor: a service built from a config that never mentions the field
// refuses an unknown email with the typed error and writes nothing.
func TestPublicRegistrationDefault_RefusesUnknownUser(t *testing.T) {
	ctx := context.Background()

	cfg := validTestConfig()
	require.Nil(t, cfg.AllowPublicRegistration, "the test config must not set the field")

	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)

	options, sessionID, err := svc.BeginRegistration(ctx, "stranger@example.com", "Stranger")

	require.Error(t, err, "the default policy must refuse an unknown email")
	assert.True(t, errors.Is(err, ErrRegistrationRefused),
		"want ErrRegistrationRefused, got %v", err)
	assert.Nil(t, options)
	assert.Empty(t, sessionID)

	_, err = users.GetByEmail(ctx, "stranger@example.com")
	assert.True(t, IsUserNotFound(err),
		"a refused registration must not leave an account behind")
}

// TestPublicRegistrationAllowed_CreatesUnknownUser is the open case: an email
// nobody has seen becomes an account.
func TestPublicRegistrationAllowed_BeginsForUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, true)

	options, sessionID, err := svc.BeginRegistration(ctx, "newcomer@example.com", "Newcomer")
	require.NoError(t, err)
	require.NotNil(t, options)
	assert.NotEmpty(t, sessionID)

	// The account is created at finish, not begin (ruling 417(2)).
	_, err = users.GetByEmail(ctx, "newcomer@example.com")
	assert.True(t, IsUserNotFound(err), "begin must not create the account, got %v", err)
}

// TestPublicRegistrationDisabled_RefusesUnknownUser is the closed case: the
// implicit account creation is withheld and nothing is written.
func TestPublicRegistrationDisabled_RefusesUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, false)

	options, sessionID, err := svc.BeginRegistration(ctx, "stranger@example.com", "Stranger")

	require.Error(t, err, "closed registration must refuse an unknown email")
	assert.True(t, errors.Is(err, ErrRegistrationRefused),
		"want ErrRegistrationRefused, got %v", err)
	assert.Nil(t, options)
	assert.Empty(t, sessionID)

	_, err = users.GetByEmail(ctx, "stranger@example.com")
	assert.True(t, IsUserNotFound(err),
		"a refused registration must not leave an account behind")
}

// TestPublicRegistrationDisabled_RefusesProvisionedUser pins go-xkms#1294
// part B: the public (unauthenticated) BeginRegistration entry point never
// enrolls the first credential of an account that already existed before the
// call, in either registration mode. A provisioned-but-unenrolled account
// activates only through BeginInviteRegistration
// (TestBeginInviteRegistration_PendingAccountEnrolls), never through this one.
func TestPublicRegistrationDisabled_RefusesProvisionedUser(t *testing.T) {
	for _, allow := range []bool{true, false} {
		ctx := context.Background()
		svc, users := newServiceWithPublicRegistration(t, allow)

		// Stand in for the authorized CreateUser path an administrator would
		// use: an account that exists but holds no credential yet.
		_, err := users.Create(ctx, "staff@example.com", "Staff Member")
		require.NoError(t, err)

		options, sessionID, err := svc.BeginRegistration(ctx, "staff@example.com", "Staff Member")

		require.ErrorIs(t, err, ErrRegistrationRefused, "allow_public_registration=%v", allow)
		assert.Nil(t, options)
		assert.Empty(t, sessionID)
	}
}

// TestBeginInviteRegistration_PendingAccountEnrolls is the invite-authorized
// counterpart of the case TestPublicRegistrationDisabled_RefusesProvisionedUser
// closes: an account created through the authorized user-creation path
// (LifecyclePending, zero credentials) enrolls its first passkey through
// BeginInviteRegistration, regardless of the public-registration setting —
// the invite is the authorization, not the relying party's open-sign-up
// policy.
func TestBeginInviteRegistration_PendingAccountEnrolls(t *testing.T) {
	for _, allow := range []bool{true, false} {
		ctx := context.Background()
		f := newEnrollFixture(t, allow)

		provisioned, err := f.users.Create(ctx, "staff@example.com", "Staff Member")
		require.NoError(t, err)
		f.setStanding(t, "staff@example.com", qrdbsdk.LifecyclePending, nil)

		options, sessionID, err := f.svc.BeginInviteRegistration(ctx, "staff@example.com")

		require.NoError(t, err, "allow_public_registration=%v", allow)
		require.NotNil(t, options)
		assert.NotEmpty(t, sessionID)
		// options.Response.User.ID is declared `any` and carries a
		// protocol.URLEncodedBase64 whose underlying bytes are the WebAuthn
		// user handle. Assert the concrete type first, then compare raw
		// bytes: testify's Equal is type-strict, so comparing the handle
		// directly against []byte would fail on the type even when the
		// bytes match.
		gotID, ok := options.Response.User.ID.(protocol.URLEncodedBase64)
		require.True(t, ok, "user ID should be protocol.URLEncodedBase64, got %T", options.Response.User.ID)
		assert.Equal(t, provisioned.WebAuthnID(), []byte(gotID),
			"enrollment must bind to the provisioned account, not a new one")
	}
}
