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

	users := NewMemoryUserStore()
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	return svc, users
}

// TestPublicRegistrationDefaultsToAllowed pins the upgrade-safety property of
// the *bool.
//
// A plain bool would default to false, so every config written before this
// field existed -- and every config that simply omits the key -- would switch
// to closed registration on upgrade. That is a silent behavior regression and
// the opposite of the intended default, so the nil case is asserted directly
// rather than inferred from the struct definition.
func TestPublicRegistrationDefaultsToAllowed(t *testing.T) {
	cfg := validTestConfig()
	require.Nil(t, cfg.AllowPublicRegistration, "the test config must not set the field")

	assert.True(t, cfg.PublicRegistrationAllowed(),
		"an unset allow_public_registration must mean open registration")

	// SetDefaults must not fill the field in, or nil would stop meaning "open".
	cfg.SetDefaults()
	assert.Nil(t, cfg.AllowPublicRegistration, "SetDefaults must leave the field unset")
	assert.True(t, cfg.PublicRegistrationAllowed(), "SetDefaults must not close registration")

	// A nil Config must not panic and must read as open.
	var nilCfg *Config
	assert.True(t, nilCfg.PublicRegistrationAllowed(), "a nil Config must read as open")
}

// TestPublicRegistrationAllowed_CreatesUnknownUser is the open case: an email
// nobody has seen becomes an account.
func TestPublicRegistrationAllowed_CreatesUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, true)

	options, sessionID, err := svc.BeginRegistration(ctx, "newcomer@example.com", "Newcomer")
	require.NoError(t, err)
	require.NotNil(t, options)
	assert.NotEmpty(t, sessionID)

	_, err = users.GetByEmail(ctx, "newcomer@example.com")
	assert.NoError(t, err, "open registration must have created the account")
}

// TestPublicRegistrationDisabled_RefusesUnknownUser is the closed case: the
// implicit account creation is withheld and nothing is written.
func TestPublicRegistrationDisabled_RefusesUnknownUser(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, false)

	options, sessionID, err := svc.BeginRegistration(ctx, "stranger@example.com", "Stranger")

	require.Error(t, err, "closed registration must refuse an unknown email")
	assert.True(t, errors.Is(err, ErrPublicRegistrationDisabled),
		"want ErrPublicRegistrationDisabled, got %v", err)
	assert.Nil(t, options)
	assert.Empty(t, sessionID)

	_, err = users.GetByEmail(ctx, "stranger@example.com")
	assert.True(t, IsUserNotFound(err),
		"a refused registration must not leave an account behind")
}

// TestPublicRegistrationDisabled_AllowsProvisionedUser is the property that
// makes closed mode usable without an invite token or a second enrollment
// endpoint: an account created through the authorized user-creation path still
// enrolls its first passkey through this same entry point.
//
// Without this, turning the flag off would lock out every user including the
// ones an administrator had deliberately provisioned.
func TestPublicRegistrationDisabled_AllowsProvisionedUser(t *testing.T) {
	ctx := context.Background()
	svc, users := newServiceWithPublicRegistration(t, false)

	// Stand in for the authorized CreateUser path an administrator would use.
	provisioned, err := users.Create(ctx, "staff@example.com", "Staff Member")
	require.NoError(t, err)

	options, sessionID, err := svc.BeginRegistration(ctx, "staff@example.com", "Staff Member")

	require.NoError(t, err, "a provisioned account must still be able to enroll a passkey")
	require.NotNil(t, options)
	assert.NotEmpty(t, sessionID)
	// options.Response.User.ID is declared `any` and carries a
	// protocol.URLEncodedBase64 whose underlying bytes are the WebAuthn user
	// handle. Assert the concrete type first, then compare raw bytes:
	// testify's Equal is type-strict, so comparing the handle directly against
	// []byte would fail on the type even when the bytes match.
	gotID, ok := options.Response.User.ID.(protocol.URLEncodedBase64)
	require.True(t, ok, "user ID should be protocol.URLEncodedBase64, got %T", options.Response.User.ID)
	assert.Equal(t, provisioned.WebAuthnID(), []byte(gotID),
		"enrollment must bind to the provisioned account, not a new one")
}
