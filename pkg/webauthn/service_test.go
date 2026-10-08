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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func validTestConfig() *Config {
	return &Config{
		RPID:          "example.com",
		RPDisplayName: "Example",
		RPOrigins:     []string{"https://example.com"},
	}
}

// openRegistration opts a test relying party into public sign-up. Since
// go-xkms#184 the default is closed, so ceremony tests that exercise implicit
// account creation must ask for it explicitly, exactly like a deployment.
func openRegistration() *bool {
	b := true
	return &b
}

func TestNewService(t *testing.T) {
	users, creds := newTestStores(t)
	tests := []struct {
		name    string
		params  ServiceParams
		wantErr string
	}{
		{
			name:    "nil config",
			params:  ServiceParams{},
			wantErr: "config is required",
		},
		{
			name: "nil user store",
			params: ServiceParams{
				Config: validTestConfig(),
			},
			wantErr: "user store is required",
		},
		{
			name: "nil session store",
			params: ServiceParams{
				Config:    validTestConfig(),
				UserStore: users,
			},
			wantErr: "session store is required",
		},
		{
			name: "nil credential store",
			params: ServiceParams{
				Config:       validTestConfig(),
				UserStore:    users,
				SessionStore: NewMemorySessionStore(),
			},
			wantErr: "credential store is required",
		},
		{
			name: "invalid config",
			params: ServiceParams{
				Config:          &Config{}, // missing required fields
				UserStore:       users,
				SessionStore:    NewMemorySessionStore(),
				CredentialStore: creds,
			},
			wantErr: "invalid config",
		},
		{
			name: "valid params",
			params: ServiceParams{
				Config:          validTestConfig(),
				UserStore:       users,
				SessionStore:    NewMemorySessionStore(),
				CredentialStore: creds,
			},
			wantErr: "",
		},
		{
			name: "valid params with JWT generator",
			params: ServiceParams{
				Config:          validTestConfig(),
				UserStore:       users,
				SessionStore:    NewMemorySessionStore(),
				CredentialStore: creds,
				JWTGenerator:    &mockJWTGenerator{},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc, err := NewService(tt.params)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				assert.Nil(t, svc)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, svc)
				assert.NotNil(t, svc.Config())
			}
		})
	}
}

type mockJWTGenerator struct {
	token string
	err   error
}

func (m *mockJWTGenerator) GenerateToken(ctx context.Context, user User) (string, error) {
	if m.err != nil {
		return "", m.err
	}
	if m.token != "" {
		return m.token, nil
	}
	return "mock-jwt-token", nil
}

func newTestService(t *testing.T) *Service {
	// The ceremony tests seed accounts through open sign-up, which since
	// go-xkms#184 must be requested explicitly.
	cfg := validTestConfig()
	cfg.AllowPublicRegistration = openRegistration()
	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
	})
	require.NoError(t, err)
	return svc
}

func TestService_BeginRegistration(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Begin registration for new user
	options, sessionID, err := svc.BeginRegistration(ctx, "test@example.com", "Test User")
	require.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotEmpty(t, sessionID)
	assert.Equal(t, "example.com", options.Response.RelyingParty.ID)
	assert.Equal(t, "test@example.com", options.Response.User.Name)
	assert.Equal(t, "Test User", options.Response.User.DisplayName)

	// A second BeginRegistration for the SAME email is refused: the public
	// (unauthenticated) entry point never enrolls a credential for an
	// account that already existed before the call, whether or not it holds
	// one yet (go-xkms#1294 part B). Adding a credential to an existing
	// account requires an authenticated session (BeginAddCredential) or, for
	// a provisioned account's first credential, invite redemption
	// (BeginInviteRegistration).
	options2, sessionID2, err := svc.BeginRegistration(ctx, "test@example.com", "Test User Updated")
	require.ErrorIs(t, err, ErrRegistrationRefused)
	assert.Nil(t, options2)
	assert.Empty(t, sessionID2)
}

func TestService_BeginLogin_Discoverable(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Begin discoverable login (no user ID)
	options, sessionID, err := svc.BeginLogin(ctx, nil)
	require.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotEmpty(t, sessionID)
	// Discoverable login should have empty allowCredentials
	assert.Empty(t, options.Response.AllowedCredentials)
}

func TestService_BeginLogin_UserNotFound(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Begin login with non-existent user
	_, _, err := svc.BeginLogin(ctx, []byte{1, 2, 3})
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err))
}

func TestService_BeginLogin_NoCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Create user without credentials
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// Begin login with user who has no credentials
	_, _, err = svc.BeginLogin(ctx, user.WebAuthnID())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNoCredentials)
}

func TestService_IsRegistered(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Check nil user ID
	registered, err := svc.IsRegistered(ctx, nil)
	require.NoError(t, err)
	assert.False(t, registered)

	// Check non-existent user
	registered, err = svc.IsRegistered(ctx, []byte{1, 2, 3})
	require.NoError(t, err)
	assert.False(t, registered)

	// Create a user
	_, _, err = svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// User exists but has no credentials
	registered, err = svc.IsRegistered(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.False(t, registered)
}

func TestService_GetUser(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Get non-existent user
	_, err := svc.GetUser(ctx, []byte{1, 2, 3})
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err))

	// Create user
	_, _, err = svc.BeginRegistration(ctx, "test@example.com", "Test User")
	require.NoError(t, err)

	// Get by email
	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", user.Email())

	// Get by ID
	user2, err := svc.GetUser(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, user.WebAuthnID(), user2.WebAuthnID())
}

func TestService_GetCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Get credentials for non-existent user (returns empty, not error)
	creds, err := svc.GetCredentials(ctx, []byte{1, 2, 3})
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestService_DeleteCredential(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Delete non-existent credential
	err := svc.DeleteCredential(ctx, []byte{1, 2, 3})
	require.Error(t, err)
	assert.True(t, IsCredentialNotFound(err))
}

func TestService_DeleteUser(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Create user
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// Delete user
	err = svc.DeleteUser(ctx, user.WebAuthnID())
	require.NoError(t, err)

	// Verify deleted
	_, err = svc.GetUser(ctx, user.WebAuthnID())
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err))
}

func TestService_NotConfigured(t *testing.T) {
	// Create an unconfigured service by manipulating the struct directly
	svc := &Service{configured: false}
	ctx := context.Background()

	// All methods should return ErrNotConfigured
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, _, err = svc.FinishRegistration(ctx, "session", nil)
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, _, err = svc.BeginLogin(ctx, nil)
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, _, err = svc.FinishLogin(ctx, "session", nil, nil)
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, err = svc.IsRegistered(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, err = svc.GetUser(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, err = svc.GetUserByEmail(ctx, "test@example.com")
	assert.ErrorIs(t, err, ErrNotConfigured)

	_, err = svc.GetCredentials(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrNotConfigured)

	err = svc.DeleteCredential(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrNotConfigured)

	err = svc.DeleteUser(ctx, []byte{1})
	assert.ErrorIs(t, err, ErrNotConfigured)
}

func TestService_Config(t *testing.T) {
	svc := newTestService(t)
	cfg := svc.Config()
	assert.NotNil(t, cfg)
	assert.Equal(t, "example.com", cfg.RPID)
}

func TestService_WithJWTGenerator(t *testing.T) {
	ctx := context.Background()

	jwtGen := &mockJWTGenerator{token: "custom-jwt-token"}
	cfg := validTestConfig()
	cfg.AllowPublicRegistration = openRegistration()
	users, creds := newTestStores(t)
	svc, err := NewService(ServiceParams{
		Config:          cfg,
		UserStore:       users,
		SessionStore:    NewMemorySessionStore(),
		CredentialStore: creds,
		JWTGenerator:    jwtGen,
	})
	require.NoError(t, err)

	// Begin registration to create user
	_, _, err = svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	// User exists
	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	assert.NotNil(t, user)
}

func TestService_BeginRegistration_RefusesSecondCallForSameEmail(t *testing.T) {
	ctx := context.Background()

	// Create a service where user already exists
	svc := newTestService(t)

	// First registration
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test User")
	require.NoError(t, err)

	// A second call for the SAME email is refused (go-xkms#1294 part B): the
	// account now exists, and the public entry point never enrolls a
	// credential for an account that already existed before the call.
	options, sessionID, err := svc.BeginRegistration(ctx, "test@example.com", "Test User 2")
	require.ErrorIs(t, err, ErrRegistrationRefused)
	assert.Nil(t, options)
	assert.Empty(t, sessionID)
}

func TestService_DeleteUser_WithCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Create user
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// Add a credential directly to the store
	cred := &Credential{
		ID:     []byte{1, 2, 3},
		UserID: user.WebAuthnID(),
	}
	_ = svc.creds.Save(ctx, cred)

	// Verify credential exists
	creds, err := svc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, creds, 1)

	// Delete user
	err = svc.DeleteUser(ctx, user.WebAuthnID())
	require.NoError(t, err)

	// Verify user deleted
	_, err = svc.GetUser(ctx, user.WebAuthnID())
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err))

	// Verify credentials deleted
	creds, err = svc.GetCredentials(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestService_DeleteUser_NonExistent(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Delete non-existent user
	err := svc.DeleteUser(ctx, HandleFromUserID(9999))
	require.Error(t, err)
	assert.True(t, IsUserNotFound(err))
}

func TestService_BeginLogin_WithCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Create user
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// Add a credential directly to the store
	cred := &Credential{
		ID:        []byte{1, 2, 3},
		UserID:    user.WebAuthnID(),
		PublicKey: []byte{4, 5, 6},
	}
	_ = svc.creds.Save(ctx, cred)

	// Also add the credential to the user (required by go-webauthn)
	user.AddCredential(cred)
	_ = svc.users.Save(ctx, user)

	// Begin login with user who has credentials
	options, sessionID, err := svc.BeginLogin(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.NotNil(t, options)
	assert.NotEmpty(t, sessionID)
}

func TestService_IsRegistered_WithCredentials(t *testing.T) {
	ctx := context.Background()
	svc := newTestService(t)

	// Create user
	_, _, err := svc.BeginRegistration(ctx, "test@example.com", "Test")
	require.NoError(t, err)

	user, err := svc.GetUserByEmail(ctx, "test@example.com")
	require.NoError(t, err)

	// Not registered yet (no credentials)
	registered, err := svc.IsRegistered(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.False(t, registered)

	// Add a credential
	cred := &Credential{
		ID:     []byte{1, 2, 3},
		UserID: user.WebAuthnID(),
	}
	_ = svc.creds.Save(ctx, cred)

	// Now registered
	registered, err = svc.IsRegistered(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.True(t, registered)
}
