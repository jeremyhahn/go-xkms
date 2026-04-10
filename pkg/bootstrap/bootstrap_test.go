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

package bootstrap

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/user"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func createTestUserStore(t *testing.T) user.Store {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)
	store, err := user.NewFileStore(backend)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = store.Close()
	})
	return store
}

// TestBootstrapNewService verifies basic service creation and configuration.
func TestBootstrapNewService(t *testing.T) {
	store := createTestUserStore(t)
	logger := testLogger()

	svc, err := NewService(Config{}, store, logger)
	require.NoError(t, err)
	assert.Equal(t, StateUninitialized, svc.State())
	assert.False(t, svc.IsInitialized())
}

// TestBootstrapNewServiceDefaults verifies default config values.
func TestBootstrapNewServiceDefaults(t *testing.T) {
	store := createTestUserStore(t)
	logger := testLogger()

	svc, err := NewService(Config{}, store, logger)
	require.NoError(t, err)
	assert.Equal(t, defaultTokenTTL, svc.config.TokenTTL)
}

// TestBootstrapNewServiceNilUserStore verifies nil user store is rejected.
func TestBootstrapNewServiceNilUserStore(t *testing.T) {
	_, err := NewService(Config{}, nil, testLogger())
	assert.ErrorIs(t, err, ErrNilUserStore)
}

// TestBootstrapNewServiceNilLogger verifies nil logger is rejected.
func TestBootstrapNewServiceNilLogger(t *testing.T) {
	store := createTestUserStore(t)
	_, err := NewService(Config{}, store, nil)
	assert.ErrorIs(t, err, ErrNilLogger)
}

// TestBootstrapNewServiceExistingUsers verifies that when users already exist,
// the service starts in the Complete state.
func TestBootstrapNewServiceExistingUsers(t *testing.T) {
	store := createTestUserStore(t)
	logger := testLogger()

	// Pre-create a user so HasAnyUsers returns true
	_, err := store.Create(context.Background(), "existing-admin", "Existing Admin", user.RoleAdmin, "")
	require.NoError(t, err)

	svc, err := NewService(Config{}, store, logger)
	require.NoError(t, err)
	assert.Equal(t, StateComplete, svc.State())
	assert.True(t, svc.IsInitialized())
}

// TestBootstrapNewServiceThresholdConfig verifies threshold mode config validation.
func TestBootstrapNewServiceThresholdConfig(t *testing.T) {
	store := createTestUserStore(t)
	logger := testLogger()

	tests := []struct {
		name      string
		config    Config
		expectErr error
	}{
		{
			name: "valid threshold config",
			config: Config{
				ThresholdMode:  true,
				AdminThreshold: 2,
				AdminTotal:     3,
			},
			expectErr: nil,
		},
		{
			name: "threshold greater than total",
			config: Config{
				ThresholdMode:  true,
				AdminThreshold: 5,
				AdminTotal:     3,
			},
			expectErr: ErrThresholdConfig,
		},
		{
			name: "zero threshold",
			config: Config{
				ThresholdMode:  true,
				AdminThreshold: 0,
				AdminTotal:     3,
			},
			expectErr: ErrThresholdConfig,
		},
		{
			name: "zero total",
			config: Config{
				ThresholdMode:  true,
				AdminThreshold: 2,
				AdminTotal:     0,
			},
			expectErr: ErrThresholdConfig,
		},
		{
			name: "negative threshold",
			config: Config{
				ThresholdMode:  true,
				AdminThreshold: -1,
				AdminTotal:     3,
			},
			expectErr: ErrThresholdConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewService(tt.config, store, logger)
			if tt.expectErr != nil {
				assert.ErrorIs(t, err, tt.expectErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestBootstrapGenerateSetupToken verifies token generation.
func TestBootstrapGenerateSetupToken(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token.Token)
	assert.False(t, token.Used)
	assert.False(t, token.ExpiresAt.IsZero())
	assert.False(t, token.CreatedAt.IsZero())
	assert.Equal(t, StateReady, svc.State())
}

// TestBootstrapGenerateSetupTokenAlreadyInitialized verifies error when already initialized.
func TestBootstrapGenerateSetupTokenAlreadyInitialized(t *testing.T) {
	store := createTestUserStore(t)
	_, err := store.Create(context.Background(), "admin", "Admin", user.RoleAdmin, "")
	require.NoError(t, err)

	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)
	assert.Equal(t, StateComplete, svc.State())

	_, err = svc.GenerateSetupToken()
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// TestBootstrapGenerateSetupTokenRegenerateAllowed verifies that regenerating a token
// is allowed when in the Ready state (overwrites previous).
func TestBootstrapGenerateSetupTokenRegenerateAllowed(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token1, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	token2, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	assert.NotEqual(t, token1.Token, token2.Token)
}

// TestBootstrapValidateSetupToken verifies token validation.
func TestBootstrapValidateSetupToken(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ValidateSetupToken(token.Token)
	assert.NoError(t, err)
}

// TestBootstrapValidateSetupTokenEmpty verifies empty token error.
func TestBootstrapValidateSetupTokenEmpty(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ValidateSetupToken("")
	assert.ErrorIs(t, err, ErrEmptyToken)
}

// TestBootstrapValidateSetupTokenNoToken verifies error when no token generated.
func TestBootstrapValidateSetupTokenNoToken(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	err = svc.ValidateSetupToken("some-token")
	assert.ErrorIs(t, err, ErrNoToken)
}

// TestBootstrapValidateSetupTokenInvalid verifies invalid token error.
func TestBootstrapValidateSetupTokenInvalid(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ValidateSetupToken("wrong-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestBootstrapValidateSetupTokenExpired verifies expired token error.
func TestBootstrapValidateSetupTokenExpired(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 1 * time.Nanosecond,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	// Wait for the token to expire
	time.Sleep(5 * time.Millisecond)

	err = svc.ValidateSetupToken(token.Token)
	assert.ErrorIs(t, err, ErrTokenExpired)
}

// TestBootstrapValidateSetupTokenUsed verifies used token error.
func TestBootstrapValidateSetupTokenUsed(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ConsumeSetupToken(token.Token)
	require.NoError(t, err)

	err = svc.ValidateSetupToken(token.Token)
	assert.ErrorIs(t, err, ErrTokenUsed)
}

// TestBootstrapConsumeSetupToken verifies token consumption.
func TestBootstrapConsumeSetupToken(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ConsumeSetupToken(token.Token)
	assert.NoError(t, err)

	// Token should now be marked as used
	err = svc.ConsumeSetupToken(token.Token)
	assert.ErrorIs(t, err, ErrTokenUsed)
}

// TestBootstrapConsumeSetupTokenInvalid verifies consume with wrong token.
func TestBootstrapConsumeSetupTokenInvalid(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	err = svc.ConsumeSetupToken("wrong-token")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestBootstrapInitialize verifies the full initialization flow.
func TestBootstrapInitialize(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	resp, err := svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "first-admin",
		DisplayName:      "First Admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.UserID)
	assert.Equal(t, "first-admin", resp.Username)
	assert.Equal(t, StateComplete, svc.State())
	assert.True(t, svc.IsInitialized())
}

// TestBootstrapInitializeDefaultDisplayName verifies display name defaults to username.
func TestBootstrapInitializeDefaultDisplayName(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	resp, err := svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin-user",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, "admin-user", resp.Username)

	// Verify user was created with username as display name
	u, err := store.GetByUsername(context.Background(), "admin-user")
	require.NoError(t, err)
	assert.Equal(t, "admin-user", u.DisplayName)
}

// TestBootstrapInitializeAlreadyInitialized verifies error when already initialized.
func TestBootstrapInitializeAlreadyInitialized(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// Second initialization should fail
	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin2",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	assert.ErrorIs(t, err, ErrAlreadyInitialized)
}

// TestBootstrapInitializeNotReady verifies error when not in ready state.
func TestBootstrapInitializeNotReady(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       "some-token",
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	assert.ErrorIs(t, err, ErrNotReady)
}

// TestBootstrapInitializeNilRequest verifies nil request error.
func TestBootstrapInitializeNilRequest(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), nil)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// TestBootstrapInitializeEmptyUsername verifies empty username error.
func TestBootstrapInitializeEmptyUsername(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	assert.ErrorIs(t, err, ErrEmptyUsername)
}

// TestBootstrapInitializeEmptyAttestation verifies empty attestation error.
func TestBootstrapInitializeEmptyAttestation(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken: token.Token,
		Username:   "admin",
	})
	assert.ErrorIs(t, err, ErrEmptyAttestation)
}

// TestBootstrapInitializeInvalidToken verifies wrong token error during initialization.
func TestBootstrapInitializeInvalidToken(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       "wrong-token",
		Username:         "admin",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	assert.ErrorIs(t, err, ErrInvalidToken)
}

// TestBootstrapInitializeAtomicTokenNotConsumedOnFailure verifies that the
// setup token is NOT consumed when user creation fails.
func TestBootstrapInitializeAtomicTokenNotConsumedOnFailure(t *testing.T) {
	// Create a separate service that starts uninitialized
	bootstrapStore := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL: 10 * time.Minute,
	}, bootstrapStore, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	// Pre-create the user in the bootstrap store to force duplicate username error
	_, err = bootstrapStore.Create(context.Background(), "duplicate", "Dup", user.RoleAdmin, "")
	require.NoError(t, err)

	// Attempt initialization with duplicate username
	req := &InitRequest{
		SetupToken:       token.Token,
		Username:         "duplicate",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	}
	_, err = svc.Initialize(context.Background(), req)
	assert.ErrorIs(t, err, ErrUsernameTaken)

	// Token should NOT be consumed -- verify it is not marked used
	assert.False(t, svc.setupToken.Used)
}

// TestBootstrapInitializeThresholdMode verifies threshold mode transitions to Ceremony state.
func TestBootstrapInitializeThresholdMode(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	resp, err := svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.NotEmpty(t, resp.UserID)
	assert.Equal(t, StateCeremony, svc.State())
	assert.False(t, svc.IsInitialized())
}

// TestBootstrapGenerateInvitations verifies invitation generation in ceremony state.
func TestBootstrapGenerateInvitations(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, StateCeremony, svc.State())

	invitations, err := svc.GenerateInvitations(2)
	require.NoError(t, err)
	assert.Len(t, invitations, 2)

	for i, inv := range invitations {
		assert.NotEmpty(t, inv.Token)
		assert.False(t, inv.Used)
		assert.False(t, inv.ExpiresAt.IsZero())
		assert.Equal(t, i+2, inv.AdminIndex)
	}
}

// TestBootstrapGenerateInvitationsNotInCeremony verifies error when not in ceremony state.
func TestBootstrapGenerateInvitationsNotInCeremony(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateInvitations(2)
	assert.ErrorIs(t, err, ErrCeremonyNotStarted)
}

// TestBootstrapGenerateInvitationsInvalidCount verifies error for invalid invitation count.
func TestBootstrapGenerateInvitationsInvalidCount(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	_, err = svc.GenerateInvitations(0)
	assert.ErrorIs(t, err, ErrInvalidRequest)

	_, err = svc.GenerateInvitations(-1)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

// TestBootstrapGenerateInvitationsComplete verifies error when ceremony is complete.
func TestBootstrapGenerateInvitationsComplete(t *testing.T) {
	store := createTestUserStore(t)
	// Pre-create a user so the service starts in Complete state
	_, err := store.Create(context.Background(), "admin", "Admin", user.RoleAdmin, "")
	require.NoError(t, err)

	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	_, err = svc.GenerateInvitations(2)
	assert.ErrorIs(t, err, ErrCeremonyComplete)
}

// TestBootstrapValidateInvitation verifies invitation validation.
func TestBootstrapValidateInvitation(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	invitations, err := svc.GenerateInvitations(1)
	require.NoError(t, err)
	require.Len(t, invitations, 1)

	err = svc.ValidateInvitation(invitations[0].Token)
	assert.NoError(t, err)
}

// TestBootstrapValidateInvitationEmpty verifies empty invitation token error.
func TestBootstrapValidateInvitationEmpty(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	err = svc.ValidateInvitation("")
	assert.ErrorIs(t, err, ErrEmptyToken)
}

// TestBootstrapValidateInvitationInvalid verifies invalid invitation token error.
func TestBootstrapValidateInvitationInvalid(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	err = svc.ValidateInvitation("nonexistent-token")
	assert.ErrorIs(t, err, ErrInvalidInvitation)
}

// TestBootstrapValidateInvitationNotInCeremony verifies error when not in ceremony state.
func TestBootstrapValidateInvitationNotInCeremony(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	err = svc.ValidateInvitation("some-token")
	assert.ErrorIs(t, err, ErrCeremonyNotStarted)
}

// TestBootstrapValidateInvitationComplete verifies error when ceremony is already complete.
func TestBootstrapValidateInvitationComplete(t *testing.T) {
	store := createTestUserStore(t)
	_, err := store.Create(context.Background(), "admin", "Admin", user.RoleAdmin, "")
	require.NoError(t, err)

	svc, err := NewService(Config{}, store, testLogger())
	require.NoError(t, err)

	err = svc.ValidateInvitation("some-token")
	assert.ErrorIs(t, err, ErrCeremonyComplete)
}

// TestBootstrapConsumeInvitation verifies invitation consumption.
func TestBootstrapConsumeInvitation(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	invitations, err := svc.GenerateInvitations(2)
	require.NoError(t, err)
	require.Len(t, invitations, 2)

	// Consume first invitation
	err = svc.ConsumeInvitation(invitations[0].Token)
	assert.NoError(t, err)
	assert.True(t, svc.invitations[invitations[0].Token].Used)

	// Cannot consume same invitation again
	err = svc.ConsumeInvitation(invitations[0].Token)
	assert.ErrorIs(t, err, ErrInvitationUsed)
}

// TestBootstrapConsumeInvitationCompleteCeremony verifies ceremony completion when
// enough admins are registered.
func TestBootstrapConsumeInvitationCompleteCeremony(t *testing.T) {
	userStore := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, userStore, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	// First admin via Initialize
	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, StateCeremony, svc.State())

	invitations, err := svc.GenerateInvitations(2)
	require.NoError(t, err)

	// Second admin
	_, err = userStore.Create(context.Background(), "admin2", "Admin 2", user.RoleAdmin, "")
	require.NoError(t, err)
	err = svc.ConsumeInvitation(invitations[0].Token)
	assert.NoError(t, err)
	assert.Equal(t, StateCeremony, svc.State()) // Not enough admins yet

	// Third admin (reaches AdminTotal=3)
	_, err = userStore.Create(context.Background(), "admin3", "Admin 3", user.RoleAdmin, "")
	require.NoError(t, err)
	err = svc.ConsumeInvitation(invitations[1].Token)
	assert.NoError(t, err)
	assert.Equal(t, StateComplete, svc.State())
	assert.True(t, svc.IsInitialized())
}

// TestBootstrapConsumeInvitationExpired verifies expired invitation error.
func TestBootstrapConsumeInvitationExpired(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// Set very short TTL for invitations
	svc.config.TokenTTL = 1 * time.Nanosecond
	invitations, err := svc.GenerateInvitations(1)
	require.NoError(t, err)

	// Wait for invitation to expire
	time.Sleep(5 * time.Millisecond)

	err = svc.ConsumeInvitation(invitations[0].Token)
	assert.ErrorIs(t, err, ErrInvitationExpired)
}

// TestBootstrapGenerateSetupTokenDuringCeremony verifies that setup token cannot
// be generated during ceremony state.
func TestBootstrapGenerateSetupTokenDuringCeremony(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     3,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)
	assert.Equal(t, StateCeremony, svc.State())

	_, err = svc.GenerateSetupToken()
	assert.ErrorIs(t, err, ErrNotReady)
}

// TestBootstrapMultipleInvitationBatches verifies generating multiple batches
// of invitations with correct admin indices.
func TestBootstrapMultipleInvitationBatches(t *testing.T) {
	store := createTestUserStore(t)
	svc, err := NewService(Config{
		TokenTTL:       10 * time.Minute,
		ThresholdMode:  true,
		AdminThreshold: 2,
		AdminTotal:     5,
	}, store, testLogger())
	require.NoError(t, err)

	token, err := svc.GenerateSetupToken()
	require.NoError(t, err)

	_, err = svc.Initialize(context.Background(), &InitRequest{
		SetupToken:       token.Token,
		Username:         "admin1",
		FIDO2Attestation: json.RawMessage(`{"test":"data"}`),
	})
	require.NoError(t, err)

	// First batch of 2 invitations
	batch1, err := svc.GenerateInvitations(2)
	require.NoError(t, err)
	assert.Len(t, batch1, 2)
	assert.Equal(t, 2, batch1[0].AdminIndex)
	assert.Equal(t, 3, batch1[1].AdminIndex)

	// Second batch of 2 invitations
	batch2, err := svc.GenerateInvitations(2)
	require.NoError(t, err)
	assert.Len(t, batch2, 2)
	assert.Equal(t, 4, batch2[0].AdminIndex)
	assert.Equal(t, 5, batch2[1].AdminIndex)
}
