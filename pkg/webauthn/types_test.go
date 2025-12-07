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
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateUserID(t *testing.T) {
	tests := []struct {
		name  string
		email string
	}{
		{
			name:  "simple email",
			email: "test@example.com",
		},
		{
			name:  "complex email",
			email: "user.name+tag@subdomain.example.com",
		},
		{
			name:  "empty email",
			email: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id := GenerateUserID(tt.email)
			assert.Len(t, id, 8, "user ID should be 8 bytes")

			// Verify determinism
			id2 := GenerateUserID(tt.email)
			assert.Equal(t, id, id2, "same email should produce same ID")
		})
	}

	// Test that different emails produce different IDs
	id1 := GenerateUserID("user1@example.com")
	id2 := GenerateUserID("user2@example.com")
	assert.NotEqual(t, id1, id2, "different emails should produce different IDs")
}

func TestNewDefaultUser(t *testing.T) {
	id := []byte{1, 2, 3, 4, 5, 6, 7, 8}
	email := "test@example.com"
	displayName := "Test User"

	user := NewDefaultUser(id, email, displayName)

	assert.Equal(t, id, user.WebAuthnID())
	assert.Equal(t, email, user.WebAuthnName())
	assert.Equal(t, displayName, user.WebAuthnDisplayName())
	assert.Equal(t, email, user.Email())
	assert.Equal(t, displayName, user.DisplayName())
	assert.Empty(t, user.WebAuthnCredentials())
	assert.Nil(t, user.SessionData())
}

func TestNewDefaultUserFromEmail(t *testing.T) {
	email := "test@example.com"
	displayName := "Test User"

	user := NewDefaultUserFromEmail(email, displayName)

	assert.NotNil(t, user.WebAuthnID())
	assert.Len(t, user.WebAuthnID(), 8)
	assert.Equal(t, email, user.WebAuthnName())
	assert.Equal(t, displayName, user.WebAuthnDisplayName())
}

func TestDefaultUser_WebAuthnDisplayName_DefaultsToEmail(t *testing.T) {
	email := "test@example.com"
	user := NewDefaultUserFromEmail(email, "")

	assert.Equal(t, email, user.WebAuthnDisplayName())
}

func TestDefaultUser_Credentials(t *testing.T) {
	user := NewDefaultUserFromEmail("test@example.com", "Test")

	// Initially empty
	assert.Empty(t, user.WebAuthnCredentials())
	assert.Empty(t, user.Credentials())

	// Add credential
	cred1 := &Credential{
		ID:        []byte{1, 2, 3},
		UserID:    user.WebAuthnID(),
		PublicKey: []byte{4, 5, 6},
	}
	user.AddCredential(cred1)

	assert.Len(t, user.WebAuthnCredentials(), 1)
	assert.Len(t, user.Credentials(), 1)

	// Add another credential
	cred2 := &Credential{
		ID:        []byte{7, 8, 9},
		UserID:    user.WebAuthnID(),
		PublicKey: []byte{10, 11, 12},
	}
	user.AddCredential(cred2)

	assert.Len(t, user.WebAuthnCredentials(), 2)

	// Update credential
	cred1.Authenticator.SignCount = 5
	user.UpdateCredential(cred1)

	creds := user.Credentials()
	require.Len(t, creds, 2)
	assert.Equal(t, uint32(5), creds[0].Authenticator.SignCount)

	// Update non-existent credential (should not add)
	nonExistent := &Credential{
		ID: []byte{99, 99, 99},
	}
	user.UpdateCredential(nonExistent)
	assert.Len(t, user.Credentials(), 2)
}

func TestDefaultUser_SessionData(t *testing.T) {
	user := NewDefaultUserFromEmail("test@example.com", "Test")

	assert.Nil(t, user.SessionData())

	data := []byte("session data")
	user.SetSessionData(data)

	assert.Equal(t, data, user.SessionData())
}

func TestDefaultUser_SetCredentials(t *testing.T) {
	user := NewDefaultUserFromEmail("test@example.com", "Test")

	creds := []*Credential{
		{ID: []byte{1}},
		{ID: []byte{2}},
	}
	user.SetCredentials(creds)

	assert.Len(t, user.Credentials(), 2)
}

func TestCredential_ToWebAuthn(t *testing.T) {
	cred := &Credential{
		ID:              []byte{1, 2, 3},
		UserID:          []byte{4, 5, 6},
		PublicKey:       []byte{7, 8, 9},
		AttestationType: "none",
		Transport:       []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC},
		Flags: CredentialFlags{
			UserPresent:    true,
			UserVerified:   true,
			BackupEligible: false,
			BackupState:    false,
		},
		Authenticator: AuthenticatorData{
			AAGUID:       []byte{10, 11, 12},
			SignCount:    42,
			CloneWarning: false,
			Attachment:   protocol.Platform,
		},
	}

	wc := cred.ToWebAuthn()

	assert.Equal(t, cred.ID, wc.ID)
	assert.Equal(t, cred.PublicKey, wc.PublicKey)
	assert.Equal(t, cred.AttestationType, wc.AttestationType)
	assert.Equal(t, cred.Transport, wc.Transport)
	assert.Equal(t, cred.Flags.UserPresent, wc.Flags.UserPresent)
	assert.Equal(t, cred.Flags.UserVerified, wc.Flags.UserVerified)
	assert.Equal(t, cred.Authenticator.AAGUID, wc.Authenticator.AAGUID)
	assert.Equal(t, cred.Authenticator.SignCount, wc.Authenticator.SignCount)
}

func TestFromWebAuthnCredential(t *testing.T) {
	userID := []byte{1, 2, 3}
	wc := &webauthn.Credential{
		ID:              []byte{4, 5, 6},
		PublicKey:       []byte{7, 8, 9},
		AttestationType: "direct",
		Transport:       []protocol.AuthenticatorTransport{protocol.BLE},
		Flags: webauthn.CredentialFlags{
			UserPresent:    true,
			UserVerified:   false,
			BackupEligible: true,
			BackupState:    true,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       []byte{10, 11, 12},
			SignCount:    100,
			CloneWarning: true,
			Attachment:   protocol.CrossPlatform,
		},
	}

	cred := FromWebAuthnCredential(userID, wc)

	assert.Equal(t, wc.ID, cred.ID)
	assert.Equal(t, userID, cred.UserID)
	assert.Equal(t, wc.PublicKey, cred.PublicKey)
	assert.Equal(t, wc.AttestationType, cred.AttestationType)
	assert.Equal(t, wc.Transport, cred.Transport)
	assert.Equal(t, wc.Flags.UserPresent, cred.Flags.UserPresent)
	assert.Equal(t, wc.Flags.UserVerified, cred.Flags.UserVerified)
	assert.Equal(t, wc.Flags.BackupEligible, cred.Flags.BackupEligible)
	assert.Equal(t, wc.Flags.BackupState, cred.Flags.BackupState)
	assert.Equal(t, wc.Authenticator.AAGUID, cred.Authenticator.AAGUID)
	assert.Equal(t, wc.Authenticator.SignCount, cred.Authenticator.SignCount)
	assert.Equal(t, wc.Authenticator.CloneWarning, cred.Authenticator.CloneWarning)
	assert.Equal(t, wc.Authenticator.Attachment, cred.Authenticator.Attachment)
	assert.WithinDuration(t, time.Now(), cred.CreatedAt, time.Second)
}
