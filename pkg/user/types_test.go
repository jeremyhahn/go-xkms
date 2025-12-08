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

package user

import (
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUser_WebAuthnID(t *testing.T) {
	user := &User{ID: []byte("test-id")}
	assert.Equal(t, []byte("test-id"), user.WebAuthnID())
}

func TestUser_WebAuthnName(t *testing.T) {
	user := &User{Username: "testuser@example.com"}
	assert.Equal(t, "testuser@example.com", user.WebAuthnName())
}

func TestUser_WebAuthnDisplayName(t *testing.T) {
	t.Run("with display name", func(t *testing.T) {
		user := &User{
			Username:    "testuser@example.com",
			DisplayName: "Test User",
		}
		assert.Equal(t, "Test User", user.WebAuthnDisplayName())
	})

	t.Run("without display name falls back to username", func(t *testing.T) {
		user := &User{
			Username:    "testuser@example.com",
			DisplayName: "",
		}
		assert.Equal(t, "testuser@example.com", user.WebAuthnDisplayName())
	})
}

func TestUser_WebAuthnCredentials(t *testing.T) {
	user := &User{
		Credentials: []Credential{
			{
				ID:              []byte("cred-1"),
				PublicKey:       []byte("pubkey-1"),
				AttestationType: "none",
				AAGUID:          []byte("aaguid-1"),
				SignCount:       5,
			},
			{
				ID:              []byte("cred-2"),
				PublicKey:       []byte("pubkey-2"),
				AttestationType: "direct",
				AAGUID:          []byte("aaguid-2"),
				SignCount:       10,
			},
		},
	}

	creds := user.WebAuthnCredentials()
	require.Len(t, creds, 2)

	assert.Equal(t, []byte("cred-1"), creds[0].ID)
	assert.Equal(t, []byte("pubkey-1"), creds[0].PublicKey)
	assert.Equal(t, "none", creds[0].AttestationType)
	assert.Equal(t, []byte("aaguid-1"), creds[0].Authenticator.AAGUID)
	assert.Equal(t, uint32(5), creds[0].Authenticator.SignCount)

	assert.Equal(t, []byte("cred-2"), creds[1].ID)
}

func TestUser_AddCredential(t *testing.T) {
	user := &User{Credentials: []Credential{}}

	cred := &Credential{
		ID:        []byte("new-cred"),
		PublicKey: []byte("pubkey"),
		Name:      "My Key",
	}

	user.AddCredential(cred)
	require.Len(t, user.Credentials, 1)
	assert.Equal(t, []byte("new-cred"), user.Credentials[0].ID)
	assert.Equal(t, "My Key", user.Credentials[0].Name)
}

func TestUser_UpdateCredential(t *testing.T) {
	now := time.Now().UTC()
	user := &User{
		Credentials: []Credential{
			{ID: []byte("cred-1"), SignCount: 5},
			{ID: []byte("cred-2"), SignCount: 10},
		},
	}

	user.UpdateCredential([]byte("cred-1"), 15)

	assert.Equal(t, uint32(15), user.Credentials[0].SignCount)
	assert.NotNil(t, user.Credentials[0].LastUsedAt)
	assert.True(t, user.Credentials[0].LastUsedAt.After(now.Add(-time.Second)))

	// Second credential should remain unchanged
	assert.Equal(t, uint32(10), user.Credentials[1].SignCount)
	assert.Nil(t, user.Credentials[1].LastUsedAt)
}

func TestUser_UpdateCredential_NotFound(t *testing.T) {
	user := &User{
		Credentials: []Credential{
			{ID: []byte("cred-1"), SignCount: 5},
		},
	}

	// Should not panic when credential not found
	user.UpdateCredential([]byte("nonexistent"), 15)
	assert.Equal(t, uint32(5), user.Credentials[0].SignCount)
}

func TestUser_RemoveCredential(t *testing.T) {
	t.Run("removes existing credential", func(t *testing.T) {
		user := &User{
			Credentials: []Credential{
				{ID: []byte("cred-1")},
				{ID: []byte("cred-2")},
				{ID: []byte("cred-3")},
			},
		}

		removed := user.RemoveCredential([]byte("cred-2"))
		assert.True(t, removed)
		require.Len(t, user.Credentials, 2)
		assert.Equal(t, []byte("cred-1"), user.Credentials[0].ID)
		assert.Equal(t, []byte("cred-3"), user.Credentials[1].ID)
	})

	t.Run("returns false for nonexistent credential", func(t *testing.T) {
		user := &User{
			Credentials: []Credential{
				{ID: []byte("cred-1")},
			},
		}

		removed := user.RemoveCredential([]byte("nonexistent"))
		assert.False(t, removed)
		require.Len(t, user.Credentials, 1)
	})
}

func TestUser_GetCredential(t *testing.T) {
	t.Run("returns existing credential", func(t *testing.T) {
		user := &User{
			Credentials: []Credential{
				{ID: []byte("cred-1"), Name: "First"},
				{ID: []byte("cred-2"), Name: "Second"},
			},
		}

		cred := user.GetCredential([]byte("cred-2"))
		require.NotNil(t, cred)
		assert.Equal(t, "Second", cred.Name)
	})

	t.Run("returns nil for nonexistent credential", func(t *testing.T) {
		user := &User{
			Credentials: []Credential{
				{ID: []byte("cred-1")},
			},
		}

		cred := user.GetCredential([]byte("nonexistent"))
		assert.Nil(t, cred)
	})
}

func TestUser_SessionData(t *testing.T) {
	user := &User{}

	assert.Nil(t, user.SessionData())

	testData := []byte("session-data-content")
	user.SetSessionData(testData)
	assert.Equal(t, testData, user.SessionData())
}

func TestUser_HasRole(t *testing.T) {
	user := &User{Role: RoleAdmin}

	assert.True(t, user.HasRole(RoleAdmin))
	assert.False(t, user.HasRole(RoleOperator))
	assert.False(t, user.HasRole(RoleUser))
}

func TestUser_IsAdmin(t *testing.T) {
	t.Run("admin user", func(t *testing.T) {
		user := &User{Role: RoleAdmin}
		assert.True(t, user.IsAdmin())
	})

	t.Run("non-admin user", func(t *testing.T) {
		user := &User{Role: RoleOperator}
		assert.False(t, user.IsAdmin())
	})
}

func TestUser_CanManageUsers(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled admin", RoleAdmin, true, true},
		{"disabled admin", RoleAdmin, false, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, user.CanManageUsers())
		})
	}
}

func TestUser_CanManageKeys(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled admin", RoleAdmin, true, true},
		{"enabled operator", RoleOperator, true, true},
		{"disabled admin", RoleAdmin, false, false},
		{"enabled user", RoleUser, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, user.CanManageKeys())
		})
	}
}

func TestUser_CanUseKeys(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled admin", RoleAdmin, true, true},
		{"enabled operator", RoleOperator, true, true},
		{"enabled user", RoleUser, true, true},
		{"enabled auditor", RoleAuditor, true, false},
		{"disabled admin", RoleAdmin, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, user.CanUseKeys())
		})
	}
}

func TestUser_CanViewAuditLogs(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled admin", RoleAdmin, true, true},
		{"enabled operator", RoleOperator, true, true},
		{"enabled auditor", RoleAuditor, true, true},
		{"enabled user", RoleUser, true, false},
		{"disabled admin", RoleAdmin, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, user.CanViewAuditLogs())
		})
	}
}

func TestUser_CanListKeys(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled admin", RoleAdmin, true, true},
		{"enabled guest", RoleGuest, true, true},
		{"disabled admin", RoleAdmin, false, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, user.CanListKeys())
		})
	}
}

func TestNewCredentialFromWebAuthn(t *testing.T) {
	webAuthnCred := &webauthn.Credential{
		ID:              []byte("cred-id"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "direct",
		Authenticator: webauthn.Authenticator{
			AAGUID:    []byte("aaguid"),
			SignCount: 42,
		},
	}

	cred := NewCredentialFromWebAuthn(webAuthnCred, "My Security Key", []byte("salt"))

	assert.Equal(t, []byte("cred-id"), cred.ID)
	assert.Equal(t, []byte("pubkey"), cred.PublicKey)
	assert.Equal(t, "direct", cred.AttestationType)
	assert.Equal(t, []byte("aaguid"), cred.AAGUID)
	assert.Equal(t, uint32(42), cred.SignCount)
	assert.Equal(t, "My Security Key", cred.Name)
	assert.Equal(t, []byte("salt"), cred.Salt)
	assert.False(t, cred.CreatedAt.IsZero())
}

func TestIsValidRole(t *testing.T) {
	tests := []struct {
		role     Role
		expected bool
	}{
		{RoleAdmin, true},
		{RoleOperator, true},
		{RoleAuditor, true},
		{RoleUser, true},
		{RoleReadOnly, true},
		{RoleGuest, true},
		{Role("invalid"), false},
		{Role(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidRole(tt.role))
		})
	}
}
