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
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
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
		{"enabled user", RoleUser, true, true},
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
		{RoleCustodian, true},
		{RoleSO, true},
		{Role("readonly"), false},
		{Role("guest"), false},
		{Role("invalid"), false},
		{Role(""), false},
	}

	for _, tt := range tests {
		t.Run(string(tt.role), func(t *testing.T) {
			assert.Equal(t, tt.expected, IsValidRole(tt.role))
		})
	}
}

func TestRoleSO_IsValid(t *testing.T) {
	assert.True(t, IsValidRole(RoleSO), "RoleSO should be a valid role")
	assert.Equal(t, Role("so"), RoleSO, "RoleSO should have value 'so'")
}

func TestUser_AddCertBinding(t *testing.T) {
	u := &User{CertBindings: []CertBinding{}}

	binding := &CertBinding{
		Fingerprint: "abc123",
		Subject:     "CN=test",
		Issuer:      "CN=ca",
		Serial:      "1",
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		Name:        "Test Cert",
		CreatedAt:   time.Now().UTC(),
	}

	u.AddCertBinding(binding)
	require.Len(t, u.CertBindings, 1)
	assert.Equal(t, "abc123", u.CertBindings[0].Fingerprint)
	assert.Equal(t, "Test Cert", u.CertBindings[0].Name)
}

func TestUser_RemoveCertBinding(t *testing.T) {
	t.Run("removes existing binding", func(t *testing.T) {
		u := &User{CertBindings: []CertBinding{
			{Fingerprint: "aaa"},
			{Fingerprint: "bbb"},
			{Fingerprint: "ccc"},
		}}

		removed := u.RemoveCertBinding("bbb")
		assert.True(t, removed)
		require.Len(t, u.CertBindings, 2)
		assert.Equal(t, "aaa", u.CertBindings[0].Fingerprint)
		assert.Equal(t, "ccc", u.CertBindings[1].Fingerprint)
	})

	t.Run("returns false for nonexistent binding", func(t *testing.T) {
		u := &User{CertBindings: []CertBinding{{Fingerprint: "aaa"}}}
		removed := u.RemoveCertBinding("nonexistent")
		assert.False(t, removed)
		require.Len(t, u.CertBindings, 1)
	})
}

func TestUser_GetCertBinding(t *testing.T) {
	t.Run("returns existing binding", func(t *testing.T) {
		u := &User{CertBindings: []CertBinding{
			{Fingerprint: "aaa", Name: "First"},
			{Fingerprint: "bbb", Name: "Second"},
		}}

		binding := u.GetCertBinding("bbb")
		require.NotNil(t, binding)
		assert.Equal(t, "Second", binding.Name)
	})

	t.Run("returns nil for nonexistent binding", func(t *testing.T) {
		u := &User{CertBindings: []CertBinding{{Fingerprint: "aaa"}}}
		binding := u.GetCertBinding("nonexistent")
		assert.Nil(t, binding)
	})
}

func TestUser_HasCertBinding(t *testing.T) {
	u := &User{CertBindings: []CertBinding{{Fingerprint: "aaa"}}}
	assert.True(t, u.HasCertBinding("aaa"))
	assert.False(t, u.HasCertBinding("bbb"))
}

func TestUser_HasAnyRole(t *testing.T) {
	t.Run("matches primary role", func(t *testing.T) {
		u := &User{Role: RoleAdmin}
		assert.True(t, u.HasAnyRole(RoleAdmin))
		assert.True(t, u.HasAnyRole(RoleOperator, RoleAdmin))
		assert.False(t, u.HasAnyRole(RoleOperator, RoleUser))
	})

	t.Run("matches role in Roles slice", func(t *testing.T) {
		u := &User{
			Role:  RoleOperator,
			Roles: []Role{RoleCustodian, RoleAuditor},
		}
		assert.True(t, u.HasAnyRole(RoleCustodian))
		assert.True(t, u.HasAnyRole(RoleAuditor))
		assert.True(t, u.HasAnyRole(RoleOperator))
		assert.False(t, u.HasAnyRole(RoleAdmin))
	})

	t.Run("returns false with no roles", func(t *testing.T) {
		u := &User{}
		assert.False(t, u.HasAnyRole(RoleAdmin))
	})

	t.Run("returns false with empty arguments", func(t *testing.T) {
		u := &User{Role: RoleAdmin}
		assert.False(t, u.HasAnyRole())
	})

	t.Run("checks both primary and additional roles", func(t *testing.T) {
		u := &User{
			Role:  RoleUser,
			Roles: []Role{RoleCustodian},
		}
		assert.True(t, u.HasAnyRole(RoleUser))
		assert.True(t, u.HasAnyRole(RoleCustodian))
		assert.False(t, u.HasAnyRole(RoleAdmin, RoleOperator))
	})
}

func TestUser_CanParticipateCeremony(t *testing.T) {
	t.Run("enabled custodian with primary role", func(t *testing.T) {
		u := &User{Role: RoleCustodian, Enabled: true}
		assert.True(t, u.CanParticipateCeremony())
	})

	t.Run("enabled custodian with role in Roles slice", func(t *testing.T) {
		u := &User{
			Role:    RoleOperator,
			Roles:   []Role{RoleCustodian},
			Enabled: true,
		}
		assert.True(t, u.CanParticipateCeremony())
	})

	t.Run("disabled custodian cannot participate", func(t *testing.T) {
		u := &User{Role: RoleCustodian, Enabled: false}
		assert.False(t, u.CanParticipateCeremony())
	})

	t.Run("non-custodian cannot participate", func(t *testing.T) {
		u := &User{Role: RoleAdmin, Enabled: true}
		assert.False(t, u.CanParticipateCeremony())
	})

	t.Run("non-custodian with roles cannot participate", func(t *testing.T) {
		u := &User{
			Role:    RoleAdmin,
			Roles:   []Role{RoleOperator, RoleAuditor},
			Enabled: true,
		}
		assert.False(t, u.CanParticipateCeremony())
	})

	t.Run("disabled user with custodian in Roles cannot participate", func(t *testing.T) {
		u := &User{
			Role:    RoleUser,
			Roles:   []Role{RoleCustodian},
			Enabled: false,
		}
		assert.False(t, u.CanParticipateCeremony())
	})
}

func TestUser_TenantID(t *testing.T) {
	t.Run("system-level user has empty tenant ID", func(t *testing.T) {
		u := &User{Username: "system-user"}
		assert.Equal(t, "", u.TenantID)
	})

	t.Run("tenant-scoped user has tenant ID", func(t *testing.T) {
		u := &User{Username: "tenant-user", TenantID: "tenant-123"}
		assert.Equal(t, "tenant-123", u.TenantID)
	})
}

func TestUser_CanInitializeModule(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanInitializeModule())
		})
	}
}

func TestUser_CanSignCSR(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanSignCSR())
		})
	}
}

func TestUser_CanManageSecurityPolicy(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanManageSecurityPolicy())
		})
	}
}

func TestUser_CanZeroize(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanZeroize())
		})
	}
}

func TestUser_CanResetPIN(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanResetPIN())
		})
	}
}

func TestUser_CanManageTenants(t *testing.T) {
	tests := []struct {
		name     string
		role     Role
		enabled  bool
		expected bool
	}{
		{"enabled SO", RoleSO, true, true},
		{"disabled SO", RoleSO, false, false},
		{"enabled admin", RoleAdmin, true, true},
		{"disabled admin", RoleAdmin, false, false},
		{"enabled operator", RoleOperator, true, false},
		{"enabled user", RoleUser, true, false},
		{"enabled custodian", RoleCustodian, true, false},
		{"enabled auditor", RoleAuditor, true, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &User{Role: tt.role, Enabled: tt.enabled}
			assert.Equal(t, tt.expected, u.CanManageTenants())
		})
	}
}

func TestUser_CanManageUsers_IncludesSO(t *testing.T) {
	t.Run("SO can manage users", func(t *testing.T) {
		u := &User{Role: RoleSO, Enabled: true}
		assert.True(t, u.CanManageUsers())
	})

	t.Run("admin can manage users", func(t *testing.T) {
		u := &User{Role: RoleAdmin, Enabled: true}
		assert.True(t, u.CanManageUsers())
	})

	t.Run("operator cannot manage users", func(t *testing.T) {
		u := &User{Role: RoleOperator, Enabled: true}
		assert.False(t, u.CanManageUsers())
	})

	t.Run("disabled SO cannot manage users", func(t *testing.T) {
		u := &User{Role: RoleSO, Enabled: false}
		assert.False(t, u.CanManageUsers())
	})
}

func TestSOCannotUseKeys(t *testing.T) {
	t.Run("SO cannot use keys for crypto operations", func(t *testing.T) {
		u := &User{Role: RoleSO, Enabled: true}
		assert.False(t, u.CanUseKeys(), "SO should NOT be able to use keys for cryptographic operations")
	})

	t.Run("SO cannot manage keys", func(t *testing.T) {
		u := &User{Role: RoleSO, Enabled: true}
		assert.False(t, u.CanManageKeys(), "SO should NOT be able to manage keys")
	})

	t.Run("SO can list keys", func(t *testing.T) {
		u := &User{Role: RoleSO, Enabled: true}
		assert.True(t, u.CanListKeys(), "SO should be able to list keys")
	})
}
