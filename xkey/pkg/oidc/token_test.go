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

package oidc

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTokenResponse_IsExpired(t *testing.T) {
	t.Run("not expired when expiry is in the future", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Now().Add(1 * time.Hour),
		}
		assert.False(t, token.IsExpired())
	})

	t.Run("expired when expiry is in the past", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Now().Add(-1 * time.Hour),
		}
		assert.True(t, token.IsExpired())
	})

	t.Run("expired with 10 second buffer", func(t *testing.T) {
		// Token expires in 5 seconds, but with 10 second buffer it's considered expired
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Now().Add(5 * time.Second),
		}
		assert.True(t, token.IsExpired())
	})

	t.Run("not expired when no expiry set", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
		}
		assert.False(t, token.IsExpired())
	})

	t.Run("not expired with zero expiry", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Time{},
		}
		assert.False(t, token.IsExpired())
	})
}

func TestTokenResponse_Valid(t *testing.T) {
	t.Run("valid with access token and not expired", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Now().Add(1 * time.Hour),
		}
		assert.True(t, token.Valid())
	})

	t.Run("invalid when access token is empty", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "",
			Expiry:      time.Now().Add(1 * time.Hour),
		}
		assert.False(t, token.Valid())
	})

	t.Run("invalid when expired", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
			Expiry:      time.Now().Add(-1 * time.Hour),
		}
		assert.False(t, token.Valid())
	})

	t.Run("valid when no expiry set", func(t *testing.T) {
		token := &TokenResponse{
			AccessToken: "test-token",
		}
		assert.True(t, token.Valid())
	})
}

func TestAudience_Contains(t *testing.T) {
	t.Run("contains single audience", func(t *testing.T) {
		aud := Audience{"client-123"}
		assert.True(t, aud.Contains("client-123"))
		assert.False(t, aud.Contains("other-client"))
	})

	t.Run("contains multiple audiences", func(t *testing.T) {
		aud := Audience{"client-1", "client-2", "client-3"}
		assert.True(t, aud.Contains("client-1"))
		assert.True(t, aud.Contains("client-2"))
		assert.True(t, aud.Contains("client-3"))
		assert.False(t, aud.Contains("client-4"))
	})

	t.Run("empty audience", func(t *testing.T) {
		aud := Audience{}
		assert.False(t, aud.Contains("any"))
	})

	t.Run("nil audience", func(t *testing.T) {
		var aud Audience
		assert.False(t, aud.Contains("any"))
	})
}

func TestIDTokenClaims_ExpiryTime(t *testing.T) {
	claims := &IDTokenClaims{
		Expiry: 1704067200, // 2024-01-01 00:00:00 UTC
	}
	expected := time.Unix(1704067200, 0)
	assert.Equal(t, expected, claims.ExpiryTime())
}

func TestIDTokenClaims_IssuedAtTime(t *testing.T) {
	claims := &IDTokenClaims{
		IssuedAt: 1704067200, // 2024-01-01 00:00:00 UTC
	}
	expected := time.Unix(1704067200, 0)
	assert.Equal(t, expected, claims.IssuedAtTime())
}

func TestIDTokenClaims_AuthenticationTime(t *testing.T) {
	claims := &IDTokenClaims{
		AuthTime: 1704067200, // 2024-01-01 00:00:00 UTC
	}
	expected := time.Unix(1704067200, 0)
	assert.Equal(t, expected, claims.AuthenticationTime())
}

func TestIDTokenClaims_IsExpired(t *testing.T) {
	t.Run("not expired when expiry is in the future", func(t *testing.T) {
		claims := &IDTokenClaims{
			Expiry: time.Now().Add(1 * time.Hour).Unix(),
		}
		assert.False(t, claims.IsExpired())
	})

	t.Run("expired when expiry is in the past", func(t *testing.T) {
		claims := &IDTokenClaims{
			Expiry: time.Now().Add(-1 * time.Hour).Unix(),
		}
		assert.True(t, claims.IsExpired())
	})

	t.Run("expired when expiry is zero", func(t *testing.T) {
		claims := &IDTokenClaims{
			Expiry: 0,
		}
		// Unix epoch (0) is in the past
		assert.True(t, claims.IsExpired())
	})
}

func TestIDTokenClaims_AllFields(t *testing.T) {
	now := time.Now()
	claims := &IDTokenClaims{
		Issuer:              "https://auth.example.com",
		Subject:             "user-123",
		Audience:            Audience{"client-456"},
		Expiry:              now.Add(1 * time.Hour).Unix(),
		IssuedAt:            now.Unix(),
		AuthTime:            now.Add(-5 * time.Minute).Unix(),
		Nonce:               "nonce-789",
		AuthorizedParty:     "client-456",
		AccessTokenHash:     "at_hash_value",
		CodeHash:            "c_hash_value",
		ACR:                 "urn:mace:incommon:iap:silver",
		AMR:                 []string{"pwd", "mfa"},
		Email:               "user@example.com",
		EmailVerified:       true,
		Name:                "Test User",
		GivenName:           "Test",
		FamilyName:          "User",
		PreferredUsername:   "testuser",
		Picture:             "https://example.com/photo.jpg",
		Profile:             "https://example.com/profile",
		Locale:              "en-US",
		Zoneinfo:            "America/New_York",
		UpdatedAt:           now.Unix(),
		PhoneNumber:         "+1234567890",
		PhoneNumberVerified: true,
		Address: &Address{
			Formatted:     "123 Main St, City, Country",
			StreetAddress: "123 Main St",
			Locality:      "City",
			Region:        "State",
			PostalCode:    "12345",
			Country:       "Country",
		},
		Extra: map[string]interface{}{
			"custom_claim": "custom_value",
		},
	}

	assert.Equal(t, "https://auth.example.com", claims.Issuer)
	assert.Equal(t, "user-123", claims.Subject)
	assert.True(t, claims.Audience.Contains("client-456"))
	assert.False(t, claims.IsExpired())
	assert.Equal(t, "nonce-789", claims.Nonce)
	assert.Equal(t, "client-456", claims.AuthorizedParty)
	assert.Equal(t, "user@example.com", claims.Email)
	assert.True(t, claims.EmailVerified)
	assert.Equal(t, "Test User", claims.Name)
	assert.Equal(t, "Test", claims.GivenName)
	assert.Equal(t, "User", claims.FamilyName)
	assert.Equal(t, "testuser", claims.PreferredUsername)
	assert.Equal(t, "+1234567890", claims.PhoneNumber)
	assert.True(t, claims.PhoneNumberVerified)
	assert.NotNil(t, claims.Address)
	assert.Equal(t, "123 Main St", claims.Address.StreetAddress)
	assert.Contains(t, claims.AMR, "pwd")
	assert.Contains(t, claims.AMR, "mfa")
	assert.Equal(t, "custom_value", claims.Extra["custom_claim"])
}

func TestAddress_AllFields(t *testing.T) {
	addr := &Address{
		Formatted:     "123 Main St, City, State 12345, Country",
		StreetAddress: "123 Main St",
		Locality:      "City",
		Region:        "State",
		PostalCode:    "12345",
		Country:       "Country",
	}

	assert.Equal(t, "123 Main St, City, State 12345, Country", addr.Formatted)
	assert.Equal(t, "123 Main St", addr.StreetAddress)
	assert.Equal(t, "City", addr.Locality)
	assert.Equal(t, "State", addr.Region)
	assert.Equal(t, "12345", addr.PostalCode)
	assert.Equal(t, "Country", addr.Country)
}

func TestUserInfo_AllFields(t *testing.T) {
	userInfo := &UserInfo{
		Subject:           "user-123",
		Name:              "Test User",
		GivenName:         "Test",
		FamilyName:        "User",
		PreferredUsername: "testuser",
		Email:             "user@example.com",
		EmailVerified:     true,
		Picture:           "https://example.com/photo.jpg",
		Profile:           "https://example.com/profile",
		Locale:            "en-US",
		Zoneinfo:          "America/New_York",
		Address: Address{
			Formatted: "123 Main St",
		},
	}

	assert.Equal(t, "user-123", userInfo.Subject)
	assert.Equal(t, "Test User", userInfo.Name)
	assert.Equal(t, "Test", userInfo.GivenName)
	assert.Equal(t, "User", userInfo.FamilyName)
	assert.Equal(t, "testuser", userInfo.PreferredUsername)
	assert.Equal(t, "user@example.com", userInfo.Email)
	assert.True(t, userInfo.EmailVerified)
	assert.Equal(t, "https://example.com/photo.jpg", userInfo.Picture)
	assert.Equal(t, "123 Main St", userInfo.Address.Formatted)
}

func TestTokenResponse_AllFields(t *testing.T) {
	expiry := time.Now().Add(1 * time.Hour)
	token := &TokenResponse{
		AccessToken:  "access-token-123",
		TokenType:    "Bearer",
		RefreshToken: "refresh-token-456",
		ExpiresIn:    3600,
		IDToken:      "id-token-789",
		Scope:        "openid profile email",
		Expiry:       expiry,
	}

	assert.Equal(t, "access-token-123", token.AccessToken)
	assert.Equal(t, "Bearer", token.TokenType)
	assert.Equal(t, "refresh-token-456", token.RefreshToken)
	assert.Equal(t, 3600, token.ExpiresIn)
	assert.Equal(t, "id-token-789", token.IDToken)
	assert.Equal(t, "openid profile email", token.Scope)
	assert.Equal(t, expiry, token.Expiry)
	assert.True(t, token.Valid())
}
