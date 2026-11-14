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

package fido2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name        string
		config      Config
		expectError bool
		checkFields func(*testing.T, *Config)
	}{
		{
			name:        "valid default config",
			config:      DefaultConfig,
			expectError: false,
		},
		{
			name: "zero timeout gets default",
			config: Config{
				Timeout: 0,
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultTimeout, c.Timeout)
			},
		},
		{
			name: "negative retry count gets default",
			config: Config{
				RetryCount: -1,
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, DefaultRetryCount, c.RetryCount)
			},
		},
		{
			name: "empty RP ID gets default",
			config: Config{
				RelyingPartyID: "",
			},
			expectError: false,
			checkFields: func(t *testing.T, c *Config) {
				assert.Equal(t, "go-xkms", c.RelyingPartyID)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				if tt.checkFields != nil {
					tt.checkFields(t, &tt.config)
				}
			}
		})
	}
}

func TestDefaultPublicKeyCredentialParameters(t *testing.T) {
	params := DefaultPublicKeyCredentialParameters()

	require.NotEmpty(t, params)
	assert.GreaterOrEqual(t, len(params), 3)

	// Check for common algorithms
	hasES256 := false
	hasRS256 := false

	for _, param := range params {
		assert.Equal(t, "public-key", param.Type)
		if param.Alg == COSEAlgES256 {
			hasES256 = true
		}
		if param.Alg == COSEAlgRS256 {
			hasRS256 = true
		}
	}

	assert.True(t, hasES256, "should include ES256 algorithm")
	assert.True(t, hasRS256, "should include RS256 algorithm")
}

func TestCreateClientDataHash(t *testing.T) {
	challenge := []byte("test challenge data")
	hash := CreateClientDataHash(challenge)

	assert.NotNil(t, hash)
	assert.Equal(t, 32, len(hash), "SHA-256 hash should be 32 bytes")

	// Same input should produce same hash
	hash2 := CreateClientDataHash(challenge)
	assert.Equal(t, hash, hash2)

	// Different input should produce different hash
	hash3 := CreateClientDataHash([]byte("different challenge"))
	assert.NotEqual(t, hash, hash3)
}

func TestEnrollmentConfig_Defaults(t *testing.T) {
	config := DefaultEnrollmentConfig("testuser")

	assert.Equal(t, "go-xkms", config.RelyingParty.ID)
	assert.Equal(t, "Go xKMS", config.RelyingParty.Name)
	assert.Equal(t, "testuser", config.User.Name)
	assert.Equal(t, "testuser", config.User.DisplayName)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}

func TestAuthenticationConfig_Defaults(t *testing.T) {
	credID := make([]byte, 32)
	salt := make([]byte, 32)

	config := DefaultAuthenticationConfig(credID, salt)

	assert.Equal(t, "go-xkms", config.RelyingPartyID)
	assert.Equal(t, credID, config.CredentialID)
	assert.Equal(t, salt, config.Salt)
	assert.False(t, config.RequireUserVerification)
	assert.Equal(t, DefaultUserPresenceTimeout, config.Timeout)
}
