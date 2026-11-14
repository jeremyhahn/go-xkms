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
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewHMACSecretExtension(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	// Mock authenticator supports hmac-secret
	hmacExt, err := NewHMACSecretExtension(auth)
	assert.NoError(t, err)
	assert.NotNil(t, hmacExt)
}

func TestHMACSecretExtension_EnrollCredential(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: User{
			Name:        "test@example.com",
			DisplayName: "Test User",
		},
		RequireUserVerification: false,
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.CredentialID)
	assert.NotEmpty(t, result.Salt)
	assert.Equal(t, 16, len(result.AAGUID))
	assert.Equal(t, "example.com", result.RelyingParty.ID)
	assert.NotEmpty(t, result.User.ID)
}

func TestHMACSecretExtension_EnrollCredential_WithCustomSalt(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customSalt := make([]byte, 32)
	for i := range customSalt {
		customSalt[i] = byte(i)
	}

	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "example.com",
			Name: "Example Corp",
		},
		User: User{
			Name:        "test@example.com",
			DisplayName: "Test User",
		},
		Salt:                    customSalt,
		RequireUserVerification: false,
	}

	result, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)

	assert.Equal(t, customSalt, result.Salt)
}

func TestHMACSecretExtension_DeriveSecret(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	credID := make([]byte, 32)
	salt := make([]byte, 32)

	authConfig := &AuthenticationConfig{
		RelyingPartyID:          "example.com",
		CredentialID:            credID,
		Salt:                    salt,
		RequireUserVerification: false,
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.HMACSecret)
	assert.NotEmpty(t, result.AuthData)
	assert.NotEmpty(t, result.Signature)
	assert.True(t, result.UserPresent)
}

func TestGenerateDerivedKey(t *testing.T) {
	tests := []struct {
		name        string
		hmacSecret  []byte
		expectError bool
	}{
		{
			name:        "valid 32-byte secret",
			hmacSecret:  make([]byte, 32),
			expectError: false,
		},
		{
			name:        "invalid length - too short",
			hmacSecret:  make([]byte, 16),
			expectError: true,
		},
		{
			name:        "invalid length - too long",
			hmacSecret:  make([]byte, 64),
			expectError: true,
		},
		{
			name:        "empty secret",
			hmacSecret:  []byte{},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			derivedKey, err := GenerateDerivedKey(tt.hmacSecret)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, derivedKey)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, derivedKey)
				assert.Equal(t, 64, len(derivedKey), "Derived key should be 512 bits (64 bytes)")

				// Verify deterministic output
				derivedKey2, err := GenerateDerivedKey(tt.hmacSecret)
				assert.NoError(t, err)
				assert.Equal(t, derivedKey, derivedKey2, "same input should produce same output")
			}
		})
	}
}

func TestGenerateDerivedKey_Uniqueness(t *testing.T) {
	secret1 := make([]byte, 32)
	secret2 := make([]byte, 32)
	secret2[0] = 1 // Make it different

	key1, err := GenerateDerivedKey(secret1)
	require.NoError(t, err)

	key2, err := GenerateDerivedKey(secret2)
	require.NoError(t, err)

	assert.NotEqual(t, key1, key2, "different secrets should produce different keys")
}

func TestParseAuthDataExtensions(t *testing.T) {
	tests := []struct {
		name        string
		authData    []byte
		expectError bool
		expectedErr error
		expectNil   bool
	}{
		{
			name:        "too short",
			authData:    make([]byte, 30),
			expectError: true,
			expectedErr: ErrAuthDataTooShort,
		},
		{
			name: "no extensions flag",
			authData: func() []byte {
				data := make([]byte, 37)
				data[32] = 0x00 // flags with no ED bit
				return data
			}(),
			expectError: false,
			expectNil:   true,
		},
		{
			// The ED flag promises an extension map, but the three
			// trailing zero bytes decode as CBOR unsigned zero rather
			// than a map, so this must be rejected.
			name: "extensions flag set over non-map payload",
			authData: func() []byte {
				data := make([]byte, 40)
				data[32] = 0x80 // flags with ED bit
				return data
			}(),
			expectError: true,
			expectedErr: ErrInvalidExtensions,
			expectNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extensions, err := ParseAuthDataExtensions(tt.authData)

			if tt.expectError {
				assert.Error(t, err)
				assert.ErrorIs(t, err, tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
			if tt.expectNil {
				assert.Nil(t, extensions)
			}
		})
	}
}

func TestParseAuthDataExtensions_WithAttestedData(t *testing.T) {
	// Create auth data with AT and ED flags. The COSE public key position
	// holds CBOR unsigned zero, which is well-formed but is not a
	// COSE_Key map, so the extension map cannot be located.
	authData := make([]byte, 100)
	authData[32] = 0xC0                             // AT | ED flags
	binary.BigEndian.PutUint16(authData[53:55], 32) // Cred ID length

	extensions, err := ParseAuthDataExtensions(authData)
	assert.ErrorIs(t, err, ErrInvalidCOSEKey)
	assert.Nil(t, extensions)
}

func TestParseAuthDataExtensions_InvalidAttestedData(t *testing.T) {
	// Create auth data with AT flag but invalid length
	authData := make([]byte, 50)
	authData[32] = 0xC0 // AT | ED flags

	_, err := ParseAuthDataExtensions(authData)
	assert.ErrorIs(t, err, ErrInvalidAttestedCredentialData)
}

func TestParseAuthDataExtensions_InvalidCredIDLength(t *testing.T) {
	// Create auth data with AT flag and excessive cred ID length
	authData := make([]byte, 60)
	authData[32] = 0xC0                               // AT | ED flags
	binary.BigEndian.PutUint16(authData[53:55], 1000) // Too large

	_, err := ParseAuthDataExtensions(authData)
	assert.ErrorIs(t, err, ErrInvalidAttestedCredentialData)
}

func TestHMACSecretExtension_FullFlow(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	// Step 1: Enroll credential
	enrollConfig := &EnrollmentConfig{
		RelyingParty: RelyingParty{
			ID:   "go-xkms",
			Name: "Go xKMS",
		},
		User: User{
			Name:        "testuser",
			DisplayName: "Test User",
		},
		RequireUserVerification: false,
	}

	enrollResult, err := hmacExt.EnrollCredential(enrollConfig)
	require.NoError(t, err)
	require.NotNil(t, enrollResult)

	// Step 2: Derive secret using enrolled credential
	authConfig := &AuthenticationConfig{
		RelyingPartyID:          enrollResult.RelyingParty.ID,
		CredentialID:            enrollResult.CredentialID,
		Salt:                    enrollResult.Salt,
		RequireUserVerification: false,
	}

	authResult, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, authResult)

	// Step 3: Generate derived key
	derivedKey, err := GenerateDerivedKey(authResult.HMACSecret)
	require.NoError(t, err)
	require.NotNil(t, derivedKey)

	assert.Equal(t, 64, len(derivedKey))

	// Verify deterministic key generation
	derivedKey2, err := GenerateDerivedKey(authResult.HMACSecret)
	require.NoError(t, err)
	assert.Equal(t, derivedKey, derivedKey2)
}

func TestHMACSecretExtension_DeriveSecret_WithCustomChallenge(t *testing.T) {
	mockDev := NewMockHIDDevice("/dev/hidraw0")
	config := DefaultConfig

	ctapDev, err := NewCTAPHIDDevice(mockDev, &config)
	require.NoError(t, err)
	defer func() { _ = ctapDev.Close() }()

	auth, err := NewAuthenticator(ctapDev, &config)
	require.NoError(t, err)

	hmacExt, err := NewHMACSecretExtension(auth)
	require.NoError(t, err)

	customChallenge := make([]byte, 32)
	for i := range customChallenge {
		customChallenge[i] = byte(i)
	}

	authConfig := &AuthenticationConfig{
		RelyingPartyID:          "example.com",
		CredentialID:            make([]byte, 32),
		Salt:                    make([]byte, 32),
		Challenge:               customChallenge,
		RequireUserVerification: false,
	}

	result, err := hmacExt.DeriveSecret(authConfig)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.NotEmpty(t, result.HMACSecret)
}

func TestVerifyHMACSecret_AllCases(t *testing.T) {
	tests := []struct {
		name        string
		secret      []byte
		expectError bool
		errorMsg    string
	}{
		{
			name:        "valid 32 bytes",
			secret:      make([]byte, 32),
			expectError: false,
		},
		{
			name:        "valid 64 bytes",
			secret:      make([]byte, 64),
			expectError: false,
		},
		{
			name:        "invalid: too short",
			secret:      make([]byte, 16),
			expectError: true,
			errorMsg:    "invalid HMAC secret length",
		},
		{
			name:        "invalid: too long",
			secret:      make([]byte, 128),
			expectError: true,
			errorMsg:    "invalid HMAC secret length",
		},
		{
			name:        "invalid: empty",
			secret:      []byte{},
			expectError: true,
		},
		{
			name:        "invalid: nil",
			secret:      nil,
			expectError: true,
		},
		{
			name:        "invalid: single byte",
			secret:      []byte{0x00},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := VerifyHMACSecret(tt.secret)
			if tt.expectError {
				assert.Error(t, err)
				if tt.errorMsg != "" {
					assert.Contains(t, err.Error(), tt.errorMsg)
				}
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
