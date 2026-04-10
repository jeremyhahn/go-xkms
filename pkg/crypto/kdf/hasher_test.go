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

package kdf

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPasswordHasher_V1(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)
	assert.NotNil(t, h)
	assert.Equal(t, HashV1, h.Version())
	assert.False(t, h.IsFIPS())
}

func TestNewPasswordHasher_V2(t *testing.T) {
	h, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)
	assert.NotNil(t, h)
	assert.Equal(t, HashV2, h.Version())
	assert.True(t, h.IsFIPS())
}

func TestNewPasswordHasher_InvalidVersion(t *testing.T) {
	tests := []struct {
		name    string
		version HashVersion
	}{
		{"zero", HashVersion(0)},
		{"negative", HashVersion(-1)},
		{"too high", HashVersion(99)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewPasswordHasher(tt.version)
			assert.ErrorIs(t, err, ErrHasherInvalidVersion)
			assert.Nil(t, h)
		})
	}
}

func TestNewFIPSAwareHasher_Standard(t *testing.T) {
	t.Setenv("GOFIPS140", "")
	h := NewFIPSAwareHasher()
	require.NotNil(t, h)
	assert.Equal(t, HashV1, h.Version())
	assert.False(t, h.IsFIPS())
}

func TestNewFIPSAwareHasher_FIPS(t *testing.T) {
	t.Setenv("GOFIPS140", "v1.0.0")
	h := NewFIPSAwareHasher()
	require.NotNil(t, h)
	assert.Equal(t, HashV2, h.Version())
	assert.True(t, h.IsFIPS())
}

func TestHash_V1(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("correct-horse-battery-staple")
	key, salt, version, err := h.Hash(password)
	require.NoError(t, err)

	assert.Len(t, key, KeyLength, "derived key must be %d bytes", KeyLength)
	assert.Len(t, salt, SaltLength, "salt must be %d bytes", SaltLength)
	assert.Equal(t, HashV1, version)
}

func TestHash_V2(t *testing.T) {
	h, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)

	password := []byte("correct-horse-battery-staple")
	key, salt, version, err := h.Hash(password)
	require.NoError(t, err)

	assert.Len(t, key, KeyLength, "derived key must be %d bytes", KeyLength)
	assert.Len(t, salt, SaltLength, "salt must be %d bytes", SaltLength)
	assert.Equal(t, HashV2, version)
}

func TestHash_EmptyPassword(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	key, salt, _, err := h.Hash([]byte{})
	assert.ErrorIs(t, err, ErrHasherInvalidPassword)
	assert.Nil(t, key)
	assert.Nil(t, salt)
}

func TestHash_NilPassword(t *testing.T) {
	h, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)

	key, salt, _, err := h.Hash(nil)
	assert.ErrorIs(t, err, ErrHasherInvalidPassword)
	assert.Nil(t, key)
	assert.Nil(t, salt)
}

func TestHash_UniqueSalts(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("same-password-both-times")

	_, salt1, _, err := h.Hash(password)
	require.NoError(t, err)

	_, salt2, _, err := h.Hash(password)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(salt1, salt2),
		"two Hash calls must produce different salts")
}

func TestDeriveKey_V1_Deterministic(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("deterministic-test-password")
	salt := make([]byte, SaltLength)
	for i := range salt {
		salt[i] = byte(i)
	}

	key1, err := h.DeriveKey(password, salt, HashV1)
	require.NoError(t, err)

	key2, err := h.DeriveKey(password, salt, HashV1)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(key1, key2),
		"same password+salt+version must produce identical keys")
}

func TestDeriveKey_V2_Deterministic(t *testing.T) {
	h, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)

	password := []byte("deterministic-test-password")
	salt := make([]byte, SaltLength)
	for i := range salt {
		salt[i] = byte(i + 100)
	}

	key1, err := h.DeriveKey(password, salt, HashV2)
	require.NoError(t, err)

	key2, err := h.DeriveKey(password, salt, HashV2)
	require.NoError(t, err)

	assert.True(t, bytes.Equal(key1, key2),
		"same password+salt+version must produce identical keys")
}

func TestDeriveKey_EmptyPassword(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	salt := make([]byte, SaltLength)

	_, err = h.DeriveKey([]byte{}, salt, HashV1)
	assert.ErrorIs(t, err, ErrHasherInvalidPassword)

	_, err = h.DeriveKey(nil, salt, HashV2)
	assert.ErrorIs(t, err, ErrHasherInvalidPassword)
}

func TestDeriveKey_ShortSalt(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("password")

	tests := []struct {
		name string
		salt []byte
	}{
		{"nil salt", nil},
		{"empty salt", []byte{}},
		{"1 byte salt", []byte{0x01}},
		{"15 byte salt", make([]byte, 15)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := h.DeriveKey(password, tt.salt, HashV1)
			assert.ErrorIs(t, err, ErrHasherInvalidSalt)
		})
	}
}

func TestDeriveKey_InvalidVersion(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("password")
	salt := make([]byte, SaltLength)

	_, err = h.DeriveKey(password, salt, HashVersion(99))
	assert.ErrorIs(t, err, ErrHasherInvalidVersion)
}

func TestIsFIPS(t *testing.T) {
	v1, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)
	assert.False(t, v1.IsFIPS(), "V1 (Argon2id) must not be FIPS")

	v2, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)
	assert.True(t, v2.IsFIPS(), "V2 (PBKDF2) must be FIPS")
}

func TestHash_DeriveKey_Roundtrip(t *testing.T) {
	versions := []struct {
		name    string
		version HashVersion
	}{
		{"HashV1_Argon2id", HashV1},
		{"HashV2_PBKDF2", HashV2},
	}

	for _, tt := range versions {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewPasswordHasher(tt.version)
			require.NoError(t, err)

			password := []byte("round-trip-password")

			key, salt, version, err := h.Hash(password)
			require.NoError(t, err)

			reproduced, err := h.DeriveKey(password, salt, version)
			require.NoError(t, err)

			assert.True(t, bytes.Equal(key, reproduced),
				"DeriveKey with Hash outputs must reproduce the same key")
		})
	}
}

func TestDeriveKey_DifferentVersionsDifferentKeys(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	password := []byte("cross-version-test")
	salt := make([]byte, SaltLength)
	for i := range salt {
		salt[i] = byte(i + 50)
	}

	keyV1, err := h.DeriveKey(password, salt, HashV1)
	require.NoError(t, err)

	keyV2, err := h.DeriveKey(password, salt, HashV2)
	require.NoError(t, err)

	assert.False(t, bytes.Equal(keyV1, keyV2),
		"different versions must produce different keys for same password and salt")
}
