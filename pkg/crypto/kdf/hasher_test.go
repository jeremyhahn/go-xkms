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
	"crypto/fips140"
	"os"
	"os/exec"
	"strings"
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

// TestNewFIPSAwareHasher_Standard runs in whatever mode the ambient `go test`
// invocation set rather than re-exec'ing (TestNewFIPSAwareHasher_FIPS already
// covers the FIPS case exhaustively via subprocess), so a suite run entirely
// under GODEBUG=fips140=only -- go-xkms#23's fips-aware CI lane -- asserts
// the FIPS selection here too instead of failing on the "standard" outcome
// the ambient mode makes impossible to satisfy.
func TestNewFIPSAwareHasher_Standard(t *testing.T) {
	h := NewFIPSAwareHasher()
	require.NotNil(t, h)
	if fips140.Enabled() {
		assert.Equal(t, HashV2, h.Version())
		assert.True(t, h.IsFIPS())
		return
	}
	assert.Equal(t, HashV1, h.Version())
	assert.False(t, h.IsFIPS())
}

// TestNewFIPSAwareHasher_FIPS is the compliance assertion for go-xkms #21:
// NewFIPSAwareHasher selects PBKDF2 because crypto/fips140.Enabled is true,
// not because of a GOFIPS140 environment variable this package used to read
// itself. crypto/fips140.Enabled is fixed when the process starts, so this
// re-execs under GODEBUG=fips140=on, mirroring
// pkg/quantum/mlkem512.TestNewAndCreate_RefuseUnderFIPS.
func TestNewFIPSAwareHasher_FIPS(t *testing.T) {
	if os.Getenv("XKMS_FIPS_SUBPROCESS") == "1" {
		h := NewFIPSAwareHasher()
		if h == nil {
			t.Fatal("NewFIPSAwareHasher() = nil")
		}
		if h.Version() != HashV2 {
			t.Fatalf("Version() = %v, want HashV2", h.Version())
		}
		if !h.IsFIPS() {
			t.Fatal("IsFIPS() = false, want true under GODEBUG=fips140=on")
		}
		return
	}

	cmd := exec.Command(os.Args[0], "-test.run=TestNewFIPSAwareHasher_FIPS", "-test.v")
	cmd.Env = append(os.Environ(), "XKMS_FIPS_SUBPROCESS=1", "GODEBUG=fips140=on")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fips140=on subprocess failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "PASS") {
		t.Errorf("fips140=on subprocess did not pass:\n%s", out)
	}
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

func TestNewKeyParams_DescribesVersionProfile(t *testing.T) {
	tests := []struct {
		name    string
		version HashVersion
		want    PasswordKeyParams
	}{
		{"argon2id", HashV1, PasswordKeyParams{
			Version: HashV1, Algorithm: AlgorithmArgon2id, Time: 3,
			MemoryKiB: 64 * 1024, Threads: 4, KeyLength: KeyLength,
		}},
		{"pbkdf2", HashV2, PasswordKeyParams{
			Version: HashV2, Algorithm: AlgorithmPBKDF2, Iterations: 600000,
			Hash: "SHA-256", KeyLength: KeyLength,
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h, err := NewPasswordHasher(tt.version)
			require.NoError(t, err)

			params, err := h.NewKeyParams()
			require.NoError(t, err)
			assert.Len(t, params.Salt, SaltLength)

			got := *params
			got.Salt = nil
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestNewKeyParams_FreshSaltEachCall(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	first, err := h.NewKeyParams()
	require.NoError(t, err)
	second, err := h.NewKeyParams()
	require.NoError(t, err)

	assert.False(t, bytes.Equal(first.Salt, second.Salt))
}

func TestDeriveKeyFromParams_MatchesDeriveKey(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)
	password := []byte("params-roundtrip")

	params, err := h.NewKeyParams()
	require.NoError(t, err)

	fromParams, err := h.DeriveKeyFromParams(password, params)
	require.NoError(t, err)
	direct, err := h.DeriveKey(password, params.Salt, HashV1)
	require.NoError(t, err)

	assert.Equal(t, direct, fromParams)
}

func TestDeriveKeyFromParams_CrossVersion(t *testing.T) {
	// A record written by a PBKDF2 (FIPS) hasher is derivable by an
	// Argon2id hasher: the record's version, not the hasher's, decides.
	writer, err := NewPasswordHasher(HashV2)
	require.NoError(t, err)
	reader, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)
	password := []byte("cross-version")

	params, err := writer.NewKeyParams()
	require.NoError(t, err)
	want, err := writer.DeriveKeyFromParams(password, params)
	require.NoError(t, err)
	got, err := reader.DeriveKeyFromParams(password, params)
	require.NoError(t, err)

	assert.Equal(t, want, got)
}

func TestDeriveKeyFromParams_RejectsTamperedParams(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	tamper := map[string]func(p *PasswordKeyParams){
		"time":       func(p *PasswordKeyParams) { p.Time = 1 },
		"memory":     func(p *PasswordKeyParams) { p.MemoryKiB = 1 << 30 },
		"threads":    func(p *PasswordKeyParams) { p.Threads = 1 },
		"algorithm":  func(p *PasswordKeyParams) { p.Algorithm = AlgorithmArgon2i },
		"iterations": func(p *PasswordKeyParams) { p.Iterations = 1 },
		"hash":       func(p *PasswordKeyParams) { p.Hash = "MD5" },
		"key length": func(p *PasswordKeyParams) { p.KeyLength = 16 },
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			params, err := h.NewKeyParams()
			require.NoError(t, err)
			mutate(params)

			_, err = h.DeriveKeyFromParams([]byte("pw"), params)
			assert.ErrorIs(t, err, ErrHasherParamsMismatch)
		})
	}
}

func TestDeriveKeyFromParams_InvalidInput(t *testing.T) {
	h, err := NewPasswordHasher(HashV1)
	require.NoError(t, err)

	_, err = h.DeriveKeyFromParams([]byte("pw"), nil)
	assert.ErrorIs(t, err, ErrHasherParamsMismatch)

	_, err = h.DeriveKeyFromParams([]byte("pw"), &PasswordKeyParams{Version: 99})
	assert.ErrorIs(t, err, ErrHasherInvalidVersion)

	params, err := h.NewKeyParams()
	require.NoError(t, err)
	params.Salt = params.Salt[:8]
	_, err = h.DeriveKeyFromParams([]byte("pw"), params)
	assert.ErrorIs(t, err, ErrHasherInvalidSalt)

	params, err = h.NewKeyParams()
	require.NoError(t, err)
	_, err = h.DeriveKeyFromParams(nil, params)
	assert.ErrorIs(t, err, ErrHasherInvalidPassword)
}
