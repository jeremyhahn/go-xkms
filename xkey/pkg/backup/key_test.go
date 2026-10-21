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

package backup

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// passwordBackupService returns a service with one trust-store certificate,
// so CreateBackup has data to seal.
func passwordBackupService(t *testing.T) *Service {
	t.Helper()
	svc, err := NewService(testConfig(),
		WithTrustStore(&mockTrustStore{certs: []*x509.Certificate{testCert(t)}}),
	)
	require.NoError(t, err)
	return svc
}

func TestNewRawKey(t *testing.T) {
	material := bytes.Repeat([]byte{0x42}, KeySize)
	key, err := NewRawKey(material)
	require.NoError(t, err)
	assert.Equal(t, material, key.Bytes())
	assert.Nil(t, key.KDF())

	material[0] = 0
	assert.Equal(t, byte(0x42), key.Bytes()[0], "NewRawKey must copy its input")
}

func TestNewRawKey_WrongLength(t *testing.T) {
	for _, n := range []int{0, 16, KeySize + 1} {
		key, err := NewRawKey(make([]byte, n))
		assert.Nil(t, key)
		assert.ErrorIs(t, err, ErrInvalidKey)
	}
}

func TestGenerateKey_Random(t *testing.T) {
	first, err := GenerateKey()
	require.NoError(t, err)
	second, err := GenerateKey()
	require.NoError(t, err)

	assert.Len(t, first.Bytes(), KeySize)
	assert.Nil(t, first.KDF())
	assert.NotEqual(t, first.Bytes(), second.Bytes())
}

func TestKeyWipe(t *testing.T) {
	key, err := GenerateKey()
	require.NoError(t, err)

	key.Wipe()
	assert.Equal(t, make([]byte, KeySize), key.Bytes())

	var nilKey *Key
	nilKey.Wipe()
}

func TestPasswordBackup_RoundTrip(t *testing.T) {
	svc := passwordBackupService(t)
	password := []byte("correct horse battery staple")

	key, err := NewPasswordKey(password)
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	// Round-trip through the on-disk JSON form, as the CLI does.
	data, err := json.Marshal(eb)
	require.NoError(t, err)
	var loaded EncryptedBackup
	require.NoError(t, json.Unmarshal(data, &loaded))

	derived, err := DerivePasswordKey(loaded.KDF, password)
	require.NoError(t, err)
	assert.Equal(t, key.Bytes(), derived.Bytes())

	archive, err := svc.DecryptBackup(&loaded, derived)
	require.NoError(t, err)
	require.NotNil(t, archive.TrustStore)
	assert.Len(t, archive.TrustStore.Certificates, 1)
}

func TestPasswordBackup_HeaderCarriesSaltAndParams(t *testing.T) {
	svc := passwordBackupService(t)

	key, err := NewPasswordKey([]byte("header-check"))
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	require.NotNil(t, eb.KDF)
	assert.Equal(t, BackupVersion, eb.Version)
	assert.Equal(t, KeySize, eb.KDF.KeyLength)
	assert.GreaterOrEqual(t, len(eb.KDF.Salt), 16)

	// The header records exactly the FIPS-aware hasher's parameters:
	// Argon2id normally, PBKDF2-SHA256 when the FIPS 140 module is on.
	want, err := xkms.NewFIPSAwareHasher().NewKeyParams()
	require.NoError(t, err)
	got := *eb.KDF
	got.Salt, want.Salt = nil, nil
	assert.Equal(t, *want, got)

	data, err := json.Marshal(eb)
	require.NoError(t, err)
	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(data, &raw))
	var kdf map[string]any
	require.NoError(t, json.Unmarshal(raw["kdf"], &kdf))
	want.Salt = eb.KDF.Salt
	wantData, err := json.Marshal(want)
	require.NoError(t, err)
	var wantKDF map[string]any
	require.NoError(t, json.Unmarshal(wantData, &wantKDF))
	for field := range wantKDF {
		assert.Contains(t, kdf, field)
	}
}

func TestPasswordBackup_SamePasswordDiffers(t *testing.T) {
	svc := passwordBackupService(t)
	password := []byte("same password")

	first, err := NewPasswordKey(password)
	require.NoError(t, err)
	second, err := NewPasswordKey(password)
	require.NoError(t, err)

	assert.NotEqual(t, first.KDF().Salt, second.KDF().Salt)
	assert.NotEqual(t, first.Bytes(), second.Bytes())

	ebFirst, err := svc.CreateBackup(first)
	require.NoError(t, err)
	ebSecond, err := svc.CreateBackup(second)
	require.NoError(t, err)
	assert.NotEqual(t, ebFirst.Ciphertext, ebSecond.Ciphertext)
}

func TestPasswordBackup_WrongPassword(t *testing.T) {
	svc := passwordBackupService(t)

	key, err := NewPasswordKey([]byte("right"))
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	wrong, err := DerivePasswordKey(eb.KDF, []byte("wrong"))
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(eb, wrong)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrDecryptionFailed)
}

// TestPasswordBackup_LegacyFormatRefused builds a version 1 envelope -- the
// key an unsalted SHA-256 of the password, no KDF record -- and checks it is
// refused with the dedicated error even given the password. The refusal is
// decided by the version field before any decryption, so the sealed bytes
// are opaque.
func TestPasswordBackup_LegacyFormatRefused(t *testing.T) {
	password := []byte("legacy")
	legacyKey := sha256.Sum256(password)
	legacy := &EncryptedBackup{
		Magic:      BackupMagic,
		Version:    1,
		Nonce:      make([]byte, 24),
		Ciphertext: []byte("opaque version 1 ciphertext"),
	}

	svc := passwordBackupService(t)
	raw, err := NewRawKey(legacyKey[:])
	require.NoError(t, err)
	archive, err := svc.DecryptBackup(legacy, raw)
	assert.Nil(t, archive)
	assert.ErrorIs(t, err, ErrLegacyBackupFormat)

	_, err = DerivePasswordKey(legacy.KDF, password)
	assert.ErrorIs(t, err, ErrNotPasswordSealed)
}

// TestPasswordBackup_HeaderAuthenticated proves the header is AEAD additional
// data: decrypting with the genuine key fails once any header field changes.
func TestPasswordBackup_HeaderAuthenticated(t *testing.T) {
	svc := passwordBackupService(t)

	key, err := NewPasswordKey([]byte("aad"))
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	tamper := map[string]func(p *xkms.PasswordKeyParams){
		"salt":   func(p *xkms.PasswordKeyParams) { p.Salt[0] ^= 0xFF },
		"memory": func(p *xkms.PasswordKeyParams) { p.MemoryKiB = 8 * 1024 },
		"time":   func(p *xkms.PasswordKeyParams) { p.Time = 1 },
		// Swap to the other KDF: the hasher picks PBKDF2 under FIPS mode
		// and Argon2id otherwise.
		"algorithm": func(p *xkms.PasswordKeyParams) {
			if p.Algorithm == "PBKDF2" {
				p.Algorithm = "Argon2id"
				return
			}
			p.Algorithm = "PBKDF2"
		},
	}
	for name, mutate := range tamper {
		t.Run(name, func(t *testing.T) {
			params := *eb.KDF
			params.Salt = append([]byte(nil), eb.KDF.Salt...)
			mutate(&params)
			tampered := *eb
			tampered.KDF = &params

			archive, err := svc.DecryptBackup(&tampered, key)
			assert.Nil(t, archive)
			assert.ErrorIs(t, err, ErrDecryptionFailed)
		})
	}

	t.Run("kdf stripped", func(t *testing.T) {
		tampered := *eb
		tampered.KDF = nil
		archive, err := svc.DecryptBackup(&tampered, key)
		assert.Nil(t, archive)
		assert.ErrorIs(t, err, ErrDecryptionFailed)
	})
}

// TestDerivePasswordKey_TamperedParamsRefused checks a weakened or inflated
// cost is refused before any derivation runs.
func TestDerivePasswordKey_TamperedParamsRefused(t *testing.T) {
	key, err := NewPasswordKey([]byte("costs"))
	require.NoError(t, err)

	for name, mutate := range map[string]func(p *xkms.PasswordKeyParams){
		"weakened memory": func(p *xkms.PasswordKeyParams) { p.MemoryKiB = 8 * 1024 },
		"inflated memory": func(p *xkms.PasswordKeyParams) { p.MemoryKiB = 1 << 30 },
		"weakened time":   func(p *xkms.PasswordKeyParams) { p.Time = 1 },
	} {
		t.Run(name, func(t *testing.T) {
			params := *key.KDF()
			mutate(&params)
			derived, err := DerivePasswordKey(&params, []byte("costs"))
			assert.Nil(t, derived)
			assert.ErrorIs(t, err, ErrKeyDerivationFailed)
			assert.ErrorIs(t, err, xkms.ErrPasswordHashParamsMismatch)
		})
	}
}

func TestDerivePasswordKey_RawKeyEnvelope(t *testing.T) {
	derived, err := DerivePasswordKey(nil, []byte("pw"))
	assert.Nil(t, derived)
	assert.ErrorIs(t, err, ErrNotPasswordSealed)
}

func TestNewPasswordKey_EmptyPassword(t *testing.T) {
	key, err := NewPasswordKey(nil)
	assert.Nil(t, key)
	assert.ErrorIs(t, err, ErrKeyDerivationFailed)
	assert.ErrorIs(t, err, xkms.ErrPasswordHashInvalidPassword)
}

func TestEncryptedBackupPasswordKey(t *testing.T) {
	svc := passwordBackupService(t)
	password := []byte("envelope")

	key, err := NewPasswordKey(password)
	require.NoError(t, err)
	eb, err := svc.CreateBackup(key)
	require.NoError(t, err)

	derived, err := eb.PasswordKey(password)
	require.NoError(t, err)
	assert.Equal(t, key.Bytes(), derived.Bytes())

	raw, err := svc.CreateBackup(testKey())
	require.NoError(t, err)
	_, err = raw.PasswordKey(password)
	assert.ErrorIs(t, err, ErrNotPasswordSealed)
}

func TestEncryptedBackupPasswordKey_InvalidEnvelope(t *testing.T) {
	legacy := &EncryptedBackup{Magic: BackupMagic, Version: 1}
	_, err := legacy.PasswordKey([]byte("pw"))
	assert.ErrorIs(t, err, ErrLegacyBackupFormat)

	var missing *EncryptedBackup
	_, err = missing.PasswordKey([]byte("pw"))
	assert.ErrorIs(t, err, ErrInvalidBackup)

	future := &EncryptedBackup{Magic: BackupMagic, Version: 99}
	_, err = future.PasswordKey([]byte("pw"))
	assert.ErrorIs(t, err, ErrVersionMismatch)
}
