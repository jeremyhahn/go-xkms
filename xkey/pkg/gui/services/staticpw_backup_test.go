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

package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var passwordBackupPlaintext = []byte(`[{"name":"vault-entry","password":"s3cret"}]`)

// decodePasswordBackup parses a sealed envelope.
func decodePasswordBackup(t *testing.T, data []byte) *passwordBackupEnvelope {
	t.Helper()
	var envelope passwordBackupEnvelope
	require.NoError(t, json.Unmarshal(data, &envelope))
	return &envelope
}

func TestPasswordBackup_RoundTripEveryAlgorithm(t *testing.T) {
	for algorithm := range algorithmKeySize {
		t.Run(algorithm, func(t *testing.T) {
			sealed, err := sealPasswordBackup(passwordBackupPlaintext, algorithm, []byte("vault-pw"))
			require.NoError(t, err)
			assert.NotContains(t, string(sealed), "s3cret")

			opened, err := openPasswordBackup(sealed, algorithm, []byte("vault-pw"))
			require.NoError(t, err)
			assert.Equal(t, passwordBackupPlaintext, opened)
		})
	}
}

func TestPasswordBackup_HeaderCarriesSaltAndParams(t *testing.T) {
	sealed, err := sealPasswordBackup(passwordBackupPlaintext, "aes-128", []byte("vault-pw"))
	require.NoError(t, err)

	envelope := decodePasswordBackup(t, sealed)
	assert.Equal(t, passwordBackupMagic, envelope.Magic)
	assert.Equal(t, passwordBackupVersion, envelope.Version)
	assert.Equal(t, "aes-128", envelope.Algorithm)
	require.NotNil(t, envelope.KDF)
	assert.EqualValues(t, "Argon2id", envelope.KDF.Algorithm)
	assert.EqualValues(t, 3, envelope.KDF.Time)
	assert.EqualValues(t, 64*1024, envelope.KDF.MemoryKiB)
	assert.EqualValues(t, 4, envelope.KDF.Threads)
	assert.GreaterOrEqual(t, len(envelope.KDF.Salt), 16)
}

func TestPasswordBackup_SamePasswordAndDataDiffer(t *testing.T) {
	password := []byte("same")
	first, err := sealPasswordBackup(passwordBackupPlaintext, "aes-256", password)
	require.NoError(t, err)
	second, err := sealPasswordBackup(passwordBackupPlaintext, "aes-256", password)
	require.NoError(t, err)

	a, b := decodePasswordBackup(t, first), decodePasswordBackup(t, second)
	assert.NotEqual(t, a.KDF.Salt, b.KDF.Salt)
	assert.NotEqual(t, a.Ciphertext, b.Ciphertext)

	keyA, err := backup.DerivePasswordKey(a.KDF, password)
	require.NoError(t, err)
	keyB, err := backup.DerivePasswordKey(b.KDF, password)
	require.NoError(t, err)
	assert.NotEqual(t, keyA.Bytes(), keyB.Bytes())
}

func TestPasswordBackup_WrongPassword(t *testing.T) {
	sealed, err := sealPasswordBackup(passwordBackupPlaintext, "aes-256", []byte("right"))
	require.NoError(t, err)

	_, err = openPasswordBackup(sealed, "aes-256", []byte("wrong"))
	assert.ErrorIs(t, err, ErrRestoreDecryptFailed)
}

// TestPasswordBackup_LegacyFormatRefused builds a genuine pre-#1202 file --
// AES-GCM keyed with an unsalted SHA-256 of the password, nonce prepended --
// and checks it is refused with a typed error even given the password.
func TestPasswordBackup_LegacyFormatRefused(t *testing.T) {
	password := []byte("legacy")
	hash := sha256.Sum256(password)
	block, err := aes.NewCipher(hash[:])
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)
	nonce := make([]byte, gcm.NonceSize())
	legacy := gcm.Seal(nonce, nonce, passwordBackupPlaintext, nil)

	_, err = openPasswordBackup(legacy, "aes-256", password)
	assert.ErrorIs(t, err, ErrRestoreLegacyFormat)
}

func TestPasswordBackup_HeaderTamperingDetected(t *testing.T) {
	sealed, err := sealPasswordBackup(passwordBackupPlaintext, "aes-256", []byte("pw"))
	require.NoError(t, err)

	tests := map[string]struct {
		mutate func(e *passwordBackupEnvelope)
		want   error
	}{
		"salt": {func(e *passwordBackupEnvelope) { e.KDF.Salt[0] ^= 0xFF }, ErrRestoreDecryptFailed},
		"weakened memory": {func(e *passwordBackupEnvelope) { e.KDF.MemoryKiB = 8 * 1024 },
			ErrRestoreKeyDerivationFailed},
		"inflated memory": {func(e *passwordBackupEnvelope) { e.KDF.MemoryKiB = 1 << 30 },
			ErrRestoreKeyDerivationFailed},
		"time":          {func(e *passwordBackupEnvelope) { e.KDF.Time = 1 }, ErrRestoreKeyDerivationFailed},
		"kdf stripped":  {func(e *passwordBackupEnvelope) { e.KDF = nil }, ErrRestoreKeyDerivationFailed},
		"version":       {func(e *passwordBackupEnvelope) { e.Version = 2 }, ErrRestoreUnsupportedVersion},
		"short nonce":   {func(e *passwordBackupEnvelope) { e.Nonce = e.Nonce[:4] }, ErrRestoreDecryptFailed},
		"ciphertext":    {func(e *passwordBackupEnvelope) { e.Ciphertext[0] ^= 0xFF }, ErrRestoreDecryptFailed},
		"algorithm tag": {func(e *passwordBackupEnvelope) { e.Algorithm = "aes-128" }, ErrRestoreAlgorithmMismatch},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			envelope := decodePasswordBackup(t, sealed)
			tt.mutate(envelope)
			data, err := json.Marshal(envelope)
			require.NoError(t, err)

			_, err = openPasswordBackup(data, "aes-256", []byte("pw"))
			assert.ErrorIs(t, err, tt.want)
		})
	}
}

// TestPasswordBackup_HeaderIsAAD proves the header is GCM additional data:
// re-sealing nothing, only relabelling the algorithm in a header that
// otherwise still derives the same key, fails authentication.
func TestPasswordBackup_HeaderIsAAD(t *testing.T) {
	sealed, err := sealPasswordBackup(passwordBackupPlaintext, "aes-128", []byte("pw"))
	require.NoError(t, err)
	envelope := decodePasswordBackup(t, sealed)

	key, err := backup.DerivePasswordKey(envelope.KDF, []byte("pw"))
	require.NoError(t, err)
	gcm, err := passwordBackupGCM("aes-128", key)
	require.NoError(t, err)

	envelope.Magic = "XKPX"
	aad, err := envelope.aad()
	require.NoError(t, err)
	_, err = gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	assert.Error(t, err, "a modified header must fail GCM authentication")
}

func TestPasswordBackup_InvalidInput(t *testing.T) {
	_, err := sealPasswordBackup(passwordBackupPlaintext, "blowfish", []byte("pw"))
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)

	_, err = sealPasswordBackup(passwordBackupPlaintext, "aes-256", nil)
	assert.ErrorIs(t, err, ErrBackupFailed)
	assert.ErrorIs(t, err, xkms.ErrPasswordHashInvalidPassword)

	_, err = openPasswordBackup([]byte("{}"), "blowfish", []byte("pw"))
	assert.ErrorIs(t, err, ErrBackupInvalidAlgorithm)

	_, err = openPasswordBackup([]byte(`{"magic":"XKPW","version":1,"algorithm":"aes-256"}`), "aes-256", []byte("pw"))
	assert.ErrorIs(t, err, ErrRestoreKeyDerivationFailed)
}

func TestRestorePasswords_EncryptedRoundTripAndRefusals(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPassword(AddPasswordParams{Name: "vault-entry", Password: "s3cret"})
	require.NoError(t, err)

	backupFile := filepath.Join(t.TempDir(), "vault.enc")
	require.NoError(t, svc.BackupPasswords(backupFile, true, "aes-192", "vault-pw"))

	target, _ := newTestStaticPWService(t)
	_, err = target.RestorePasswords(backupFile, true, "aes-256", "vault-pw")
	assert.ErrorIs(t, err, ErrRestoreAlgorithmMismatch)

	imported, err := target.RestorePasswords(backupFile, true, "aes-192", "vault-pw")
	require.NoError(t, err)
	assert.Equal(t, 1, imported)

	legacyFile := filepath.Join(t.TempDir(), "legacy.enc")
	require.NoError(t, os.WriteFile(legacyFile, make([]byte, 64), 0o600))
	_, err = target.RestorePasswords(legacyFile, true, "aes-256", "vault-pw")
	assert.ErrorIs(t, err, ErrRestoreLegacyFormat)
}
