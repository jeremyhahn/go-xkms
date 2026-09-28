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
	crand "crypto/rand"
	"encoding/json"
	"errors"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/backup"
)

// The encrypted password-vault backup is a JSON envelope whose header --
// magic, version, AES algorithm and password KDF record -- is authenticated
// as AES-GCM additional data. The key is derived by backup.NewPasswordKey,
// the one password KDF every xkey backup uses (Argon2id, t=3, m=64 MiB,
// p=4, random salt; PBKDF2-SHA256 under the Go FIPS 140 module), and
// truncated to the selected AES key size. The unsalted SHA-256(password)
// raw nonce||ciphertext files written before go-xkms#1202 are refused.
const (
	// passwordBackupMagic identifies an encrypted password-vault backup.
	passwordBackupMagic = "XKPW"

	// passwordBackupVersion is the current envelope version.
	passwordBackupVersion = 1
)

// Encrypted password-vault backup errors.
var (
	// ErrRestoreLegacyFormat indicates the file is not a salted password
	// backup envelope. Encrypted backups written before go-xkms#1202 keyed
	// AES with an unsalted SHA-256 of the password; they are refused, never
	// migrated.
	ErrRestoreLegacyFormat = errors.New("staticpw_service: not a salted password backup; unsalted backups from earlier releases are no longer supported")

	// ErrRestoreUnsupportedVersion indicates a password backup envelope of
	// a version this release does not read.
	ErrRestoreUnsupportedVersion = errors.New("staticpw_service: unsupported password backup version")

	// ErrRestoreAlgorithmMismatch indicates the algorithm chosen for restore
	// differs from the one recorded in the backup header.
	ErrRestoreAlgorithmMismatch = errors.New("staticpw_service: selected algorithm does not match the backup")

	// ErrRestoreKeyDerivationFailed indicates the backup's KDF record is
	// missing, invalid or altered, so no key was derived.
	ErrRestoreKeyDerivationFailed = errors.New("staticpw_service: backup key derivation failed")
)

// passwordBackupHeader is the authenticated part of a passwordBackupEnvelope.
type passwordBackupHeader struct {
	Magic     string                  `json:"magic"`
	Version   int                     `json:"version"`
	Algorithm string                  `json:"algorithm"`
	KDF       *xkms.PasswordKeyParams `json:"kdf"`
}

// passwordBackupEnvelope is the on-disk form of an encrypted password
// backup.
type passwordBackupEnvelope struct {
	passwordBackupHeader
	Nonce      []byte `json:"nonce"`
	Ciphertext []byte `json:"ciphertext"`
}

// aad returns the canonical header encoding used as GCM additional data.
func (h *passwordBackupHeader) aad() ([]byte, error) {
	return json.Marshal(h)
}

// passwordBackupGCM returns the AES-GCM AEAD for algorithm, keyed with the
// leading bytes of key.
func passwordBackupGCM(algorithm string, key *backup.Key) (cipher.AEAD, error) {
	keySize, ok := algorithmKeySize[algorithm]
	if !ok {
		return nil, ErrBackupInvalidAlgorithm
	}
	block, err := aes.NewCipher(key.Bytes()[:keySize])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// sealPasswordBackup encrypts plaintext under a fresh password-derived key
// and returns the encoded envelope. The password is not wiped here; the
// caller owns it.
func sealPasswordBackup(plaintext []byte, algorithm string, password []byte) ([]byte, error) {
	if _, ok := algorithmKeySize[algorithm]; !ok {
		return nil, ErrBackupInvalidAlgorithm
	}
	key, err := backup.NewPasswordKey(password)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupFailed, Cause: err}
	}
	defer key.Wipe()

	gcm, err := passwordBackupGCM(algorithm, key)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupFailed, Cause: err}
	}

	envelope := passwordBackupEnvelope{
		passwordBackupHeader: passwordBackupHeader{
			Magic:     passwordBackupMagic,
			Version:   passwordBackupVersion,
			Algorithm: algorithm,
			KDF:       key.KDF(),
		},
		Nonce: make([]byte, gcm.NonceSize()),
	}
	if _, err := crand.Read(envelope.Nonce); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupFailed, Cause: err}
	}
	aad, err := envelope.aad()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupFailed, Cause: err}
	}
	envelope.Ciphertext = gcm.Seal(nil, envelope.Nonce, plaintext, aad)

	data, err := json.Marshal(&envelope)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrBackupFailed, Cause: err}
	}
	return data, nil
}

// openPasswordBackup decodes and decrypts an envelope written by
// sealPasswordBackup. algorithm is the operator's selection and must match
// the authenticated header. The password is not wiped here; the caller owns
// it.
func openPasswordBackup(data []byte, algorithm string, password []byte) ([]byte, error) {
	if _, ok := algorithmKeySize[algorithm]; !ok {
		return nil, ErrBackupInvalidAlgorithm
	}

	var envelope passwordBackupEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil || envelope.Magic != passwordBackupMagic {
		return nil, ErrRestoreLegacyFormat
	}
	if envelope.Version != passwordBackupVersion {
		return nil, ErrRestoreUnsupportedVersion
	}
	if envelope.Algorithm != algorithm {
		return nil, &DetailError{Err: ErrRestoreAlgorithmMismatch, Detail: ": backup uses " + envelope.Algorithm}
	}

	key, err := backup.DerivePasswordKey(envelope.KDF, password)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrRestoreKeyDerivationFailed, Cause: err}
	}
	defer key.Wipe()

	gcm, err := passwordBackupGCM(envelope.Algorithm, key)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrRestoreDecryptFailed, Cause: err}
	}
	// GCM Open panics on a nonce of the wrong length; the nonce comes from
	// the file, so check it first.
	if len(envelope.Nonce) != gcm.NonceSize() {
		return nil, ErrRestoreDecryptFailed
	}
	aad, err := envelope.aad()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrRestoreDecryptFailed, Cause: err}
	}
	plaintext, err := gcm.Open(nil, envelope.Nonce, envelope.Ciphertext, aad)
	if err != nil {
		return nil, ErrRestoreDecryptFailed
	}
	return plaintext, nil
}
