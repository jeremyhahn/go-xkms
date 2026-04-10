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
	"crypto"
	cryptorand "crypto/rand"
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
)

// HashVersion identifies the password hashing version.
type HashVersion int

const (
	// HashV1 uses Argon2id (standard, non-FIPS mode).
	HashV1 HashVersion = 1
	// HashV2 uses PBKDF2-SHA256 (FIPS-compliant mode).
	HashV2 HashVersion = 2

	// SaltLength is the length of randomly generated salts in bytes.
	SaltLength = 32

	// KeyLength is the derived key length in bytes.
	KeyLength = 32

	// Default Argon2id parameters.
	defaultArgon2Time    = 3
	defaultArgon2Memory  = 64 * 1024 // 64 MiB
	defaultArgon2Threads = 4

	// Default PBKDF2 parameters.
	defaultPBKDF2Iterations = 600000

	// minHasherSaltLength is the minimum salt length accepted by DeriveKey.
	minHasherSaltLength = 16
)

// Password hasher errors.
var (
	// ErrHasherInvalidVersion indicates an unsupported hash version.
	ErrHasherInvalidVersion = errors.New("kdf: unsupported hash version")

	// ErrHasherInvalidPassword indicates an empty password.
	ErrHasherInvalidPassword = errors.New("kdf: empty password")

	// ErrHasherInvalidSalt indicates an empty or too-short salt.
	ErrHasherInvalidSalt = errors.New("kdf: invalid salt for hasher")
)

// PasswordHasher provides FIPS-aware password hashing and key derivation.
type PasswordHasher struct {
	version HashVersion
	argon2  *Argon2Adapter
	pbkdf2  *PBKDF2Adapter
}

// NewPasswordHasher creates a new PasswordHasher with the specified version.
// Both the Argon2 and PBKDF2 adapters are initialised so that DeriveKey can
// verify hashes produced by any version.
func NewPasswordHasher(version HashVersion) (*PasswordHasher, error) {
	if version != HashV1 && version != HashV2 {
		return nil, ErrHasherInvalidVersion
	}
	return &PasswordHasher{
		version: version,
		argon2:  NewArgon2idAdapter(),
		pbkdf2:  NewPBKDF2Adapter(),
	}, nil
}

// NewFIPSAwareHasher creates a PasswordHasher that auto-selects the version
// based on FIPS mode: V2 (PBKDF2) if FIPS enabled, V1 (Argon2id) otherwise.
func NewFIPSAwareHasher() *PasswordHasher {
	version := HashV1
	if fips.Enabled() {
		version = HashV2
	}
	// Version is always valid here, so the error can be safely ignored.
	h, _ := NewPasswordHasher(version)
	return h
}

// Hash generates a random salt and derives a key from the password.
// Returns the derived key, the salt, the version used, or an error.
// The caller should store the salt and version alongside the hash for later
// verification.
func (h *PasswordHasher) Hash(password []byte) (key, salt []byte, version HashVersion, err error) {
	if len(password) == 0 {
		return nil, nil, 0, ErrHasherInvalidPassword
	}

	salt = make([]byte, SaltLength)
	if _, err = cryptorand.Read(salt); err != nil {
		return nil, nil, 0, err
	}

	key, err = h.DeriveKey(password, salt, h.version)
	if err != nil {
		mem.Zero(salt)
		return nil, nil, 0, err
	}

	return key, salt, h.version, nil
}

// DeriveKey derives a key from the password and salt using the specified version.
// This is used for verification: given a stored salt and version, derive the key
// and compare with the stored hash.
func (h *PasswordHasher) DeriveKey(password, salt []byte, version HashVersion) ([]byte, error) {
	if len(password) == 0 {
		return nil, ErrHasherInvalidPassword
	}
	if len(salt) < minHasherSaltLength {
		return nil, ErrHasherInvalidSalt
	}

	switch version {
	case HashV1:
		return h.argon2.DeriveKey(password, &KDFParams{
			Algorithm: AlgorithmArgon2id,
			Salt:      salt,
			KeyLength: KeyLength,
			Time:      defaultArgon2Time,
			Memory:    defaultArgon2Memory,
			Threads:   defaultArgon2Threads,
		})
	case HashV2:
		return h.pbkdf2.DeriveKey(password, &KDFParams{
			Algorithm:  AlgorithmPBKDF2,
			Salt:       salt,
			KeyLength:  KeyLength,
			Iterations: defaultPBKDF2Iterations,
			Hash:       crypto.SHA256,
		})
	default:
		return nil, ErrHasherInvalidVersion
	}
}

// IsFIPS returns true if the hasher is using FIPS-compliant algorithms (V2).
func (h *PasswordHasher) IsFIPS() bool {
	return h.version == HashV2
}

// Version returns the current hash version.
func (h *PasswordHasher) Version() HashVersion {
	return h.version
}
