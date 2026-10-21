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
	"crypto/rand"
	"fmt"

	"github.com/jeremyhahn/go-enclave"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// KeySize is the length in bytes of a backup sealing key (AES-256).
const KeySize = 32

// Key is a backup sealing key. A password-derived key carries the KDF record
// that re-derives it from the password; the record is written into the
// envelope header and authenticated with the ciphertext. A raw key --
// randomly generated or supplied by the operator -- carries no record.
//
// Key derivation is the one canonical go-xkms password hasher
// (xkms.NewFIPSAwareHasher): Argon2id (t=3, m=64 MiB, p=4) with a random
// 32-byte salt, or PBKDF2-SHA256 when the Go FIPS 140 module is enabled.
// Every xkey backup format derives its password keys through this type.
type Key struct {
	material []byte
	kdf      *xkms.PasswordKeyParams
}

// NewRawKey returns a Key holding a copy of material, which must be exactly
// KeySize bytes. It returns ErrInvalidKey otherwise.
func NewRawKey(material []byte) (*Key, error) {
	if len(material) != KeySize {
		return nil, &DetailError{Err: ErrInvalidKey, Detail: fmt.Sprintf(": got %d bytes, want %d", len(material), KeySize)}
	}
	return &Key{material: append([]byte(nil), material...)}, nil
}

// GenerateKey returns a random raw Key.
func GenerateKey() (*Key, error) {
	material := make([]byte, KeySize)
	if _, err := rand.Read(material); err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKeyDerivationFailed, Cause: err}
	}
	return &Key{material: material}, nil
}

// NewPasswordKey derives a fresh Key from password under a new random salt.
// Two calls with the same password yield different keys. The password is
// neither retained nor wiped: the caller owns it and wipes it.
func NewPasswordKey(password []byte) (*Key, error) {
	hasher := xkms.NewFIPSAwareHasher()
	params, err := hasher.NewKeyParams()
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKeyDerivationFailed, Cause: err}
	}
	return derivePasswordKey(hasher, params, password)
}

// DerivePasswordKey re-derives the Key a KDF record describes. A nil record
// means the envelope was sealed with a raw key, and ErrNotPasswordSealed is
// returned. A record whose costs differ from the ones its version pins is
// refused before any derivation runs. The password is neither retained nor
// wiped.
func DerivePasswordKey(params *xkms.PasswordKeyParams, password []byte) (*Key, error) {
	if params == nil {
		return nil, ErrNotPasswordSealed
	}
	return derivePasswordKey(xkms.NewFIPSAwareHasher(), params, password)
}

// derivePasswordKey runs the derivation and checks the key length.
func derivePasswordKey(hasher *xkms.PasswordHasher, params *xkms.PasswordKeyParams, password []byte) (*Key, error) {
	material, err := hasher.DeriveKeyFromParams(password, params)
	if err != nil {
		return nil, &SentinelCauseError{Sentinel: ErrKeyDerivationFailed, Cause: err}
	}
	if len(material) != KeySize {
		enclave.Wipe(material)
		return nil, &DetailError{Err: ErrInvalidKey, Detail: fmt.Sprintf(": derived %d bytes, want %d", len(material), KeySize)}
	}
	return &Key{material: material, kdf: params}, nil
}

// Bytes returns the key material. The slice aliases the Key: it is wiped by
// Wipe and must not be retained.
func (k *Key) Bytes() []byte {
	return k.material
}

// KDF returns the key's derivation record, or nil for a raw key.
func (k *Key) KDF() *xkms.PasswordKeyParams {
	return k.kdf
}

// Wipe zeroes the key material. A nil Key is a no-op.
func (k *Key) Wipe() {
	if k == nil {
		return
	}
	enclave.Wipe(k.material)
}

// PasswordKey validates the envelope and re-derives its sealing key from
// password using the KDF record in its header. A version 1 envelope is
// refused with ErrLegacyBackupFormat before any derivation, and an envelope
// sealed with a raw key returns ErrNotPasswordSealed.
func (eb *EncryptedBackup) PasswordKey(password []byte) (*Key, error) {
	if err := validateEncryptedBackup(eb); err != nil {
		return nil, err
	}
	return DerivePasswordKey(eb.KDF, password)
}
