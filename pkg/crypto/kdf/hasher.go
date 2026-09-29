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
	"crypto/fips140"
	cryptorand "crypto/rand"
	"errors"

	"github.com/jeremyhahn/go-enclave"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
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

	// ErrHasherParamsMismatch indicates a PasswordKeyParams record whose
	// algorithm or cost parameters differ from the ones its version pins.
	ErrHasherParamsMismatch = errors.New("kdf: password key parameters do not match their version")
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
// FIPS mode is crypto/fips140.Enabled directly (go-xkms #21): GODEBUG=fips140
// =on|only at runtime, or a GOFIPS140 build.
func NewFIPSAwareHasher() *PasswordHasher {
	version := HashV1
	if fips140.Enabled() {
		version = HashV2
	}
	// version is always HashV1 or HashV2 here, the only two values
	// NewPasswordHasher accepts, so err is unreachable. A third HashVersion
	// added to this package without updating this function is exactly the
	// programming error panic exists for: NewFIPSAwareHasher has no error
	// return of its own to surface it through instead.
	h, err := NewPasswordHasher(version)
	if err != nil {
		panic(&errs.Wrapped{Msg: "kdf: unreachable invalid hasher version", Err: err})
	}
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
		enclave.Wipe(salt)
		return nil, nil, 0, err
	}

	return key, salt, h.version, nil
}

// hashProfiles pins the algorithm and cost parameters of every HashVersion.
// It is the single source of truth for both DeriveKey and the persisted
// PasswordKeyParams record, so the two can never describe different
// derivations. Salt is filled in per derivation.
var hashProfiles = map[HashVersion]KDFParams{
	HashV1: {
		Algorithm: AlgorithmArgon2id,
		KeyLength: KeyLength,
		Time:      defaultArgon2Time,
		Memory:    defaultArgon2Memory,
		Threads:   defaultArgon2Threads,
	},
	HashV2: {
		Algorithm:  AlgorithmPBKDF2,
		KeyLength:  KeyLength,
		Iterations: defaultPBKDF2Iterations,
		Hash:       crypto.SHA256,
	},
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

	profile, ok := hashProfiles[version]
	if !ok {
		return nil, ErrHasherInvalidVersion
	}
	profile.Salt = salt

	if profile.Algorithm == AlgorithmPBKDF2 {
		return h.pbkdf2.DeriveKey(password, &profile)
	}
	return h.argon2.DeriveKey(password, &profile)
}

// PasswordKeyParams is the self-describing record of one password-based key
// derivation: the hasher version, the algorithm and cost parameters that
// version pins, and the random salt. It is meant to be persisted beside the
// ciphertext it protects -- and authenticated with it, for example as AEAD
// additional data -- so the key can be re-derived from the password alone.
//
// The cost fields are descriptive, not negotiable: DeriveKeyFromParams
// refuses a record whose algorithm or costs differ from the ones its version
// pins, so a tampered header can neither weaken the derivation nor demand an
// unbounded amount of memory.
type PasswordKeyParams struct {
	// Version is the hasher version that produced the key.
	Version HashVersion `json:"version"`

	// Algorithm is the KDF algorithm the version pins.
	Algorithm KDFAlgorithm `json:"algorithm"`

	// Salt is the random per-derivation salt.
	Salt []byte `json:"salt"`

	// Time is the Argon2 time cost (Argon2 only).
	Time uint32 `json:"time,omitempty"`

	// MemoryKiB is the Argon2 memory cost in KiB (Argon2 only).
	MemoryKiB uint32 `json:"memory_kib,omitempty"`

	// Threads is the Argon2 parallelism (Argon2 only).
	Threads uint8 `json:"threads,omitempty"`

	// Iterations is the PBKDF2 iteration count (PBKDF2 only).
	Iterations int `json:"iterations,omitempty"`

	// Hash names the PBKDF2 PRF hash (PBKDF2 only).
	Hash string `json:"hash,omitempty"`

	// KeyLength is the derived key length in bytes.
	KeyLength int `json:"key_length"`
}

// newPasswordKeyParams describes version's profile with the given salt.
func newPasswordKeyParams(version HashVersion, salt []byte) (*PasswordKeyParams, error) {
	profile, ok := hashProfiles[version]
	if !ok {
		return nil, ErrHasherInvalidVersion
	}
	params := &PasswordKeyParams{
		Version:    version,
		Algorithm:  profile.Algorithm,
		Salt:       salt,
		Time:       profile.Time,
		MemoryKiB:  profile.Memory,
		Threads:    profile.Threads,
		Iterations: profile.Iterations,
		KeyLength:  profile.KeyLength,
	}
	if profile.Hash != 0 {
		params.Hash = profile.Hash.String()
	}
	return params, nil
}

// sameDerivation reports whether p and q describe the same algorithm and
// costs. The salt is deliberately not compared.
func (p *PasswordKeyParams) sameDerivation(q *PasswordKeyParams) bool {
	return p.Version == q.Version &&
		p.Algorithm == q.Algorithm &&
		p.Time == q.Time &&
		p.MemoryKiB == q.MemoryKiB &&
		p.Threads == q.Threads &&
		p.Iterations == q.Iterations &&
		p.Hash == q.Hash &&
		p.KeyLength == q.KeyLength
}

// NewKeyParams generates a fresh random salt and returns the parameter
// record for this hasher's version. Pass it to DeriveKeyFromParams to derive
// the key, and persist it so the key can be derived again.
func (h *PasswordHasher) NewKeyParams() (*PasswordKeyParams, error) {
	salt := make([]byte, SaltLength)
	if _, err := cryptorand.Read(salt); err != nil {
		return nil, err
	}
	return newPasswordKeyParams(h.version, salt)
}

// DeriveKeyFromParams derives the key a PasswordKeyParams record describes.
// The record's version selects the derivation, so a hasher of either version
// can re-derive keys produced by the other. It returns ErrHasherParamsMismatch
// when the recorded algorithm or costs differ from the ones the version pins,
// ErrHasherInvalidVersion for an unknown version, and ErrHasherInvalidSalt
// for a missing or short salt.
func (h *PasswordHasher) DeriveKeyFromParams(password []byte, params *PasswordKeyParams) ([]byte, error) {
	if params == nil {
		return nil, ErrHasherParamsMismatch
	}
	pinned, err := newPasswordKeyParams(params.Version, params.Salt)
	if err != nil {
		return nil, err
	}
	if !pinned.sameDerivation(params) {
		return nil, ErrHasherParamsMismatch
	}
	return h.DeriveKey(password, params.Salt, params.Version)
}

// IsFIPS returns true if the hasher is using FIPS-compliant algorithms (V2).
func (h *PasswordHasher) IsFIPS() bool {
	return h.version == HashV2
}

// Version returns the current hash version.
func (h *PasswordHasher) Version() HashVersion {
	return h.version
}
