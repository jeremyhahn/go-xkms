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

package pin

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/subtle"
	"encoding/json"
	"hash"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/fips"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// HashAlgorithm identifies the top-level PIN hashing algorithm.
type HashAlgorithm string

const (
	// HashArgon2id selects the Argon2id password hashing algorithm.
	HashArgon2id HashAlgorithm = "argon2id"

	// HashPBKDF2 selects the PBKDF2 password hashing algorithm (FIPS-approved).
	HashPBKDF2 HashAlgorithm = "pbkdf2"
)

// HashConfig holds configurable parameters for PIN hashing. The Algorithm
// field selects which hash function is used; only the parameters relevant
// to the selected algorithm need to be populated.
type HashConfig struct {
	// Algorithm selects the hash function: HashArgon2id or HashPBKDF2.
	Algorithm HashAlgorithm

	// Argon2id parameters (used when Algorithm == HashArgon2id).
	Time    uint32 // Number of passes over memory.
	Memory  uint32 // Memory usage in KiB.
	Threads uint8  // Degree of parallelism.
	KeyLen  uint32 // Output key length in bytes.
	SaltLen int    // Salt length in bytes.

	// PBKDF2 parameters (used when Algorithm == HashPBKDF2).
	PBKDF2Hash types.HashName // Underlying hash function (SHA-256, etc.).
	Iterations int            // Number of PBKDF2 iterations.
}

// DefaultHashConfig returns a HashConfig using Argon2id with production-grade
// parameters suitable for non-FIPS environments.
func DefaultHashConfig() HashConfig {
	return HashConfig{
		Algorithm: HashArgon2id,
		Time:      3,
		Memory:    64 * 1024, // 64 MiB
		Threads:   4,
		KeyLen:    32,
		SaltLen:   16,
	}
}

// FIPSHashConfig returns a HashConfig using PBKDF2-SHA256 with NIST SP 800-132
// recommended iteration count for FIPS 140 compliance.
func FIPSHashConfig() HashConfig {
	return HashConfig{
		Algorithm:  HashPBKDF2,
		PBKDF2Hash: types.HashSHA256,
		Iterations: 600000,
		KeyLen:     32,
		SaltLen:    16,
	}
}

// AutoDetectHashConfig returns FIPSHashConfig when FIPS mode is active,
// otherwise DefaultHashConfig.
func AutoDetectHashConfig() HashConfig {
	if fips.Enabled() {
		return FIPSHashConfig()
	}
	return DefaultHashConfig()
}

// PINRecord stores the hash of a single PIN (user or SO) together with
// algorithm metadata so that verification can reproduce the same hash
// without out-of-band parameter knowledge.
type PINRecord struct {
	Algorithm string          `json:"algorithm"`        // "argon2id" or "pbkdf2"
	Hash      []byte          `json:"hash"`             // Derived key bytes.
	Salt      []byte          `json:"salt"`             // Random salt.
	Params    json.RawMessage `json:"params,omitempty"` // Algorithm-specific parameters.
}

// argon2idParams is the JSON-serializable parameter set for Argon2id records.
type argon2idParams struct {
	Time    uint32 `json:"time"`
	Memory  uint32 `json:"memory"`
	Threads uint8  `json:"threads"`
	KeyLen  uint32 `json:"key_len"`
}

// pbkdf2Params is the JSON-serializable parameter set for PBKDF2 records.
type pbkdf2Params struct {
	Hash       string `json:"hash"`
	Iterations int    `json:"iterations"`
	KeyLen     uint32 `json:"key_len"`
}

// hashPINWithConfig hashes a PIN using the configured algorithm and returns
// a PINRecord containing the hash, salt, and algorithm-specific parameters
// needed for subsequent verification.
func hashPINWithConfig(pin string, cfg HashConfig) (*PINRecord, error) {
	salt := make([]byte, cfg.SaltLen)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}

	var derivedKey []byte
	var params json.RawMessage

	switch cfg.Algorithm {
	case HashArgon2id:
		derivedKey = argon2.IDKey([]byte(pin), salt, cfg.Time, cfg.Memory, cfg.Threads, cfg.KeyLen)
		p, err := json.Marshal(argon2idParams{
			Time:    cfg.Time,
			Memory:  cfg.Memory,
			Threads: cfg.Threads,
			KeyLen:  cfg.KeyLen,
		})
		if err != nil {
			return nil, err
		}
		params = p

	case HashPBKDF2:
		hashFunc, err := resolveHashFunc(cfg.PBKDF2Hash)
		if err != nil {
			return nil, err
		}
		derivedKey = pbkdf2.Key([]byte(pin), salt, cfg.Iterations, int(cfg.KeyLen), hashFunc)
		p, err := json.Marshal(pbkdf2Params{
			Hash:       string(cfg.PBKDF2Hash),
			Iterations: cfg.Iterations,
			KeyLen:     cfg.KeyLen,
		})
		if err != nil {
			return nil, err
		}
		params = p

	default:
		return nil, ErrUnsupportedHashAlgorithm
	}

	return &PINRecord{
		Algorithm: string(cfg.Algorithm),
		Hash:      derivedKey,
		Salt:      salt,
		Params:    params,
	}, nil
}

// verifyPINRecord verifies a PIN against a PINRecord by re-deriving the hash
// using the stored algorithm and parameters, then performing a constant-time
// comparison.
func verifyPINRecord(pin string, record *PINRecord) (bool, error) {
	switch HashAlgorithm(record.Algorithm) {
	case HashArgon2id:
		return verifyArgon2id(pin, record)
	case HashPBKDF2:
		return verifyPBKDF2(pin, record)
	default:
		return false, ErrUnsupportedHashAlgorithm
	}
}

// verifyArgon2id re-derives an Argon2id hash and compares it to the stored
// record using constant-time comparison.
func verifyArgon2id(pin string, record *PINRecord) (bool, error) {
	var params argon2idParams
	if err := json.Unmarshal(record.Params, &params); err != nil {
		// Fall back to defaults for backward compatibility with records
		// that were created before parameters were stored.
		params = argon2idParams{
			Time:    3,
			Memory:  64 * 1024,
			Threads: 4,
			KeyLen:  32,
		}
	}
	computed := argon2.IDKey([]byte(pin), record.Salt, params.Time, params.Memory, params.Threads, params.KeyLen)
	return subtle.ConstantTimeCompare(computed, record.Hash) == 1, nil
}

// verifyPBKDF2 re-derives a PBKDF2 hash and compares it to the stored record
// using constant-time comparison.
func verifyPBKDF2(pin string, record *PINRecord) (bool, error) {
	var params pbkdf2Params
	if err := json.Unmarshal(record.Params, &params); err != nil {
		return false, err
	}
	hashFunc, err := resolveHashFunc(types.HashName(params.Hash))
	if err != nil {
		return false, err
	}
	computed := pbkdf2.Key([]byte(pin), record.Salt, params.Iterations, int(params.KeyLen), hashFunc)
	return subtle.ConstantTimeCompare(computed, record.Hash) == 1, nil
}

// resolveHashFunc maps a types.HashName to the corresponding hash.Hash
// constructor for use with PBKDF2.
func resolveHashFunc(name types.HashName) (func() hash.Hash, error) {
	switch name {
	case types.HashSHA256:
		return sha256.New, nil
	case types.HashSHA384:
		return sha512.New384, nil
	case types.HashSHA512:
		return sha512.New, nil
	case types.HashSHA512_256:
		return sha512.New512_256, nil
	default:
		return nil, &ErrUnsupportedPBKDF2Hash{Hash: name}
	}
}
