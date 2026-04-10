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

package config

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/hkdf"
)

const (
	// hmacFileName is the name of the policy HMAC file stored in the config directory.
	hmacFileName = "xkey_policy.hmac"

	// hmacAlgorithm is the algorithm identifier stored in the HMAC file metadata.
	hmacAlgorithm = "HMAC-SHA256"

	// hmacVersion is the current schema version for the HMAC file format.
	hmacVersion = 1

	// hmacSaltLen is the number of random bytes generated for each HMAC salt.
	hmacSaltLen = 16

	// hmacKeyLen is the derived HMAC key length in bytes.
	hmacKeyLen = 32

	// hkdfInfo is the context string used in HKDF expansion to domain-separate
	// the policy integrity key from other keys derived from the SO PIN.
	hkdfInfo = "xkey-policy-integrity"

	// Argon2id parameters matching pkg/pin/store.go for consistency.
	argon2Time    = 3
	argon2Memory  = 64 * 1024
	argon2Threads = 4
	argon2KeyLen  = 32
)

// PolicyHMAC is the on-disk representation of the policy integrity tag.
// It is stored as JSON at ~/.config/xkey/xkey_policy.hmac and contains the
// salt needed to re-derive the HMAC key plus the HMAC value itself.
type PolicyHMAC struct {
	Version    int    `json:"version"`
	Algorithm  string `json:"algorithm"`
	Salt       []byte `json:"salt"`
	HMAC       []byte `json:"hmac"`
	TPMNVIndex uint32 `json:"tpm_nv_index,omitempty"`
}

// IsEnterpriseMode returns true if the HMAC file exists in the config directory.
// Enterprise mode is detected by HMAC file existence, not a config flag.
// This allows the application to load policy without requiring the SO PIN
// at startup; tamper detection is deferred until the SO logs in.
func IsEnterpriseMode(configDir string) bool {
	_, err := os.Stat(PolicyHMACPath(configDir))
	return err == nil
}

// PolicyHMACPath returns the path to the HMAC file in the given config directory.
func PolicyHMACPath(configDir string) string {
	return filepath.Join(configDir, hmacFileName)
}

// ComputePolicyHMAC derives an HMAC key from the SO PIN and computes HMAC-SHA256
// over the canonical JSON representation of the policy section.
//
// Key derivation chain:
//
//	Argon2id(soPIN, salt) -> HKDF(derived, salt, "xkey-policy-integrity") -> 32-byte HMAC key
//	HMAC-SHA256(key, canonical_json) -> tag
func ComputePolicyHMAC(policy *PolicySection, soPIN string, salt []byte) ([]byte, error) {
	if policy == nil {
		return nil, errors.Join(ErrPolicyInvalid, errors.New("policy is nil"))
	}
	if soPIN == "" {
		return nil, ErrPolicySOPINRequired
	}
	if len(salt) == 0 {
		return nil, errors.Join(ErrPolicyKeyDerivationFailed, errors.New("salt is empty"))
	}

	canonical, err := PolicyCanonicalJSON(policy)
	if err != nil {
		return nil, errors.Join(ErrPolicyInvalid, err)
	}

	key, err := deriveHMACKey(soPIN, salt)
	if err != nil {
		return nil, err
	}

	mac := hmac.New(sha256.New, key)
	mac.Write(canonical)
	return mac.Sum(nil), nil
}

// VerifyPolicyHMAC verifies the HMAC of the policy section using the SO PIN.
// It returns (true, nil) if the HMAC matches, (false, nil) if the HMAC does
// not match, or (false, error) if the verification could not be performed.
func VerifyPolicyHMAC(policy *PolicySection, hmacPath string, soPIN string) (bool, error) {
	if policy == nil {
		return false, errors.Join(ErrPolicyInvalid, errors.New("policy is nil"))
	}
	if soPIN == "" {
		return false, ErrPolicySOPINRequired
	}

	stored, err := LoadPolicyHMAC(hmacPath)
	if err != nil {
		return false, err
	}

	computed, err := ComputePolicyHMAC(policy, soPIN, stored.Salt)
	if err != nil {
		return false, err
	}

	if !hmac.Equal(computed, stored.HMAC) {
		return false, nil
	}

	return true, nil
}

// WritePolicyHMAC computes and writes the HMAC file for the given policy.
// A fresh random salt is generated for each write. The file is written
// atomically using a temporary file and rename pattern for crash safety.
func WritePolicyHMAC(policy *PolicySection, soPIN string, hmacPath string) error {
	if policy == nil {
		return errors.Join(ErrPolicyHMACSaveFailed, errors.New("policy is nil"))
	}
	if soPIN == "" {
		return ErrPolicySOPINRequired
	}

	salt := make([]byte, hmacSaltLen)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, err)
	}

	tag, err := ComputePolicyHMAC(policy, soPIN, salt)
	if err != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, err)
	}

	record := &PolicyHMAC{
		Version:   hmacVersion,
		Algorithm: hmacAlgorithm,
		Salt:      salt,
		HMAC:      tag,
	}

	data, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, err)
	}

	dir := filepath.Dir(hmacPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, err)
	}

	tmpFile, err := os.CreateTemp(dir, ".xkey-policy-hmac-*.tmp")
	if err != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, err)
	}
	tmpPath := tmpFile.Name()

	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, writeErr := tmpFile.Write(data); writeErr != nil {
		tmpFile.Close()
		return errors.Join(ErrPolicyHMACSaveFailed, writeErr)
	}

	if syncErr := tmpFile.Sync(); syncErr != nil {
		tmpFile.Close()
		return errors.Join(ErrPolicyHMACSaveFailed, syncErr)
	}

	if closeErr := tmpFile.Close(); closeErr != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, closeErr)
	}

	if chmodErr := os.Chmod(tmpPath, 0600); chmodErr != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, chmodErr)
	}

	if renameErr := os.Rename(tmpPath, hmacPath); renameErr != nil {
		return errors.Join(ErrPolicyHMACSaveFailed, renameErr)
	}

	success = true
	return nil
}

// LoadPolicyHMAC reads and deserializes the HMAC file from disk.
func LoadPolicyHMAC(hmacPath string) (*PolicyHMAC, error) {
	data, err := os.ReadFile(hmacPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, errors.Join(ErrPolicyHMACMissing, err)
		}
		return nil, errors.Join(ErrPolicyHMACLoadFailed, err)
	}

	record := &PolicyHMAC{}
	if err := json.Unmarshal(data, record); err != nil {
		return nil, errors.Join(ErrPolicyHMACLoadFailed, err)
	}

	if record.Version == 0 {
		return nil, errors.Join(ErrPolicyHMACLoadFailed, errors.New("HMAC file has invalid version"))
	}
	if len(record.Salt) == 0 {
		return nil, errors.Join(ErrPolicyHMACLoadFailed, errors.New("HMAC file has empty salt"))
	}
	if len(record.HMAC) == 0 {
		return nil, errors.Join(ErrPolicyHMACLoadFailed, errors.New("HMAC file has empty HMAC"))
	}

	return record, nil
}

// deriveHMACKey derives the HMAC key from the SO PIN and salt using Argon2id
// for memory-hard password stretching followed by HKDF for domain separation.
//
// Argon2id(soPIN, salt, t=3, m=64MB, p=4, keyLen=32) -> intermediate
// HKDF-SHA256(intermediate, salt, "xkey-policy-integrity") -> 32-byte key
func deriveHMACKey(soPIN string, salt []byte) ([]byte, error) {
	if soPIN == "" {
		return nil, errors.Join(ErrPolicyKeyDerivationFailed, errors.New("SO PIN is empty"))
	}
	if len(salt) == 0 {
		return nil, errors.Join(ErrPolicyKeyDerivationFailed, errors.New("salt is empty"))
	}

	intermediate := argon2.IDKey(
		[]byte(soPIN),
		salt,
		argon2Time,
		argon2Memory,
		argon2Threads,
		argon2KeyLen,
	)

	hkdfReader := hkdf.New(sha256.New, intermediate, salt, []byte(hkdfInfo))

	key := make([]byte, hmacKeyLen)
	if _, err := io.ReadFull(hkdfReader, key); err != nil {
		return nil, errors.Join(ErrPolicyKeyDerivationFailed, err)
	}

	return key, nil
}
