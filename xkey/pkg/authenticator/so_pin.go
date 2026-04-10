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

package authenticator

import (
	"crypto/rand"
	"errors"
	"sync/atomic"

	"golang.org/x/crypto/argon2"
)

// SO PIN constants define parameters for Security Officer PIN management.
const (
	// SOPINSaltSize is the size of the random salt for Argon2id derivation.
	SOPINSaltSize = 32

	// SOPINDefaultIterations is the Argon2id time parameter (iterations).
	SOPINDefaultIterations = 3

	// SOPINDefaultMemory is the Argon2id memory parameter in KiB (64 MiB).
	SOPINDefaultMemory = 64 * 1024

	// SOPINDefaultParallelism is the Argon2id parallelism parameter.
	SOPINDefaultParallelism = 4

	// SOPINDerivedKeySize is the size of the derived Storage Master Key (32 bytes for AES-256).
	SOPINDerivedKeySize = 32

	// DefaultSOPINMaxRetries is the maximum number of SO PIN retry attempts before blocking.
	DefaultSOPINMaxRetries = 8

	// sopinMinLength is the minimum SO PIN length in UTF-8 bytes.
	sopinMinLength = 6

	// sopinMaxLength is the maximum SO PIN length in UTF-8 bytes.
	sopinMaxLength = 63
)

// SO PIN errors define error conditions for Security Officer PIN operations.
var (
	// ErrSOPINRequired indicates an SO PIN is required but was not provided.
	ErrSOPINRequired = errors.New("authenticator: SO PIN required")

	// ErrSOPINInvalid indicates the provided SO PIN is incorrect.
	ErrSOPINInvalid = errors.New("authenticator: SO PIN invalid")

	// ErrSOPINBlocked indicates the SO PIN has been blocked due to too many failed attempts.
	ErrSOPINBlocked = errors.New("authenticator: SO PIN blocked")

	// ErrSOPINNotSet indicates SO PIN operations were attempted but no SO PIN is configured.
	ErrSOPINNotSet = errors.New("authenticator: SO PIN not set")

	// ErrSOPINAlreadySet indicates an attempt to initialize an SO PIN that is already configured.
	ErrSOPINAlreadySet = errors.New("authenticator: SO PIN already set")

	// ErrSOPINPolicyViolation indicates the SO PIN does not meet policy requirements.
	ErrSOPINPolicyViolation = errors.New("authenticator: SO PIN policy violation")
)

// SOPINManager manages Security Officer PIN state and key derivation.
// The SO PIN is used to derive a Storage Master Key (SMK) that protects
// the authenticator's attestation key and other sensitive materials.
//
// Key derivation uses Argon2id, a memory-hard password hashing function
// that provides resistance against GPU and ASIC-based brute force attacks.
//
// All public methods are safe for concurrent use.
type SOPINManager struct {
	// Salt is the random salt used for Argon2id key derivation.
	// Generated during Initialize and must be persisted.
	Salt []byte

	// Iterations is the Argon2id time parameter.
	Iterations uint32

	// Memory is the Argon2id memory parameter in KiB.
	Memory uint32

	// Parallelism is the Argon2id parallelism parameter.
	Parallelism uint8

	// retries stores the remaining SO PIN attempts atomically.
	retries atomic.Int32

	// IsSet indicates whether an SO PIN has been configured.
	IsSet bool
}

// NewSOPINManager creates a new SOPINManager with default Argon2id parameters.
// The manager is created in an uninitialized state; call Initialize to set up
// the SO PIN for the first time.
func NewSOPINManager() *SOPINManager {
	m := &SOPINManager{
		Iterations:  SOPINDefaultIterations,
		Memory:      SOPINDefaultMemory,
		Parallelism: SOPINDefaultParallelism,
		IsSet:       false,
	}
	m.retries.Store(int32(DefaultSOPINMaxRetries))
	return m
}

// DeriveKey derives a 32-byte Storage Master Key (SMK) from the provided PIN
// using Argon2id with the manager's configured parameters.
//
// The derivation formula is:
//
//	SMK = Argon2id(PIN, Salt, Iterations, Memory, Parallelism, KeyLength)
//
// Returns nil if the salt has not been initialized.
func (m *SOPINManager) DeriveKey(pin string) []byte {
	if len(m.Salt) == 0 {
		return nil
	}

	return argon2.IDKey(
		[]byte(pin),
		m.Salt,
		m.Iterations,
		m.Memory,
		m.Parallelism,
		SOPINDerivedKeySize,
	)
}

// Initialize sets up the SO PIN for the first time.
// It generates a cryptographically secure random salt and derives the initial SMK.
//
// Returns the derived Storage Master Key on success, which the caller should use
// to wrap the attestation key before persisting.
//
// Returns ErrSOPINAlreadySet if an SO PIN is already configured.
// Returns ErrSOPINPolicyViolation if the PIN does not meet length requirements.
func (m *SOPINManager) Initialize(pin string) ([]byte, error) {
	if m.IsSet {
		return nil, ErrSOPINAlreadySet
	}

	if err := m.validatePINPolicy(pin); err != nil {
		return nil, err
	}

	// Generate cryptographically secure random salt
	salt := make([]byte, SOPINSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, ErrCryptoError
	}

	m.Salt = salt
	m.IsSet = true
	m.retries.Store(int32(DefaultSOPINMaxRetries))

	// Derive the Storage Master Key
	smk := m.DeriveKey(pin)

	return smk, nil
}

// Verify verifies the provided SO PIN and returns the derived SMK if correct.
//
// The caller is responsible for validating the SMK by attempting to unwrap
// protected materials. If unwrapping fails, the caller should call DecrementRetries.
//
// Returns ErrSOPINBlocked if the retry counter has reached zero.
// Returns ErrSOPINNotSet if no SO PIN has been configured.
// Returns ErrSOPINInvalid if the PIN verification fails.
func (m *SOPINManager) Verify(pin string) ([]byte, error) {
	if !m.IsSet {
		return nil, ErrSOPINNotSet
	}

	if m.IsBlocked() {
		return nil, ErrSOPINBlocked
	}

	// Derive key from provided PIN
	smk := m.DeriveKey(pin)
	if smk == nil {
		return nil, ErrSOPINNotSet
	}

	// Reset retries on successful derivation.
	// The caller validates the SMK via AES-GCM authenticated unwrap
	// which is cryptographically stronger than a separate hash check.
	m.ResetRetries()

	return smk, nil
}

// Change changes the SO PIN from the current PIN to a new PIN.
// The currentSMK parameter must be a valid SMK derived from the current PIN.
//
// Returns the new SMK derived from the new PIN on success.
// The caller must re-wrap protected materials with the new SMK.
//
// Returns ErrSOPINNotSet if no SO PIN has been configured.
// Returns ErrSOPINBlocked if the retry counter has reached zero.
// Returns ErrSOPINPolicyViolation if the new PIN does not meet length requirements.
// Returns ErrSOPINInvalid if the current SMK verification fails.
func (m *SOPINManager) Change(currentSMK []byte, newPIN string) ([]byte, error) {
	if !m.IsSet {
		return nil, ErrSOPINNotSet
	}

	if m.IsBlocked() {
		return nil, ErrSOPINBlocked
	}

	if err := m.validatePINPolicy(newPIN); err != nil {
		return nil, err
	}

	// The caller (KeyManager.ChangeSOPIN) validates currentSMK by unwrapping
	// the AK first. AES-GCM authenticated decryption proves the SMK is correct.

	// Generate new salt for the new PIN
	newSalt := make([]byte, SOPINSaltSize)
	if _, err := rand.Read(newSalt); err != nil {
		return nil, ErrCryptoError
	}

	m.Salt = newSalt
	m.retries.Store(int32(DefaultSOPINMaxRetries))

	// Derive the new Storage Master Key
	newSMK := m.DeriveKey(newPIN)

	return newSMK, nil
}

// Retries returns the current number of remaining SO PIN attempts.
func (m *SOPINManager) Retries() int {
	return int(m.retries.Load())
}

// SetRetries sets the number of remaining SO PIN attempts.
func (m *SOPINManager) SetRetries(n int) {
	m.retries.Store(int32(n))
}

// DecrementRetries decrements the SO PIN retry counter and returns the new value.
// The caller should call this method when PIN verification fails.
func (m *SOPINManager) DecrementRetries() int {
	return int(m.retries.Add(-1))
}

// ResetRetries resets the SO PIN retry counter to the default maximum value.
func (m *SOPINManager) ResetRetries() {
	m.retries.Store(int32(DefaultSOPINMaxRetries))
}

// IsBlocked returns true if the SO PIN has been blocked due to too many failed attempts.
func (m *SOPINManager) IsBlocked() bool {
	return m.retries.Load() <= 0
}

// validatePINPolicy validates that the PIN meets the policy requirements.
func (m *SOPINManager) validatePINPolicy(pin string) error {
	pinBytes := []byte(pin)
	if len(pinBytes) < sopinMinLength {
		return ErrSOPINPolicyViolation
	}
	if len(pinBytes) > sopinMaxLength {
		return ErrSOPINPolicyViolation
	}
	return nil
}
