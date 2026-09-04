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

	// DefaultSOPINMaxRetries is the total number of SO PIN attempts allowed
	// before the token locks out. CTAP 2.1 §6.5.5.7 sets the same budget of 8
	// for the user PIN; the Security Officer credential uses it too.
	DefaultSOPINMaxRetries = 8

	// SOPINMaxConsecutiveFailures is the number of consecutive failed SO PIN
	// attempts allowed within a single power cycle. CTAP 2.1 §6.5.5.7 requires
	// the authenticator to refuse further attempts after three consecutive
	// mismatches until it is power-cycled, which bounds an online brute force
	// far below the total retry budget.
	SOPINMaxConsecutiveFailures = 3

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

	// ErrSOPINBlocked indicates the SO PIN retry budget is exhausted. This is
	// terminal: only authenticatorReset clears it.
	ErrSOPINBlocked = errors.New("authenticator: SO PIN blocked")

	// ErrSOPINAuthBlocked indicates too many consecutive failures within one
	// power cycle. Attempts resume after the authenticator is power-cycled.
	// CTAP 2.1 §6.5.5.7 (CTAP2_ERR_PIN_AUTH_BLOCKED).
	ErrSOPINAuthBlocked = errors.New("authenticator: SO PIN attempts blocked until power cycle")

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

	// retries stores the remaining SO PIN attempts atomically. It is
	// persisted, so the budget survives a restart.
	retries atomic.Int32

	// consecutiveFailures counts failed attempts since the last success or
	// power-up. It is deliberately NOT persisted: "power cycle to continue" is
	// only meaningful if a power cycle clears it, and for this authenticator a
	// power cycle is a process restart.
	consecutiveFailures atomic.Int32

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

	if err := validateSOPINPolicy(pin); err != nil {
		return nil, err
	}

	// Generate cryptographically secure random salt
	salt := make([]byte, SOPINSaltSize)
	if _, err := rand.Read(salt); err != nil {
		return nil, ErrCryptoError
	}

	m.Salt = salt
	m.IsSet = true
	m.ConfirmVerified()

	// Derive the Storage Master Key
	smk := m.DeriveKey(pin)

	return smk, nil
}

// BeginVerify starts an SO PIN verification. It spends one attempt from the
// retry budget and returns the candidate Storage Master Key derived from pin.
//
// The retry is spent *before* the answer is known, so a caller that crashes,
// is killed, or simply never reports back cannot get a free attempt. The
// caller must finish the exchange:
//
//	smk, err := m.BeginVerify(pin)
//	if err != nil { return err }
//	if unwrapOK(smk) { m.ConfirmVerified() } else { return m.RecordFailure() }
//
// Verification itself is the caller's AES-GCM authenticated unwrap of material
// wrapped under the SMK, which is a stronger check than comparing a hash.
//
// Returns ErrSOPINNotSet if the token is uninitialized, ErrSOPINBlocked if the
// retry budget is exhausted, and ErrSOPINAuthBlocked if too many consecutive
// attempts have failed since the last power cycle.
func (m *SOPINManager) BeginVerify(pin string) ([]byte, error) {
	if !m.IsSet {
		return nil, ErrSOPINNotSet
	}

	if m.IsBlocked() {
		return nil, ErrSOPINBlocked
	}

	if m.IsAuthBlocked() {
		return nil, ErrSOPINAuthBlocked
	}

	smk := m.DeriveKey(pin)
	if smk == nil {
		return nil, ErrSOPINNotSet
	}

	m.retries.Add(-1)

	return smk, nil
}

// ConfirmVerified records that the caller cryptographically confirmed the SMK
// returned by BeginVerify. It restores the full retry budget and clears the
// consecutive-failure counter.
func (m *SOPINManager) ConfirmVerified() {
	m.retries.Store(int32(DefaultSOPINMaxRetries))
	m.consecutiveFailures.Store(0)
}

// RecordFailure records that the SMK returned by BeginVerify did not decrypt
// the wrapped material, and returns the error the caller should propagate.
//
// The retry was already spent by BeginVerify; this adds the consecutive-failure
// accounting CTAP 2.1 §6.5.5.7 requires and reports which of the three refusals
// now applies.
func (m *SOPINManager) RecordFailure() error {
	m.consecutiveFailures.Add(1)

	switch {
	case m.IsBlocked():
		return ErrSOPINBlocked
	case m.IsAuthBlocked():
		return ErrSOPINAuthBlocked
	default:
		return ErrSOPINInvalid
	}
}

// Rekey rotates the SO PIN to newPIN and returns the new Storage Master Key.
//
// It does not authenticate anything: the caller MUST have already proven the
// current SO PIN, because Rekey replaces the salt and the previous SMK becomes
// underivable the moment it does. Only KeyManager.ChangeSOPIN calls it, and
// only after unwrapping the Admin Key with the current SMK.
//
// Returns ErrSOPINNotSet if the token is uninitialized and
// ErrSOPINPolicyViolation if newPIN does not meet the length policy.
func (m *SOPINManager) Rekey(newPIN string) ([]byte, error) {
	if !m.IsSet {
		return nil, ErrSOPINNotSet
	}

	if err := validateSOPINPolicy(newPIN); err != nil {
		return nil, err
	}

	// Generate new salt for the new PIN
	newSalt := make([]byte, SOPINSaltSize)
	if _, err := rand.Read(newSalt); err != nil {
		return nil, ErrCryptoError
	}

	m.Salt = newSalt
	m.ConfirmVerified()

	return m.DeriveKey(newPIN), nil
}

// Retries returns the current number of remaining SO PIN attempts.
func (m *SOPINManager) Retries() int {
	return int(m.retries.Load())
}

// SetRetries sets the number of remaining SO PIN attempts. It exists so that
// persisted state can be restored on load; it is not part of the verification
// contract, which is BeginVerify / ConfirmVerified / RecordFailure.
func (m *SOPINManager) SetRetries(n int) {
	m.retries.Store(int32(n))
}

// ConsecutiveFailures returns the number of failed attempts since the last
// success or power cycle.
func (m *SOPINManager) ConsecutiveFailures() int {
	return int(m.consecutiveFailures.Load())
}

// IsBlocked reports whether the SO PIN retry budget is exhausted. This state is
// terminal until authenticatorReset.
func (m *SOPINManager) IsBlocked() bool {
	return m.retries.Load() <= 0
}

// IsAuthBlocked reports whether too many consecutive attempts have failed since
// the last power cycle. CTAP 2.1 §6.5.5.7.
func (m *SOPINManager) IsAuthBlocked() bool {
	return m.consecutiveFailures.Load() >= int32(SOPINMaxConsecutiveFailures)
}

// validateSOPINPolicy validates that the SO PIN meets the length policy.
// It is a package function rather than a method because the token layer must
// apply the same policy before an attempt is charged against the retry budget.
func validateSOPINPolicy(pin string) error {
	pinBytes := []byte(pin)
	if len(pinBytes) < sopinMinLength {
		return ErrSOPINPolicyViolation
	}
	if len(pinBytes) > sopinMaxLength {
		return ErrSOPINPolicyViolation
	}
	return nil
}
