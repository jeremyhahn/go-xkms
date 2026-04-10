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

// Package pin provides PIN management with pluggable backend implementations
// for software hash-based and TPM 2.0 platform auth-based PIN protection.
//
// New code should use [PINBackend] for backend implementations and [Service]
// as the single entry point for all PIN operations.
package pin

import "time"

// StrategyID identifies a PIN management strategy.
type StrategyID string

const (
	// StrategySoftware uses Argon2id/PBKDF2 hashing with storage persistence.
	StrategySoftware StrategyID = "software"

	// StrategyTPM2 uses TPM 2.0 platform auth for PIN verification.
	StrategyTPM2 StrategyID = "tpm2"

	// minPINLength is the minimum allowed PIN length.
	minPINLength = 6
)

// Deprecated: PINManager is the legacy interface for PIN management operations.
// Use [PINBackend] for backend implementations and [Service] as the entry point.
// This interface will be removed in a future release.
type PINManager interface {
	Strategy() StrategyID
	SetSOPIN(currentSOPIN, newSOPIN string) error
	SetUserPIN(soPIN, newUserPIN string) error
	ChangeSOPIN(currentSOPIN, newSOPIN string) error
	ChangeUserPIN(currentUserPIN, newUserPIN string) error
	VerifySOPIN(pin string) error
	VerifyUserPIN(pin string) error
	GetLockoutStatus() *LockoutStatus
	ResetLockout(soPIN string) error
	SetMaxAttempts(n int)
	IsInitialized() bool
	SOPINSet() bool
	UserPINSet() bool
}

// Deprecated: PINSeeder is the legacy interface for seeding user PINs from
// a trusted internal source. Use [PINBackend] and [Service] instead.
// This interface will be removed in a future release.
type PINSeeder interface {
	SeedUserPIN(pin string) error
}

// LockoutStatus represents the current lockout state.
type LockoutStatus struct {
	FailedAttempts  int       `json:"failed_attempts"`
	MaxAttempts     int       `json:"max_attempts"`
	IsLocked        bool      `json:"is_locked"`
	LockoutUntil    time.Time `json:"lockout_until,omitempty"`
	RecoverySeconds int       `json:"recovery_seconds"`
}

// LockoutConfig configures the lockout behavior for software-based PIN
// backends that manage their own lockout counters.
type LockoutConfig struct {
	MaxAttempts     int           `json:"max_attempts"`
	LockoutDuration time.Duration `json:"lockout_duration"`
	Backoff         bool          `json:"backoff"`
}

// DefaultLockoutConfig returns the default lockout configuration.
func DefaultLockoutConfig() LockoutConfig {
	return LockoutConfig{
		MaxAttempts:     5,
		LockoutDuration: 5 * time.Minute,
		Backoff:         true,
	}
}

// PINManagerAdapter wraps a PINBackend to satisfy the deprecated PINManager
// interface. SetMaxAttempts is a no-op since the new backends manage lockout
// through their native mechanisms (TPM DA protection or no lockout).
//
// Deprecated: Will be removed when all consumers migrate to PINBackend.
type PINManagerAdapter struct {
	PINBackend
}

// SetMaxAttempts is a no-op for the adapter. Lockout is managed by the
// backend's native mechanism.
func (a *PINManagerAdapter) SetMaxAttempts(_ int) {}

// Compile-time check.
var _ PINManager = (*PINManagerAdapter)(nil)

// validatePINLength checks that the PIN meets the minimum length requirement.
func validatePINLength(pin string) error {
	if len(pin) < minPINLength {
		return ErrPINTooShort
	}
	return nil
}
