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
	"crypto/sha256"
	"crypto/subtle"
	"log/slog"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
)

// FIDO2PINHashSize is the CTAP2-mandated PIN hash length (first 16 bytes of SHA-256).
const FIDO2PINHashSize = 16

// FIDO2PINHashSetter is called by the Service to push updated FIDO2 PIN hashes
// to the authenticator. The authenticator stores SHA-256(PIN)[:16] for CTAP2
// PIN verification.
type FIDO2PINHashSetter func(hash []byte)

// Service provides PIN management by delegating to a backend-native PINBackend.
// It is the single point of truth for PIN operations.
//
// The Service also maintains FIDO2 authenticator integration: when a user PIN
// is set or changed, it computes SHA-256(PIN)[:16] and pushes it to the
// authenticator via the FIDO2PINHashSetter callback.
type Service struct {
	backend         PINBackend
	fido2HashSetter atomic.Pointer[FIDO2PINHashSetter]
	log             *slog.Logger
}

// NewService creates a new PIN service backed by the given PINBackend.
func NewService(backend PINBackend, log *slog.Logger) *Service {
	if log == nil {
		log = slog.Default()
	}
	return &Service{
		backend: backend,
		log:     log,
	}
}

// SetFIDO2HashSetter registers a callback to push FIDO2 PIN hashes to
// the authenticator. Call this after authenticator initialization.
func (s *Service) SetFIDO2HashSetter(setter FIDO2PINHashSetter) {
	s.fido2HashSetter.Store(&setter)
}

// Backend returns the underlying PINBackend.
func (s *Service) Backend() PINBackend {
	return s.backend
}

// Strategy returns the backend strategy identifier.
func (s *Service) Strategy() StrategyID {
	return s.backend.Strategy()
}

// SetSOPIN sets the Security Officer PIN.
func (s *Service) SetSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	return s.backend.SetSOPIN(currentSOPIN, newSOPIN)
}

// SetUserPIN sets the user PIN using SO PIN authorization.
// Also pushes the FIDO2 PIN hash to the authenticator.
func (s *Service) SetUserPIN(soPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	if err := s.backend.SetUserPIN(soPIN, newUserPIN); err != nil {
		return err
	}
	s.pushFIDO2Hash(newUserPIN)
	return nil
}

// ChangeSOPIN changes the SO PIN.
func (s *Service) ChangeSOPIN(currentSOPIN, newSOPIN string) error {
	if err := validatePINLength(newSOPIN); err != nil {
		return err
	}
	return s.backend.ChangeSOPIN(currentSOPIN, newSOPIN)
}

// ChangeUserPIN changes the user PIN and pushes the updated FIDO2 hash.
func (s *Service) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	if err := s.backend.ChangeUserPIN(currentUserPIN, newUserPIN); err != nil {
		return err
	}
	s.pushFIDO2Hash(newUserPIN)
	return nil
}

// VerifySOPIN verifies the SO PIN using the backend's native mechanism.
func (s *Service) VerifySOPIN(pin string) error {
	return s.backend.VerifySOPIN(pin)
}

// VerifyUserPIN verifies the user PIN using the backend's native mechanism.
// On success, the FIDO2 hash is pushed to the authenticator so that
// CTAP2 PIN verification works immediately after app restart without
// requiring the user to change their PIN first.
func (s *Service) VerifyUserPIN(pin string) error {
	if err := s.backend.VerifyUserPIN(pin); err != nil {
		return err
	}
	s.pushFIDO2Hash(pin)
	return nil
}

// IsInitialized returns true if the backend has been initialized.
func (s *Service) IsInitialized() bool {
	return s.backend.IsInitialized()
}

// IsPINSet returns true if the user PIN has been set.
func (s *Service) IsPINSet() bool {
	return s.backend.UserPINSet()
}

// SOPINSet returns true if the SO PIN has been configured.
func (s *Service) SOPINSet() bool {
	return s.backend.SOPINSet()
}

// UserPINSet returns true if the user PIN has been configured.
func (s *Service) UserPINSet() bool {
	return s.backend.UserPINSet()
}

// GetLockoutStatus returns the backend's native lockout state.
func (s *Service) GetLockoutStatus() *LockoutStatus {
	return s.backend.GetLockoutStatus()
}

// ResetLockout resets the lockout state using SO PIN authorization.
func (s *Service) ResetLockout(soPIN string) error {
	return s.backend.ResetLockout(soPIN)
}

// VerifyFIDO2Hash verifies a FIDO2 PIN hash (SHA-256(PIN)[:16]) against
// the stored PIN. This is used by the FIDO2 authenticator to verify
// incoming PIN hashes without knowing the raw PIN.
//
// Note: This requires the backend to be able to produce the expected
// FIDO2 hash. The Service computes and caches it on PIN set/change.
func (s *Service) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != FIDO2PINHashSize {
		return false
	}
	// Delegate to the backend's FIDO2 hash verification.
	if verifier, ok := s.backend.(FIDO2HashVerifier); ok {
		return verifier.VerifyFIDO2Hash(hash)
	}
	return false
}

// FIDO2HashVerifier is an optional interface that PINBackend implementations
// can implement to support FIDO2 PIN hash verification.
type FIDO2HashVerifier interface {
	// VerifyFIDO2Hash verifies a FIDO2 PIN hash (SHA-256(PIN)[:16]).
	VerifyFIDO2Hash(hash []byte) bool
}

// ComputeFIDO2PINHash computes the CTAP2 PIN hash: SHA-256(PIN)[:16].
func ComputeFIDO2PINHash(pin string) []byte {
	pinBytes := []byte(pin)
	defer mem.Zero(pinBytes)
	return computeFIDO2PINHashFromBytes(pinBytes)
}

// computeFIDO2PINHashFromBytes computes the CTAP2 PIN hash from raw bytes.
// The caller is responsible for zeroing pinBytes.
func computeFIDO2PINHashFromBytes(pinBytes []byte) []byte {
	h := sha256.Sum256(pinBytes)
	result := make([]byte, FIDO2PINHashSize)
	copy(result, h[:FIDO2PINHashSize])
	mem.Zero(h[:])
	return result
}

// VerifyFIDO2PINHash compares two FIDO2 PIN hashes using constant-time comparison.
func VerifyFIDO2PINHash(expected, actual []byte) bool {
	if len(expected) != FIDO2PINHashSize || len(actual) != FIDO2PINHashSize {
		return false
	}
	return subtle.ConstantTimeCompare(expected, actual) == 1
}

// pushFIDO2Hash computes the FIDO2 hash and sends it to the authenticator.
func (s *Service) pushFIDO2Hash(pin string) {
	setter := s.fido2HashSetter.Load()
	if setter == nil {
		return
	}
	hash := ComputeFIDO2PINHash(pin)
	defer mem.Zero(hash)
	(*setter)(hash)
	s.log.Debug("pushed FIDO2 PIN hash to authenticator")
}
