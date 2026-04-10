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
	"crypto/subtle"
	"sync/atomic"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/mem"
)

// Compile-time interface checks.
var _ PINBackend = (*TPM2Backend)(nil)
var _ FIDO2HashVerifier = (*TPM2Backend)(nil)

// TPM2Backend implements PINBackend using TPM 2.0 PlatformSRK password auth
// for user PIN verification. The user PIN IS the PlatformSRK's auth value,
// so all verification is delegated to the PlatformAuthProvider.
//
// SO PIN is not stored in the TPM backend. All SO PIN methods return
// ErrPINNotSet because the concept of a separate SO PIN does not apply
// to the TPM platform key store model.
//
// FIDO2 PIN hash verification is supported by caching SHA-256(PIN)[:16]
// in a GuardedBuffer (mlock'd, guard-paged memory) when the user PIN is
// set, verified, or changed.
type TPM2Backend struct {
	platformStore PlatformAuthProvider
	userPINSet    atomic.Bool
	fido2Guard    atomic.Pointer[mem.GuardedBuffer]
}

// NewTPM2Backend creates a new TPM2Backend that delegates PIN verification
// to the PlatformAuthProvider. The provider verifies PINs against the
// PlatformSRK's password auth value.
//
// User PIN state is detected by querying platformStore.IsProvisioned().
// The actual PIN value is not known until the user calls SetUserPIN or
// VerifyUserPIN with the correct PIN.
func NewTPM2Backend(platformStore PlatformAuthProvider) *TPM2Backend {
	b := &TPM2Backend{
		platformStore: platformStore,
	}

	// If the platform is provisioned, the PlatformSRK exists and
	// may have a password auth value (user PIN). We optimistically
	// mark userPINSet as true; VerifyUserPIN will confirm correctness.
	if platformStore.IsProvisioned() {
		b.userPINSet.Store(true)
	}

	return b
}

// Strategy returns StrategyTPM2.
func (b *TPM2Backend) Strategy() StrategyID {
	return StrategyTPM2
}

// SetSOPIN is not supported for the TPM2 backend. The TPM platform key
// store model does not use a separate SO PIN.
func (b *TPM2Backend) SetSOPIN(_, _ string) error {
	return ErrPINNotSet
}

// SetUserPIN sets the user PIN by verifying it against the PlatformSRK's
// existing auth value. The soPIN parameter is ignored because the TPM2
// backend does not use SO PINs; the first parameter exists to satisfy
// the PINBackend interface.
//
// The user PIN must match the PlatformSRK's current password auth. On
// success, the FIDO2 hash is cached in a GuardedBuffer.
func (b *TPM2Backend) SetUserPIN(_ string, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}

	// Verify the PIN matches the PlatformSRK's auth value.
	if err := b.platformStore.VerifyAuth(newUserPIN); err != nil {
		if isAuthError(err) {
			return ErrPINInvalid
		}
		return err
	}

	b.cacheFIDO2Hash([]byte(newUserPIN))
	b.userPINSet.Store(true)
	return nil
}

// ChangeSOPIN is not supported for the TPM2 backend.
func (b *TPM2Backend) ChangeSOPIN(_, _ string) error {
	return ErrPINNotSet
}

// ChangeUserPIN changes the user PIN by delegating to the PlatformAuthProvider's
// ChangeAuth method. On success, the FIDO2 hash is updated.
func (b *TPM2Backend) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}

	if !b.userPINSet.Load() {
		return ErrPINNotSet
	}

	if err := b.platformStore.ChangeAuth(currentUserPIN, newUserPIN); err != nil {
		if isAuthError(err) {
			return b.buildAuthFailureError()
		}
		return err
	}

	b.cacheFIDO2Hash([]byte(newUserPIN))
	return nil
}

// VerifySOPIN is not supported for the TPM2 backend.
func (b *TPM2Backend) VerifySOPIN(_ string) error {
	return ErrPINNotSet
}

// VerifyUserPIN verifies the user PIN against the PlatformSRK's auth value.
// On success, the FIDO2 hash is lazily cached if not already present.
// On failure, DA lockout status is queried and included in the error.
func (b *TPM2Backend) VerifyUserPIN(pin string) error {
	if !b.userPINSet.Load() {
		return ErrPINNotSet
	}

	if err := b.platformStore.VerifyAuth(pin); err != nil {
		if isAuthError(err) {
			return b.buildAuthFailureError()
		}
		return err
	}

	// Lazy FIDO2 hash caching: recompute if not yet cached (e.g., after restart).
	guard := b.fido2Guard.Load()
	if guard == nil || guard.IsFreed() {
		b.cacheFIDO2Hash([]byte(pin))
	}

	return nil
}

// IsInitialized returns true if the TPM is provisioned with a PlatformSRK.
func (b *TPM2Backend) IsInitialized() bool {
	return b.platformStore.IsProvisioned()
}

// SOPINSet returns false. The TPM2 backend does not use SO PINs.
func (b *TPM2Backend) SOPINSet() bool {
	return false
}

// UserPINSet returns true if the user PIN has been configured.
func (b *TPM2Backend) UserPINSet() bool {
	return b.userPINSet.Load()
}

// GetLockoutStatus returns the TPM dictionary attack protection status
// by querying the PlatformAuthProvider. Returns nil if the lockout
// information cannot be retrieved.
func (b *TPM2Backend) GetLockoutStatus() *LockoutStatus {
	failedAttempts, maxFail, _, recovery, err := b.platformStore.GetLockoutInfo()
	if err != nil {
		return nil
	}

	isLocked := maxFail > 0 && failedAttempts >= maxFail

	return &LockoutStatus{
		FailedAttempts:  failedAttempts,
		MaxAttempts:     maxFail,
		IsLocked:        isLocked,
		RecoverySeconds: recovery,
	}
}

// ResetLockout resets the TPM dictionary attack lockout counter. The
// lockoutAuth parameter is passed directly to the provider's
// DictionaryAttackLockoutReset method.
func (b *TPM2Backend) ResetLockout(lockoutAuth string) error {
	return b.platformStore.DictionaryAttackLockoutReset([]byte(lockoutAuth))
}

// VerifyFIDO2Hash compares the provided FIDO2 PIN hash against the cached
// GuardedBuffer using constant-time comparison. Returns false if no hash
// is cached or the lengths do not match.
func (b *TPM2Backend) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != FIDO2PINHashSize {
		return false
	}

	guard := b.fido2Guard.Load()
	if guard == nil || guard.IsFreed() {
		return false
	}

	return subtle.ConstantTimeCompare(guard.Bytes(), hash) == 1
}

// Close frees the GuardedBuffer holding the FIDO2 hash. Safe to call
// multiple times.
func (b *TPM2Backend) Close() {
	if guard := b.fido2Guard.Load(); guard != nil {
		guard.Free()
	}
}

// buildAuthFailureError queries the TPM DA lockout status and returns
// either ErrTPMLocked or ErrPINInvalidWithStatus with the current
// lockout counters. Falls back to ErrPINInvalid if lockout info is
// unavailable.
func (b *TPM2Backend) buildAuthFailureError() error {
	failedAttempts, maxFail, _, recovery, err := b.platformStore.GetLockoutInfo()
	if err != nil {
		return ErrPINInvalid
	}

	status := &LockoutStatus{
		FailedAttempts:  failedAttempts,
		MaxAttempts:     maxFail,
		IsLocked:        maxFail > 0 && failedAttempts >= maxFail,
		RecoverySeconds: recovery,
	}

	if status.IsLocked {
		return &ErrTPMLocked{Status: status}
	}

	return &ErrPINInvalidWithStatus{Status: status}
}

// cacheFIDO2Hash computes the FIDO2 PIN hash and stores it in a
// GuardedBuffer. The previous buffer (if any) is freed.
func (b *TPM2Backend) cacheFIDO2Hash(pinBytes []byte) {
	hash := computeFIDO2PINHashFromBytes(pinBytes)
	defer mem.Zero(hash)

	guard, err := mem.NewGuardedBuffer(FIDO2PINHashSize)
	if err != nil {
		return
	}
	guard.Write(hash)

	// Free the old buffer.
	if old := b.fido2Guard.Swap(guard); old != nil {
		old.Free()
	}
}
