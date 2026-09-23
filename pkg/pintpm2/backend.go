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

// Package pintpm2 provides the TPM 2.0 PINBackend implementation for the
// qrdb/pkg/pin contract. PIN verification is delegated to a TPM
// PlatformSRK's password auth (with native dictionary-attack protection);
// the FIDO2 PIN hash (CTAP2: SHA-256(PIN)[:16]) is cached in mlock'd,
// guard-paged memory between operations.
//
// Higher layers compose this backend into a qrdb server via
// qrdbserver.WithPINBackend. The canonical PINBackend interface lives in
// go-qrdb/pkg/pin; pintpm2 is one of the hardware implementations.
package pintpm2

import (
	"crypto/sha256"
	"sync/atomic"

	"github.com/jeremyhahn/go-enclave"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// Compile-time interface conformance against the canonical qrdb contract.
var (
	_ qrdbsdk.PINBackend        = (*TPM2Backend)(nil)
	_ qrdbsdk.FIDO2HashVerifier = (*TPM2Backend)(nil)
)

// minPINLength is the minimum allowed PIN length, mirroring qrdb's
// software backend so the policy is uniform across backends.
const minPINLength = 6

// TPM2Backend implements qrdb/pkg/qrdbsdk.PINBackend using TPM 2.0 PlatformSRK
// password auth for user PIN verification. The user PIN IS the
// PlatformSRK's auth value; all verification is delegated to the
// PlatformAuthProvider.
//
// SO PIN is not stored in the TPM backend — the TPM platform key store
// model does not use a separate SO PIN, so all SO PIN methods return
// qrdbsdk.ErrPINNotSet.
//
// FIDO2 PIN hash verification is supported by caching SHA-256(PIN)[:16]
// in a go-enclave MemoryEnclave (mlock'd, guard-paged memory) when the
// user PIN is set, verified, or changed.
type TPM2Backend struct {
	platformStore PlatformAuthProvider
	userPINSet    atomic.Bool
	fido2Enclave  atomic.Pointer[enclave.MemoryEnclave]
}

// NewTPM2Backend creates a new TPM2Backend that delegates PIN verification
// to the PlatformAuthProvider.
//
// The user PIN is reported as set only when the PlatformSRK is provisioned
// AND its auth value is in a known-good state (IsAuthReady). A provisioned
// SRK on its own proves nothing about the auth value: an SRK left behind by
// a prior TPM owner is readable while its auth is unknown, so reporting a
// PIN as set from IsProvisioned alone makes the backend claim a credential
// it has never seen and cannot verify. Verification itself remains available
// whenever the SRK is provisioned; a successful SetUserPIN or VerifyUserPIN
// confirms the auth value and flips the reported state.
func NewTPM2Backend(platformStore PlatformAuthProvider) *TPM2Backend {
	b := &TPM2Backend{platformStore: platformStore}
	if platformStore.IsProvisioned() && platformStore.IsAuthReady() {
		b.userPINSet.Store(true)
	}
	return b
}

// Strategy returns qrdbsdk.PINStrategyTPM2.
func (b *TPM2Backend) Strategy() qrdbsdk.PINStrategyID { return qrdbsdk.PINStrategyTPM2 }

// SetSOPIN is not supported for the TPM2 backend.
func (b *TPM2Backend) SetSOPIN(_, _ string) error { return qrdbsdk.ErrPINNotSet }

// SetUserPIN sets the user PIN by verifying it against the PlatformSRK's
// existing auth value. The soPIN parameter is ignored because the TPM2
// backend does not use SO PINs; the first parameter exists to satisfy
// the PINBackend interface.
//
// On success the FIDO2 hash is cached in a MemoryEnclave.
func (b *TPM2Backend) SetUserPIN(_ string, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	if err := b.platformStore.VerifyAuth(newUserPIN); err != nil {
		if isAuthError(err) {
			return qrdbsdk.ErrPINInvalid
		}
		return err
	}
	b.cacheFIDO2Hash([]byte(newUserPIN))
	b.userPINSet.Store(true)
	return nil
}

// ChangeSOPIN is not supported for the TPM2 backend.
func (b *TPM2Backend) ChangeSOPIN(_, _ string) error { return qrdbsdk.ErrPINNotSet }

// ChangeUserPIN changes the user PIN via the PlatformAuthProvider's
// ChangeAuth. On success the FIDO2 hash is updated.
func (b *TPM2Backend) ChangeUserPIN(currentUserPIN, newUserPIN string) error {
	if err := validatePINLength(newUserPIN); err != nil {
		return err
	}
	if !b.platformStore.IsProvisioned() {
		return qrdbsdk.ErrPINNotSet
	}
	if err := b.platformStore.ChangeAuth(currentUserPIN, newUserPIN); err != nil {
		// A change can fail after the SRK has already been evicted, which
		// leaves what it holds unknown; the provider reports that by
		// dropping its readiness. Re-read it rather than keeping a cached
		// "set" that the provider no longer stands behind, and drop the
		// cached FIDO2 hash with it: VerifyFIDO2Hash is consulted directly
		// by callers that never see UserPINSet, so leaving the old digest
		// behind would keep accepting a PIN this backend can no longer
		// vouch for.
		ready := b.platformStore.IsAuthReady()
		b.userPINSet.Store(ready)
		if !ready {
			if enc := b.fido2Enclave.Swap(nil); enc != nil {
				enc.Destroy()
			}
		}
		if isAuthError(err) {
			return b.buildAuthFailureError()
		}
		return err
	}
	// ChangeAuth proved the current auth value and installed the new one, so
	// the credential is now known either way.
	b.userPINSet.Store(true)
	b.cacheFIDO2Hash([]byte(newUserPIN))
	return nil
}

// VerifySOPIN is not supported for the TPM2 backend.
func (b *TPM2Backend) VerifySOPIN(_ string) error { return qrdbsdk.ErrPINNotSet }

// VerifyUserPIN verifies the user PIN against the PlatformSRK's auth value.
// On success the FIDO2 hash is lazily cached if not already present.
// On failure the DA lockout status is queried and surfaced via
// qrdbsdk.PINTPMLockedError or qrdbsdk.PINInvalidWithStatusError.
func (b *TPM2Backend) VerifyUserPIN(p string) error {
	if !b.platformStore.IsProvisioned() {
		return qrdbsdk.ErrPINNotSet
	}
	if err := b.platformStore.VerifyAuth(p); err != nil {
		if isAuthError(err) {
			return b.buildAuthFailureError()
		}
		return err
	}
	// The supplied PIN is the SRK auth value. Record that the credential is
	// now known so UserPINSet reports the confirmed state rather than a
	// guess derived from SRK presence.
	b.userPINSet.Store(true)
	enc := b.fido2Enclave.Load()
	if enc == nil || !enc.IsAlive() {
		b.cacheFIDO2Hash([]byte(p))
	}
	return nil
}

// IsInitialized returns true when the TPM is provisioned with a
// PlatformSRK.
func (b *TPM2Backend) IsInitialized() bool { return b.platformStore.IsProvisioned() }

// SOPINSet returns false. The TPM2 backend does not use SO PINs.
func (b *TPM2Backend) SOPINSet() bool { return false }

// UserPINSet reports whether the PlatformSRK's auth value is known to be
// the user PIN — either confirmed by a successful SetUserPIN/VerifyUserPIN
// in this process, or reported auth-ready by the provider at construction.
// It is deliberately NOT derived from SRK presence alone.
func (b *TPM2Backend) UserPINSet() bool { return b.userPINSet.Load() }

// GetLockoutStatus returns the TPM dictionary-attack protection state
// via the PlatformAuthProvider, or nil when the info cannot be read.
func (b *TPM2Backend) GetLockoutStatus() *qrdbsdk.PINLockoutStatus {
	failedAttempts, maxFail, _, recovery, err := b.platformStore.GetLockoutInfo()
	if err != nil {
		return nil
	}
	return &qrdbsdk.PINLockoutStatus{
		FailedAttempts:  failedAttempts,
		MaxAttempts:     maxFail,
		IsLocked:        maxFail > 0 && failedAttempts >= maxFail,
		RecoverySeconds: recovery,
	}
}

// ResetLockout resets the TPM DA lockout counter.
func (b *TPM2Backend) ResetLockout(lockoutAuth string) error {
	return b.platformStore.DictionaryAttackLockoutReset([]byte(lockoutAuth))
}

// VerifyFIDO2Hash compares the supplied CTAP2 PIN hash against the cached
// MemoryEnclave using constant-time comparison. A nil or destroyed enclave
// reports false, matching the fail-closed behavior of enclave.EqualTo.
func (b *TPM2Backend) VerifyFIDO2Hash(hash []byte) bool {
	if len(hash) != qrdbsdk.FIDO2PINHashSize {
		return false
	}
	return b.fido2Enclave.Load().EqualTo(hash)
}

// Close destroys the MemoryEnclave holding the FIDO2 hash. Safe to call
// multiple times.
func (b *TPM2Backend) Close() {
	if enc := b.fido2Enclave.Load(); enc != nil {
		enc.Destroy()
	}
}

// buildAuthFailureError queries TPM DA lockout state and returns the
// appropriate typed error: qrdbsdk.PINTPMLockedError when the TPM is locked,
// qrdbsdk.PINInvalidWithStatusError when it is not. Falls back to
// qrdbsdk.ErrPINInvalid when the lockout info cannot be retrieved.
func (b *TPM2Backend) buildAuthFailureError() error {
	failedAttempts, maxFail, _, recovery, err := b.platformStore.GetLockoutInfo()
	if err != nil {
		return qrdbsdk.ErrPINInvalid
	}
	status := &qrdbsdk.PINLockoutStatus{
		FailedAttempts:  failedAttempts,
		MaxAttempts:     maxFail,
		IsLocked:        maxFail > 0 && failedAttempts >= maxFail,
		RecoverySeconds: recovery,
	}
	if status.IsLocked {
		return &qrdbsdk.PINTPMLockedError{Status: status}
	}
	return &qrdbsdk.PINInvalidWithStatusError{Status: status}
}

// cacheFIDO2Hash computes SHA-256(pinBytes)[:16] and stores it in a
// MemoryEnclave; the prior enclave is destroyed. NewMemoryEnclave takes
// ownership of the slice handed to it and wipes it before returning, so
// the remainder of digest (bytes 16:32, never handed to the enclave) is
// wiped separately to leave nothing of the digest on the heap.
func (b *TPM2Backend) cacheFIDO2Hash(pinBytes []byte) {
	digest := sha256.Sum256(pinBytes)
	enc, err := enclave.NewMemoryEnclave(digest[:qrdbsdk.FIDO2PINHashSize])
	enclave.Wipe(digest[:])
	if err != nil {
		return
	}
	if old := b.fido2Enclave.Swap(enc); old != nil {
		old.Destroy()
	}
}

// validatePINLength enforces the uniform 6-character minimum across all
// backends. Returns qrdbsdk.ErrPINTooShort when below the threshold.
func validatePINLength(p string) error {
	if len(p) < minPINLength {
		return qrdbsdk.ErrPINTooShort
	}
	return nil
}
