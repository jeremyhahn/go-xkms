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

package tpm2

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/pin"
)

// VerifyAuth verifies the auth value on the backend's SRK. The TPM validates
// the auth by attempting a child-key creation under the SRK handle with the
// provided PIN as the auth value. If the PIN is incorrect, the TPM returns
// an auth failure and the DA counter is incremented.
func (b *Backend) VerifyAuth(pinValue string) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return ErrNotInitialized
	}

	handle := b.srkAttrs.TPMAttributes.Handle
	if err := b.tpm.VerifyAuth(handle, []byte(pinValue)); err != nil {
		return errors.Join(ErrAuthVerifyFailed, err)
	}

	return nil
}

// ChangeAuth changes the auth value on the backend's SRK. This evicts the
// current SRK, recreates it with the same template and the new auth value,
// and re-persists it at the same handle. The current PIN must be verified
// before the change is applied.
func (b *Backend) ChangeAuth(currentPIN, newPIN string) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrNotInitialized
	}

	handle := b.srkAttrs.TPMAttributes.Handle
	if err := b.tpm.ChangeAuth(handle, []byte(currentPIN), []byte(newPIN)); err != nil {
		return errors.Join(ErrAuthChangeFailed, err)
	}

	return nil
}

// LockoutStatus returns the TPM dictionary attack (DA) protection status by
// querying the TPM's fixed properties. The returned LockoutStatus contains
// the current failure counter, maximum allowed failures, lockout state, and
// recovery interval.
func (b *Backend) LockoutStatus() (*pin.LockoutStatus, error) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return nil, ErrNotInitialized
	}

	props, err := b.tpm.FixedProperties()
	if err != nil {
		return nil, errors.Join(ErrLockoutQueryFailed, err)
	}

	isLocked := props.LockoutCounter >= props.MaxAuthFail && props.MaxAuthFail > 0

	return &pin.LockoutStatus{
		FailedAttempts:  int(props.LockoutCounter),
		MaxAttempts:     int(props.MaxAuthFail),
		IsLocked:        isLocked,
		RecoverySeconds: int(props.LockoutRecovery),
	}, nil
}

// ResetLockout resets the TPM DA lockout counter using the lockout hierarchy
// auth value. This executes TPM2_DictionaryAttackLockReset which clears the
// failure counter and releases any active lockout.
func (b *Backend) ResetLockout(lockoutAuth []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return ErrNotInitialized
	}

	if err := b.tpm.DictionaryAttackLockoutReset(lockoutAuth); err != nil {
		return errors.Join(ErrLockoutResetFailed, err)
	}

	return nil
}
