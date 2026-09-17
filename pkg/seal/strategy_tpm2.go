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

package seal

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// Compile-time interface check.
var _ SealingStrategy = (*TPM2Strategy)(nil)

// TPM2Strategy wraps an existing types.Sealer that uses TPM 2.0 hardware
// for root key protection. The underlying sealer handles all TPM-specific
// operations (PCR binding, SRK hierarchy, etc.).
//
// When an optional types.SymmetricEncrypter is provided, barrier data
// operations use hardware-backed symmetric encryption where keys never
// leave the TPM. Without it, a software DEK is derived from the root key
// as fallback.
type TPM2Strategy struct {
	sealer    types.Sealer
	encryptor types.SymmetricEncrypter
}

// NewTPM2Strategy creates a TPM2Strategy backed by the given sealer and
// an optional hardware encryptor. The sealer may be nil; in that case,
// Available() returns false. The encryptor may be nil; in that case,
// BarrierEncryptor falls back to software-derived DEK encryption.
func NewTPM2Strategy(sealer types.Sealer, encryptor types.SymmetricEncrypter) *TPM2Strategy {
	return &TPM2Strategy{
		sealer:    sealer,
		encryptor: encryptor,
	}
}

// ID returns StrategyTPM2.
func (t *TPM2Strategy) ID() StrategyID {
	return StrategyTPM2
}

// Available returns true when the sealer is non-nil and reports CanSeal.
func (t *TPM2Strategy) Available() bool {
	return t.sealer != nil && t.sealer.CanSeal()
}

// HardwareBacked returns true. TPM 2.0 is dedicated security hardware.
func (t *TPM2Strategy) HardwareBacked() bool {
	return true
}

// SealRootKey delegates to the underlying types.Sealer and stores the
// sealed payload as JSON in SealedRootKey.HardwarePayload.
//
// When creds.Secret is supplied it is applied as the sealed object's TPM
// UserAuth authorization value, so unsealing requires presenting the same
// secret. Absent credentials seal with no authorization value (legacy
// behavior), keeping existing blobs and callers compatible.
func (t *TPM2Strategy) SealRootKey(
	ctx context.Context,
	rootKey []byte,
	creds Credentials,
) (*SealedRootKey, error) {
	if t.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}
	var opts *types.SealOptions
	if creds.Secret != nil {
		// The credential secret lives in protected memory. Open it into a
		// locked view, copy the plaintext out for the password, and destroy
		// the view on return; the caller still owns and destroys the
		// credential itself.
		opened, openErr := creds.Secret.Open()
		if openErr != nil {
			return nil, openErr
		}
		secret, strErr := opened.OpenString()
		opened.Destroy()
		if strErr != nil {
			return nil, strErr
		}
		pw, pwErr := types.NewPasswordFromString(secret)
		if pwErr != nil {
			return nil, pwErr
		}
		opts = &types.SealOptions{
			Password: pw,
		}
	}
	sealed, err := t.sealer.Seal(ctx, rootKey, opts)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}

	return &SealedRootKey{
		Version:         sealedRootKeyVersion,
		Strategy:        StrategyTPM2,
		HardwarePayload: payload,
		CreatedAt:       time.Now(),
	}, nil
}

// UnsealRootKey deserializes the HardwarePayload into a types.SealedData
// and delegates to the underlying types.Sealer.
//
// When creds.Secret is supplied it is presented as the sealed object's TPM
// UserAuth authorization value. A wrong secret fails TPM session
// authorization and the unseal is rejected by the hardware.
func (t *TPM2Strategy) UnsealRootKey(
	ctx context.Context,
	sealed *SealedRootKey,
	creds Credentials,
) ([]byte, error) {
	if sealed == nil {
		return nil, ErrNilSealedData
	}
	if len(sealed.HardwarePayload) == 0 {
		return nil, ErrNilSealedData
	}
	if t.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}

	var sd types.SealedData
	if err := json.Unmarshal(sealed.HardwarePayload, &sd); err != nil {
		return nil, ErrCorruptRootKey
	}

	var opts *types.UnsealOptions
	if creds.Secret != nil {
		// Same borrow as SealRootKey: open the protected secret, copy the
		// plaintext for the password, destroy the view immediately.
		opened, openErr := creds.Secret.Open()
		if openErr != nil {
			return nil, openErr
		}
		secret, strErr := opened.OpenString()
		opened.Destroy()
		if strErr != nil {
			return nil, strErr
		}
		pw, pwErr := types.NewPasswordFromString(secret)
		if pwErr != nil {
			return nil, pwErr
		}
		opts = &types.UnsealOptions{
			Password: pw,
		}
	}
	return t.sealer.Unseal(ctx, &sd, opts)
}

// BarrierEncryptor returns a SymmetricEncrypter for barrier data operations.
// If a hardware encryptor was provided at construction time, it is wrapped
// via hardwareEncryptorWrapper (keys never leave the TPM). Otherwise it
// returns (nil, nil): the barrier manages its own epoch-based HKDF DEK —
// the software-derivation path now lives in qrdb's barrier, not here.
func (t *TPM2Strategy) BarrierEncryptor(ctx context.Context, rootKey []byte) (SymmetricEncrypter, error) {
	if t.encryptor != nil {
		return &hardwareEncryptorWrapper{inner: t.encryptor}, nil
	}
	return nil, nil
}

// Close is a no-op. TPM resources are managed by the caller.
func (t *TPM2Strategy) Close() error {
	return nil
}
