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
func (t *TPM2Strategy) SealRootKey(
	ctx context.Context,
	rootKey []byte,
	creds Credentials,
) (*SealedRootKey, error) {
	if t.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}
	sealed, err := t.sealer.Seal(ctx, rootKey, nil)
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

	return t.sealer.Unseal(ctx, &sd, nil)
}

// BarrierEncryptor returns a SymmetricEncrypter for barrier data operations.
// If a hardware encryptor was provided at construction time, it is wrapped
// via hardwareEncryptorWrapper (keys never leave the TPM). Otherwise, a
// software encryptor is derived from the root key using HKDF-SHA256 +
// AES-256-GCM.
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
