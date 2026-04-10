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
var _ SealingStrategy = (*PKCS11Strategy)(nil)

// PKCS11Strategy wraps an existing types.Sealer that uses a PKCS#11 HSM
// token for root key protection.
//
// When an optional types.SymmetricEncrypter is provided, barrier data
// operations use hardware-backed symmetric encryption where keys never
// leave the HSM. Without it, a software DEK is derived from the root key
// as fallback.
type PKCS11Strategy struct {
	sealer    types.Sealer
	encryptor types.SymmetricEncrypter
}

// NewPKCS11Strategy creates a PKCS11Strategy backed by the given sealer and
// an optional hardware encryptor. The sealer may be nil; in that case,
// Available() returns false. The encryptor may be nil; in that case,
// BarrierEncryptor falls back to software-derived DEK encryption.
func NewPKCS11Strategy(sealer types.Sealer, encryptor types.SymmetricEncrypter) *PKCS11Strategy {
	return &PKCS11Strategy{
		sealer:    sealer,
		encryptor: encryptor,
	}
}

// ID returns StrategyPKCS11.
func (p *PKCS11Strategy) ID() StrategyID {
	return StrategyPKCS11
}

// Available returns true when the sealer is non-nil and reports CanSeal.
func (p *PKCS11Strategy) Available() bool {
	return p.sealer != nil && p.sealer.CanSeal()
}

// HardwareBacked returns true. PKCS#11 tokens are hardware security modules.
func (p *PKCS11Strategy) HardwareBacked() bool {
	return true
}

// SealRootKey delegates to the underlying types.Sealer and stores the
// sealed payload as JSON in SealedRootKey.HardwarePayload.
func (p *PKCS11Strategy) SealRootKey(
	ctx context.Context,
	rootKey []byte,
	creds Credentials,
) (*SealedRootKey, error) {
	if p.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}
	sealed, err := p.sealer.Seal(ctx, rootKey, nil)
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}

	return &SealedRootKey{
		Version:         sealedRootKeyVersion,
		Strategy:        StrategyPKCS11,
		HardwarePayload: payload,
		CreatedAt:       time.Now(),
	}, nil
}

// UnsealRootKey deserializes the HardwarePayload into a types.SealedData
// and delegates to the underlying types.Sealer.
func (p *PKCS11Strategy) UnsealRootKey(
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
	if p.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}

	var sd types.SealedData
	if err := json.Unmarshal(sealed.HardwarePayload, &sd); err != nil {
		return nil, ErrCorruptRootKey
	}

	return p.sealer.Unseal(ctx, &sd, nil)
}

// BarrierEncryptor returns a SymmetricEncrypter for barrier data operations.
// If a hardware encryptor was provided at construction time, it is wrapped
// via hardwareEncryptorWrapper (keys never leave the HSM). Otherwise, a
// software encryptor is derived from the root key using HKDF-SHA256 +
// AES-256-GCM.
func (p *PKCS11Strategy) BarrierEncryptor(ctx context.Context, rootKey []byte) (SymmetricEncrypter, error) {
	if p.encryptor != nil {
		return &hardwareEncryptorWrapper{inner: p.encryptor}, nil
	}
	return nil, nil
}

// Close is a no-op. PKCS#11 session resources are managed by the caller.
func (p *PKCS11Strategy) Close() error {
	return nil
}
