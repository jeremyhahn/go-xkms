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
var _ SealingStrategy = (*CloudKMSStrategy)(nil)

// CloudKMSStrategy provides a parameterized sealing strategy for cloud KMS
// backends (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault). Each
// instance is configured with a specific StrategyID and delegates actual
// seal/unseal operations to the underlying types.Sealer.
//
// Every cloud KMS backend sealer requires a non-nil *types.SealOptions whose
// KeyAttributes identify the cloud-managed symmetric key (KMS key ARN, GCP
// crypto-key resource, Azure secret, or Vault Transit key) used to seal the
// root key. CloudKMSStrategy carries that sealing-key identity and passes it
// through on both Seal and Unseal; without it the backends reject the request.
//
// When an optional types.SymmetricEncrypter is provided, barrier data
// operations use the cloud KMS for symmetric encryption where keys are
// managed by the cloud provider. Without it, a software DEK is derived
// from the root key as fallback.
type CloudKMSStrategy struct {
	id        StrategyID
	sealer    types.Sealer
	keyAttrs  *types.KeyAttributes
	encryptor types.SymmetricEncrypter
}

// NewCloudKMSStrategy creates a CloudKMSStrategy for the given provider.
// The id should be one of StrategyAWSKMS, StrategyGCPKMS, StrategyAzureKV,
// or StrategyVault.
//
// The sealer may be nil; in that case, Available() returns false.
//
// keyAttrs identifies the cloud-managed symmetric key used to seal and unseal
// the root key. It is required by every cloud KMS backend sealer; when nil,
// SealRootKey and UnsealRootKey return ErrNoSealingKey rather than delegating
// to a backend that would reject the request.
//
// The encryptor may be nil; in that case, BarrierEncryptor falls back to
// software-derived DEK encryption.
func NewCloudKMSStrategy(
	id StrategyID,
	sealer types.Sealer,
	keyAttrs *types.KeyAttributes,
	encryptor types.SymmetricEncrypter,
) *CloudKMSStrategy {
	return &CloudKMSStrategy{
		id:        id,
		sealer:    sealer,
		keyAttrs:  keyAttrs,
		encryptor: encryptor,
	}
}

// ID returns the strategy identifier provided at construction time.
func (c *CloudKMSStrategy) ID() StrategyID {
	return c.id
}

// Available returns true when the sealer is non-nil and reports CanSeal.
func (c *CloudKMSStrategy) Available() bool {
	return c.sealer != nil && c.sealer.CanSeal()
}

// HardwareBacked returns true. Cloud KMS services use HSM-backed keys.
func (c *CloudKMSStrategy) HardwareBacked() bool {
	return true
}

// SealRootKey delegates to the underlying types.Sealer and stores the
// sealed payload as JSON in SealedRootKey.HardwarePayload. The configured
// sealing-key identity is passed through via SealOptions.KeyAttributes,
// which every cloud KMS backend requires.
func (c *CloudKMSStrategy) SealRootKey(
	ctx context.Context,
	rootKey []byte,
	creds Credentials,
) (*SealedRootKey, error) {
	if c.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}
	if c.keyAttrs == nil {
		return nil, ErrNoSealingKey
	}

	sealed, err := c.sealer.Seal(ctx, rootKey, &types.SealOptions{
		KeyAttributes: c.keyAttrs,
	})
	if err != nil {
		return nil, err
	}

	payload, err := json.Marshal(sealed)
	if err != nil {
		return nil, err
	}

	return &SealedRootKey{
		Version:         sealedRootKeyVersion,
		Strategy:        c.id,
		HardwarePayload: payload,
		CreatedAt:       time.Now(),
	}, nil
}

// UnsealRootKey deserializes the HardwarePayload into a types.SealedData
// and delegates to the underlying types.Sealer. The configured sealing-key
// identity is passed through via UnsealOptions.KeyAttributes, which every
// cloud KMS backend requires.
func (c *CloudKMSStrategy) UnsealRootKey(
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
	if c.sealer == nil {
		return nil, ErrNoAvailableStrategy
	}
	if c.keyAttrs == nil {
		return nil, ErrNoSealingKey
	}

	var sd types.SealedData
	if err := json.Unmarshal(sealed.HardwarePayload, &sd); err != nil {
		return nil, ErrCorruptRootKey
	}

	return c.sealer.Unseal(ctx, &sd, &types.UnsealOptions{
		KeyAttributes: c.keyAttrs,
	})
}

// BarrierEncryptor returns a SymmetricEncrypter for barrier data operations.
// If a hardware encryptor was provided at construction time, it is wrapped
// via hardwareEncryptorWrapper (keys are managed by the cloud KMS).
// Otherwise it returns (nil, nil): the barrier manages its own epoch-based
// HKDF DEK — the software-derivation path now lives in qrdb's barrier.
func (c *CloudKMSStrategy) BarrierEncryptor(ctx context.Context, rootKey []byte) (SymmetricEncrypter, error) {
	if c.encryptor != nil {
		return &hardwareEncryptorWrapper{inner: c.encryptor}, nil
	}
	return nil, nil
}

// Close is a no-op. Cloud KMS client connections are managed by the caller.
func (c *CloudKMSStrategy) Close() error {
	return nil
}
