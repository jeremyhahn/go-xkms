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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// cloudSealingKey returns a representative symmetric KeyAttributes identifying
// the cloud-managed sealing key (KMS key / Transit key / secret). Cloud KMS
// backends require this identity on both Seal and Unseal.
func cloudSealingKey(store types.StoreType, cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:                 cn,
		StoreType:          store,
		KeyType:            types.KeyTypeEncryption,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
}

func TestCloudKMSStrategy_SealUnseal(t *testing.T) {
	sealer := &mockSealer{canSeal: true}
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, sealer, keyAttrs, nil)
	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")

	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	assert.Equal(t, StrategyAWSKMS, sealed.Strategy)
	assert.Equal(t, sealedRootKeyVersion, sealed.Version)
	require.NotEmpty(t, sealed.HardwarePayload)

	// The configured sealing-key identity must be forwarded to the backend;
	// otherwise the real cloud KMS sealers reject the request.
	require.NotNil(t, sealer.lastSealOpts, "Seal must receive non-nil opts")
	assert.Same(t, keyAttrs, sealer.lastSealOpts.KeyAttributes,
		"Seal must forward the configured KeyAttributes")

	recovered, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	assert.Equal(t, rootKey, recovered)

	require.NotNil(t, sealer.lastUnsealOpts, "Unseal must receive non-nil opts")
	assert.Same(t, keyAttrs, sealer.lastUnsealOpts.KeyAttributes,
		"Unseal must forward the configured KeyAttributes")
}

func TestCloudKMSStrategy_DifferentIDs(t *testing.T) {
	tests := []struct {
		name  string
		id    StrategyID
		store types.StoreType
	}{
		{"AWSKMS", StrategyAWSKMS, types.StoreAWSKMS},
		{"GCPKMS", StrategyGCPKMS, types.StoreType("gcpkms")},
		{"AzureKV", StrategyAzureKV, types.StoreType("azurekv")},
		{"Vault", StrategyVault, types.StoreType("vault")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sealer := &mockSealer{canSeal: true}
			keyAttrs := cloudSealingKey(tt.store, "root-seal-key")
			strategy := NewCloudKMSStrategy(tt.id, sealer, keyAttrs, nil)

			assert.Equal(t, tt.id, strategy.ID())
			assert.True(t, strategy.Available())
			assert.True(t, strategy.HardwareBacked())

			sealed, err := strategy.SealRootKey(context.Background(),
				[]byte("0123456789abcdef0123456789abcdef"), Credentials{})
			require.NoError(t, err)
			assert.Equal(t, tt.id, sealed.Strategy)
			require.NotNil(t, sealer.lastSealOpts)
			assert.Same(t, keyAttrs, sealer.lastSealOpts.KeyAttributes)
		})
	}
}

func TestCloudKMSStrategy_Available_NilSealer(t *testing.T) {
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, nil, nil, nil)
	assert.False(t, strategy.Available())
}

func TestCloudKMSStrategy_Available_CanSealFalse(t *testing.T) {
	sealer := &mockSealer{canSeal: false}
	keyAttrs := cloudSealingKey(types.StoreType("gcpkms"), "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyGCPKMS, sealer, keyAttrs, nil)
	assert.False(t, strategy.Available())
}

func TestCloudKMSStrategy_HardwareBacked(t *testing.T) {
	strategy := NewCloudKMSStrategy(StrategyAzureKV, nil, nil, nil)
	assert.True(t, strategy.HardwareBacked())
}

func TestCloudKMSStrategy_SealRootKey_NilSealer(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreType("vault"), "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyVault, nil, keyAttrs, nil)
	_, err := strategy.SealRootKey(context.Background(), []byte("key"), Credentials{})
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

// TestCloudKMSStrategy_SealRootKey_NilKeyAttrs verifies that a strategy
// constructed without a sealing-key identity fails fast with ErrNoSealingKey
// instead of delegating a nil-opts request that the backend would reject.
func TestCloudKMSStrategy_SealRootKey_NilKeyAttrs(t *testing.T) {
	sealer := &mockSealer{canSeal: true}
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, sealer, nil, nil)
	_, err := strategy.SealRootKey(context.Background(),
		[]byte("0123456789abcdef0123456789abcdef"), Credentials{})
	assert.ErrorIs(t, err, ErrNoSealingKey)
	assert.Nil(t, sealer.lastSealOpts, "backend must not be called without a sealing key")
}

func TestCloudKMSStrategy_SealRootKey_SealerError(t *testing.T) {
	sealErr := errors.New("cloud seal failed")
	sealer := &mockSealer{canSeal: true, sealErr: sealErr}
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, sealer, keyAttrs, nil)

	_, err := strategy.SealRootKey(context.Background(), []byte("key"), Credentials{})
	assert.ErrorIs(t, err, sealErr)
}

func TestCloudKMSStrategy_UnsealRootKey_NilSealed(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, &mockSealer{canSeal: true}, keyAttrs, nil)
	_, err := strategy.UnsealRootKey(context.Background(), nil, Credentials{})
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestCloudKMSStrategy_UnsealRootKey_EmptyHardwarePayload(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, &mockSealer{canSeal: true}, keyAttrs, nil)
	sealed := &SealedRootKey{HardwarePayload: nil}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestCloudKMSStrategy_UnsealRootKey_NilSealer(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, nil, keyAttrs, nil)
	sealed := &SealedRootKey{
		HardwarePayload: []byte(`{"ciphertext":"ZGF0YQ=="}`),
	}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

// TestCloudKMSStrategy_UnsealRootKey_NilKeyAttrs verifies that unseal fails
// fast with ErrNoSealingKey when no sealing-key identity is configured.
func TestCloudKMSStrategy_UnsealRootKey_NilKeyAttrs(t *testing.T) {
	sealer := &mockSealer{canSeal: true}
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, sealer, nil, nil)
	sealed := &SealedRootKey{
		HardwarePayload: []byte(`{"ciphertext":"ZGF0YQ=="}`),
	}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrNoSealingKey)
	assert.Nil(t, sealer.lastUnsealOpts, "backend must not be called without a sealing key")
}

func TestCloudKMSStrategy_UnsealRootKey_UnsealerError(t *testing.T) {
	unsealErr := errors.New("cloud unseal failed")
	sealer := &mockSealer{canSeal: true, unsealErr: unsealErr}
	keyAttrs := cloudSealingKey(types.StoreType("gcpkms"), "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyGCPKMS, sealer, keyAttrs, nil)

	// First seal to get a valid HardwarePayload.
	sealed, err := strategy.SealRootKey(context.Background(),
		[]byte("0123456789abcdef0123456789abcdef"), Credentials{})
	require.NoError(t, err)

	_, err = strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, unsealErr)
}

func TestCloudKMSStrategy_UnsealRootKey_CorruptPayload(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, &mockSealer{canSeal: true}, keyAttrs, nil)
	sealed := &SealedRootKey{
		HardwarePayload: []byte("not-valid-json"),
	}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrCorruptRootKey)
}

// TestCloudKMSStrategy_BarrierEncryptor_WithHardwareEncryptor verifies that
// when a hardware encryptor is provided, BarrierEncryptor returns a
// hardwareEncryptorWrapper that delegates to the hardware encryptor.
func TestCloudKMSStrategy_BarrierEncryptor_WithHardwareEncryptor(t *testing.T) {
	hw := &mockSymmetricEncrypter{}
	keyAttrs := cloudSealingKey(types.StoreAWSKMS, "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, &mockSealer{canSeal: true}, keyAttrs, hw)
	ctx := context.Background()

	enc, err := strategy.BarrierEncryptor(ctx, []byte("unused-root-key-32-bytes-long!!"))
	require.NoError(t, err)
	require.NotNil(t, enc)

	// Verify it is a hardwareEncryptorWrapper wrapping our mock.
	wrapper, ok := enc.(*hardwareEncryptorWrapper)
	require.True(t, ok, "should return a hardwareEncryptorWrapper")
	assert.Same(t, hw, wrapper.inner, "wrapper should contain the hardware encryptor")
}

// TestCloudKMSStrategy_BarrierEncryptor_EpochFallback verifies that when
// no hardware encryptor is provided, BarrierEncryptor returns (nil, nil),
// signaling the barrier to use epoch-based HKDF DEK encryption.
func TestCloudKMSStrategy_BarrierEncryptor_EpochFallback(t *testing.T) {
	keyAttrs := cloudSealingKey(types.StoreType("gcpkms"), "root-seal-key")
	strategy := NewCloudKMSStrategy(StrategyGCPKMS, &mockSealer{canSeal: true}, keyAttrs, nil)
	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")

	enc, err := strategy.BarrierEncryptor(ctx, rootKey)
	require.NoError(t, err)
	assert.Nil(t, enc, "should return nil to signal epoch-based encryption")
}

func TestCloudKMSStrategy_Close(t *testing.T) {
	strategy := NewCloudKMSStrategy(StrategyAWSKMS, nil, nil, nil)
	assert.NoError(t, strategy.Close())
}
