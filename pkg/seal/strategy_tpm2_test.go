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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTPM2Strategy_SealUnseal(t *testing.T) {
	sealer := &mockSealer{canSeal: true}
	strategy := NewTPM2Strategy(sealer, nil)
	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")

	sealed, err := strategy.SealRootKey(ctx, rootKey, Credentials{})
	require.NoError(t, err)
	require.NotNil(t, sealed)
	assert.Equal(t, StrategyTPM2, sealed.Strategy)
	assert.Equal(t, sealedRootKeyVersion, sealed.Version)
	require.NotEmpty(t, sealed.HardwarePayload)

	recovered, err := strategy.UnsealRootKey(ctx, sealed, Credentials{})
	require.NoError(t, err)
	assert.Equal(t, rootKey, recovered)
}

func TestTPM2Strategy_Available_NilSealer(t *testing.T) {
	strategy := NewTPM2Strategy(nil, nil)
	assert.False(t, strategy.Available())
	assert.Equal(t, StrategyTPM2, strategy.ID())
	assert.True(t, strategy.HardwareBacked())
}

func TestTPM2Strategy_Available_CanSealFalse(t *testing.T) {
	sealer := &mockSealer{canSeal: false}
	strategy := NewTPM2Strategy(sealer, nil)
	assert.False(t, strategy.Available())
}

func TestTPM2Strategy_Available_CanSealTrue(t *testing.T) {
	sealer := &mockSealer{canSeal: true}
	strategy := NewTPM2Strategy(sealer, nil)
	assert.True(t, strategy.Available())
}

func TestTPM2Strategy_HardwareBacked(t *testing.T) {
	strategy := NewTPM2Strategy(nil, nil)
	assert.True(t, strategy.HardwareBacked())
}

func TestTPM2Strategy_SealRootKey_NilSealer(t *testing.T) {
	strategy := NewTPM2Strategy(nil, nil)
	_, err := strategy.SealRootKey(context.Background(), []byte("key"), Credentials{})
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

func TestTPM2Strategy_SealRootKey_SealerError(t *testing.T) {
	sealErr := errors.New("tpm seal failed")
	sealer := &mockSealer{canSeal: true, sealErr: sealErr}
	strategy := NewTPM2Strategy(sealer, nil)

	_, err := strategy.SealRootKey(context.Background(), []byte("key"), Credentials{})
	assert.ErrorIs(t, err, sealErr)
}

func TestTPM2Strategy_UnsealRootKey_NilSealed(t *testing.T) {
	strategy := NewTPM2Strategy(&mockSealer{canSeal: true}, nil)
	_, err := strategy.UnsealRootKey(context.Background(), nil, Credentials{})
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestTPM2Strategy_UnsealRootKey_EmptyHardwarePayload(t *testing.T) {
	strategy := NewTPM2Strategy(&mockSealer{canSeal: true}, nil)
	sealed := &SealedRootKey{HardwarePayload: nil}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestTPM2Strategy_UnsealRootKey_NilSealer(t *testing.T) {
	strategy := NewTPM2Strategy(nil, nil)
	sealed := &SealedRootKey{
		HardwarePayload: []byte(`{"ciphertext":"ZGF0YQ=="}`),
	}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrNoAvailableStrategy)
}

func TestTPM2Strategy_UnsealRootKey_UnsealerError(t *testing.T) {
	unsealErr := errors.New("tpm unseal failed")
	sealer := &mockSealer{canSeal: true, unsealErr: unsealErr}
	strategy := NewTPM2Strategy(sealer, nil)

	// First seal to get a valid HardwarePayload.
	sealed, err := strategy.SealRootKey(context.Background(),
		[]byte("0123456789abcdef0123456789abcdef"), Credentials{})
	require.NoError(t, err)

	_, err = strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, unsealErr)
}

func TestTPM2Strategy_UnsealRootKey_CorruptPayload(t *testing.T) {
	strategy := NewTPM2Strategy(&mockSealer{canSeal: true}, nil)
	sealed := &SealedRootKey{
		HardwarePayload: []byte("not-valid-json"),
	}
	_, err := strategy.UnsealRootKey(context.Background(), sealed, Credentials{})
	assert.ErrorIs(t, err, ErrCorruptRootKey)
}

// TestTPM2Strategy_BarrierEncryptor_WithHardwareEncryptor verifies that
// when a hardware encryptor is provided, BarrierEncryptor returns a
// hardwareEncryptorWrapper that delegates to the hardware encryptor.
func TestTPM2Strategy_BarrierEncryptor_WithHardwareEncryptor(t *testing.T) {
	hw := &mockSymmetricEncrypter{}
	strategy := NewTPM2Strategy(&mockSealer{canSeal: true}, hw)
	ctx := context.Background()

	enc, err := strategy.BarrierEncryptor(ctx, []byte("unused-root-key-32-bytes-long!!"))
	require.NoError(t, err)
	require.NotNil(t, enc)

	// Verify it is a hardwareEncryptorWrapper wrapping our mock.
	wrapper, ok := enc.(*hardwareEncryptorWrapper)
	require.True(t, ok, "should return a hardwareEncryptorWrapper")
	assert.Same(t, hw, wrapper.inner, "wrapper should contain the hardware encryptor")
}

// TestTPM2Strategy_BarrierEncryptor_EpochFallback verifies that when
// no hardware encryptor is provided, BarrierEncryptor returns (nil, nil),
// signaling the barrier to use epoch-based HKDF DEK encryption.
func TestTPM2Strategy_BarrierEncryptor_EpochFallback(t *testing.T) {
	strategy := NewTPM2Strategy(&mockSealer{canSeal: true}, nil)
	ctx := context.Background()
	rootKey := []byte("0123456789abcdef0123456789abcdef")

	enc, err := strategy.BarrierEncryptor(ctx, rootKey)
	require.NoError(t, err)
	assert.Nil(t, enc, "should return nil to signal epoch-based encryption")
}

func TestTPM2Strategy_Close(t *testing.T) {
	strategy := NewTPM2Strategy(nil, nil)
	assert.NoError(t, strategy.Close())
}
