//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCanSeal(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	// TPM2 should be able to seal when properly initialized
	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)
	assert.True(t, tpm2.CanSeal())
}

func TestCanSeal_NilTransport(t *testing.T) {
	// Create an uninitialized TPM2 struct
	tpm2 := &TPM2{
		transport: nil,
	}

	// Should return false when transport is nil
	assert.False(t, tpm2.CanSeal())
}

// TestSeal_NilOptions verifies that Seal with nil opts uses Platform SRK defaults
// and succeeds on a provisioned TPM.
func TestSeal_NilOptions(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed, err := tpm2Instance.Seal(ctx, []byte("test data"), nil)
	require.NoError(t, err)
	assert.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypeTPM2, sealed.Backend)
	assert.NotEmpty(t, sealed.KeyID)
	assert.Equal(t, "platform-sealing-key", sealed.KeyID)
}

// TestSeal_NilKeyAttributes verifies that Seal with nil KeyAttributes uses
// Platform SRK defaults and succeeds on a provisioned TPM.
func TestSeal_NilKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: nil,
	}
	sealed, err := tpm2Instance.Seal(ctx, []byte("test data"), opts)
	require.NoError(t, err)
	assert.NotNil(t, sealed)
	assert.Equal(t, types.BackendTypeTPM2, sealed.Backend)
	assert.Equal(t, "platform-sealing-key", sealed.KeyID)
}

// TestSeal_NilOptions_RoundTrip verifies that seal with nil opts produces data
// that can be unsealed with nil opts.
func TestSeal_NilOptions_RoundTrip(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	data := []byte("roundtrip with defaults")

	sealed, err := tpm2Instance.Seal(ctx, data, nil)
	require.NoError(t, err)
	require.NotNil(t, sealed)

	// Unseal with nil opts -- should use KeyID from sealed data
	unsealed, err := tpm2Instance.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed)
}

func TestUnseal_NilSealedData(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	_, err := tpm2Instance.Unseal(ctx, nil, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestUnseal_WrongBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: "wrong-backend",
	}
	opts := &types.UnsealOptions{}
	_, err := tpm2Instance.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrSealedDataBackendMismatch)
}

// TestUnseal_NilOptions verifies that Unseal with nil opts uses Platform SRK
// defaults and the KeyID from sealed data.
func TestUnseal_NilOptions(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// First seal some data to get valid sealed blobs
	ctx := context.Background()
	data := []byte("unseal nil opts test")
	sealed, err := tpm2Instance.Seal(ctx, data, nil)
	require.NoError(t, err)

	// Unseal with nil opts
	unsealed, err := tpm2Instance.Unseal(ctx, sealed, nil)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed)
}

// TestUnseal_NilKeyAttributes verifies that Unseal with nil KeyAttributes
// uses Platform SRK defaults and the KeyID from sealed data.
func TestUnseal_NilKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// First seal some data to get valid sealed blobs
	ctx := context.Background()
	data := []byte("unseal nil key attrs test")
	sealed, err := tpm2Instance.Seal(ctx, data, nil)
	require.NoError(t, err)

	// Unseal with nil KeyAttributes
	opts := &types.UnsealOptions{
		KeyAttributes: nil,
	}
	unsealed, err := tpm2Instance.Unseal(ctx, sealed, opts)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed)
}

func TestUnseal_NoBackendAvailable(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// Save and clear backend
	originalBackend := tpm2Instance.backend
	tpm2Instance.backend = nil
	defer func() { tpm2Instance.backend = originalBackend }()

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend:    types.BackendTypeTPM2,
		TPMPublic:  nil, // No blobs provided
		TPMPrivate: nil,
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: nil, // No backend override
	}
	_, err := tpm2Instance.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoStorageBackend)
}

func TestSeal_NoBackendAvailable(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// Save and clear backend
	originalBackend := tpm2Instance.backend
	tpm2Instance.backend = nil
	defer func() { tpm2Instance.backend = originalBackend }()

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: nil, // No backend override
	}
	_, err := tpm2Instance.Seal(ctx, []byte("test data"), opts)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNoStorageBackend)
}

func TestSeal_InvalidBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: "not-a-valid-backend", // Wrong type
	}
	_, err := tpm2Instance.Seal(ctx, []byte("test data"), opts)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealBackend)
}

func TestUnseal_InvalidBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: types.BackendTypeTPM2,
	}
	opts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: "not-a-valid-backend", // Wrong type
	}
	_, err := tpm2Instance.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidSealBackend)
}

// TestSealWithNilData tests that Seal generates a random key when data is nil
func TestSealWithNilData(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-seal-nil-data",
			Parent:   ssrkAttrs,
			Password: store.NewPassword([]byte("test-pass")),
		},
	}

	sealed, err := tpm2Instance.Seal(ctx, nil, opts)
	require.NoError(t, err)
	assert.NotNil(t, sealed)
}

// TestUnsealWithProvidedBlobs tests the Seal/Unseal roundtrip
func TestUnsealWithProvidedBlobs(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	// First seal some data
	ctx := context.Background()
	data := []byte("data for blob unseal test")
	sealOpts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-unseal-blobs",
			Parent:   ssrkAttrs,
			Password: store.NewPassword([]byte("test-pass")),
		},
	}

	sealed, err := tpm2Instance.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	// Now unseal using the blobs directly
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-unseal-blobs",
			Parent:   ssrkAttrs,
			Password: store.NewPassword([]byte("test-pass")),
		},
	}

	unsealed, err := tpm2Instance.Unseal(ctx, sealed, unsealOpts)
	require.NoError(t, err)
	assert.Equal(t, data, unsealed)
}

// TestDefaultSealKeyAttributes verifies the default key attributes helper
// uses the Platform SRK.
func TestDefaultSealKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	attrs, err := tpm2Instance.defaultSealKeyAttributes()
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, "platform-sealing-key", attrs.CN)
	assert.NotNil(t, attrs.Parent)
}

// TestDefaultSealKeyAttributes_NoPlatformSRK verifies the error when
// PlatformSRK is not configured.
func TestDefaultSealKeyAttributes_NoPlatformSRK(t *testing.T) {
	tpm2Instance := &TPM2{
		config: &Config{},
	}

	_, err := tpm2Instance.defaultSealKeyAttributes()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPlatformSRKConfiguration))
}

// TestDefaultUnsealKeyAttributes verifies the default unseal key attributes
// helper uses the Platform SRK.
func TestDefaultUnsealKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	attrs, err := tpm2Instance.defaultUnsealKeyAttributes("my-sealed-key")
	require.NoError(t, err)
	assert.NotNil(t, attrs)
	assert.Equal(t, "my-sealed-key", attrs.CN)
	assert.NotNil(t, attrs.Parent)
}

// TestDefaultUnsealKeyAttributes_NoPlatformSRK verifies the error when
// PlatformSRK is not configured.
func TestDefaultUnsealKeyAttributes_NoPlatformSRK(t *testing.T) {
	tpm2Instance := &TPM2{
		config: &Config{},
	}

	_, err := tpm2Instance.defaultUnsealKeyAttributes("some-key")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPlatformSRKConfiguration))
}
