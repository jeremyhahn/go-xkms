//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUnseal_NilSealedData(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()

	tpm2Instance, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	_, err := tpm2Instance.Unseal(ctx, nil, nil)
	assert.Error(t, err)
	assert.ErrorIs(t, err, ErrNilSealedData)
}

func TestUnseal_NoBackendAvailable(t *testing.T) {
	_, tpm := createSim(t, false)
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
	_, tpm := createSim(t, false)
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

func TestUnseal_InvalidBackendType(t *testing.T) {
	_, tpm := createSim(t, false)
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

// TestDefaultSealKeyAttributes_NoPlatformSRK verifies the error when no
// Platform SRK is configured. defaultSealKeyAttributes never falls back to
// the SSRK (see its doc comment), so the surfaced error is the Platform
// SRK's own configuration error, wrapped by defaultSealKeyAttributes.
func TestDefaultSealKeyAttributes_NoPlatformSRK(t *testing.T) {
	tpm2Instance := &TPM2{
		config: &Config{},
	}

	_, err := tpm2Instance.defaultSealKeyAttributes(&types.SealOptions{})
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPlatformSRKConfiguration))
}

// TestDefaultUnsealKeyAttributes_NoPlatformSRK verifies the error when no
// Platform SRK is configured. defaultUnsealKeyAttributes never falls back to
// the SSRK (see its doc comment), so the surfaced error is the Platform
// SRK's own configuration error, wrapped by defaultUnsealKeyAttributes.
func TestDefaultUnsealKeyAttributes_NoPlatformSRK(t *testing.T) {
	tpm2Instance := &TPM2{
		config: &Config{},
	}

	_, err := tpm2Instance.defaultUnsealKeyAttributes("some-key")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPlatformSRKConfiguration))
}

// TestSeal_Unseal_OptsPassword_RoundTrip proves the SealOptions.Password and
// UnsealOptions.Password fields -- distinct from KeyAttributes.Password --
// are applied to the key attributes rather than being read and discarded.
// keyAttrs itself carries no password, so the round trip can only succeed if
// Seal actually copied opts.Password onto it before sealing, and Unseal did
// the same before unsealing.
func TestSeal_Unseal_OptsPassword_RoundTrip(t *testing.T) {
	_, tpm := createSim(t, false)
	defer func() { _ = tpm.Close() }()
	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("opts-password-round-trip")

	sealed, err := tpm2Instance.Seal(ctx, data, &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword(t, []byte("opts-level-password")),
	})
	require.NoError(t, err)

	_, err = tpm2Instance.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword(t, []byte("wrong-password")),
	})
	require.Error(t, err, "the wrong password must not unseal data protected by SealOptions.Password")

	got, err := tpm2Instance.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword(t, []byte("opts-level-password")),
	})
	require.NoError(t, err)
	assert.Equal(t, data, got)
}
