// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
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

func TestSeal_NilOptions(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	_, err := tpm2.Seal(ctx, []byte("test data"), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "seal options with KeyAttributes required")
}

func TestSeal_NilKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: nil,
	}
	_, err := tpm2.Seal(ctx, []byte("test data"), opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "seal options with KeyAttributes required")
}

func TestUnseal_NilSealedData(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	_, err := tpm2.Unseal(ctx, nil, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sealed data is required")
}

func TestUnseal_WrongBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: "wrong-backend",
	}
	opts := &types.UnsealOptions{}
	_, err := tpm2.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "sealed data was not created by TPM2 backend")
}

func TestUnseal_NilOptions(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: types.BackendTypeTPM2,
	}
	_, err := tpm2.Unseal(ctx, sealed, nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unseal options with KeyAttributes required")
}

func TestUnseal_NilKeyAttributes(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	sealed := &types.SealedData{
		Backend: types.BackendTypeTPM2,
	}
	opts := &types.UnsealOptions{
		KeyAttributes: nil,
	}
	_, err := tpm2.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unseal options with KeyAttributes required")
}

func TestUnseal_NoBackendAvailable(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// Save and clear backend
	originalBackend := tpm2.backend
	tpm2.backend = nil
	defer func() { tpm2.backend = originalBackend }()

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
	_, err := tpm2.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no storage backend available")
}

func TestSeal_NoBackendAvailable(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	// Save and clear backend
	originalBackend := tpm2.backend
	tpm2.backend = nil
	defer func() { tpm2.backend = originalBackend }()

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: nil, // No backend override
	}
	_, err := tpm2.Seal(ctx, []byte("test data"), opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no storage backend available")
}

func TestSeal_InvalidBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
	assert.True(t, ok)

	ctx := context.Background()
	opts := &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN: "test-key",
		},
		Backend: "not-a-valid-backend", // Wrong type
	}
	_, err := tpm2.Seal(ctx, []byte("test data"), opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "opts.Backend must implement store.KeyBackend")
}

func TestUnseal_InvalidBackendType(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()

	tpm2, ok := tpm.(*TPM2)
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
	_, err := tpm2.Unseal(ctx, sealed, opts)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "opts.Backend must implement store.KeyBackend")
}
