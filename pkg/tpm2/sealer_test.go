//go:build tpm_simulator
// +build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC

package tpm2

import (
	"context"
	"errors"
	"testing"

	"github.com/google/go-tpm/tpm2"
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
			Password: mustPassword([]byte("test-pass")),
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
			Password: mustPassword([]byte("test-pass")),
		},
	}

	sealed, err := tpm2Instance.Seal(ctx, data, sealOpts)
	require.NoError(t, err)

	// Now unseal using the blobs directly
	unsealOpts := &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{
			CN:       "test-unseal-blobs",
			Parent:   ssrkAttrs,
			Password: mustPassword([]byte("test-pass")),
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

// TestDefaultSealKeyAttributes_NoPlatformSRK verifies the error when no
// Platform SRK is configured. defaultSealKeyAttributes never falls back to
// the SSRK (see its doc comment), so the surfaced error is the Platform
// SRK's own configuration error, wrapped by defaultSealKeyAttributes.
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
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()
	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	ctx := context.Background()
	data := []byte("opts-password-round-trip")

	sealed, err := tpm2Instance.Seal(ctx, data, &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword([]byte("opts-level-password")),
	})
	require.NoError(t, err)

	_, err = tpm2Instance.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword([]byte("wrong-password")),
	})
	require.Error(t, err, "the wrong password must not unseal data protected by SealOptions.Password")

	got, err := tpm2Instance.Unseal(ctx, sealed, &types.UnsealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "opts-password-key", Parent: ssrkAttrs},
		Password:      mustPassword([]byte("opts-level-password")),
	})
	require.NoError(t, err)
	assert.Equal(t, data, got)
}

// TestSeal_TPMPolicy_AuthPolicyOverridesTemplate proves the
// SealOptions.TPMPolicy.AuthPolicy branch actually reaches TPM2_Create: the
// object the TPM created carries exactly the caller-supplied AuthPolicy
// digest, which is only possible if Seal installed it into the template
// before calling SealKey rather than leaving KeyedHashTemplate's own (empty)
// AuthPolicy in place.
func TestSeal_TPMPolicy_AuthPolicyOverridesTemplate(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()
	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	ctx := context.Background()
	explicitDigest := make([]byte, 32)
	for i := range explicitDigest {
		explicitDigest[i] = 0xAB
	}

	sealed, err := tpm2Instance.Seal(ctx, []byte("auth-policy-branch"), &types.SealOptions{
		KeyAttributes: &types.KeyAttributes{CN: "auth-policy-key", Parent: ssrkAttrs},
		TPMPolicy:     &types.TPMSealPolicy{AuthPolicy: explicitDigest},
	})
	require.NoError(t, err, "sealing with an explicit AuthPolicy digest must succeed")
	require.NotEmpty(t, sealed.TPMPublic)

	public, err := UnmarshalPublic(sealed.TPMPublic)
	require.NoError(t, err)
	assert.Equal(t, explicitDigest, public.AuthPolicy.Buffer,
		"the object's AuthPolicy must be exactly the digest SealOptions.TPMPolicy carried, "+
			"not KeyedHashTemplate's own empty default")
}

// TestSeal_TPMPolicy_CopiesPCRSelectionAndHashAlg proves Seal copies
// TPMPolicy.PCRSelection and TPMPolicy.HashAlg onto the key's TPMAttributes
// before sealing. opts.KeyAttributes is a pointer Seal mutates in place, so
// the copy is observable directly on the caller's struct after Seal returns.
func TestSeal_TPMPolicy_CopiesPCRSelectionAndHashAlg(t *testing.T) {
	_, tpm := createSim(false, false)
	defer func() { _ = tpm.Close() }()
	tpm2Instance := tpm.(*TPM2)

	ssrkAttrs, err := tpm.SSRKAttributes()
	require.NoError(t, err)

	keyAttrs := &types.KeyAttributes{CN: "pcr-selection-key", Parent: ssrkAttrs}
	pcrSelection := tpm2.TPMLPCRSelection{
		PCRSelections: []tpm2.TPMSPCRSelection{
			{Hash: tpm2.TPMAlgSHA256, PCRSelect: []byte{0x80}},
		},
	}

	_, err = tpm2Instance.Seal(context.Background(), []byte("pcr-selection-branch"), &types.SealOptions{
		KeyAttributes: keyAttrs,
		TPMPolicy:     &types.TPMSealPolicy{PCRSelection: pcrSelection, HashAlg: tpm2.TPMAlgSHA256},
	})
	require.NoError(t, err)

	require.NotNil(t, keyAttrs.TPMAttributes)
	assert.Equal(t, pcrSelection, keyAttrs.TPMAttributes.PCRSelection)
	assert.Equal(t, tpm2.TPMIAlgHash(tpm2.TPMAlgSHA256), keyAttrs.TPMAttributes.HashAlg)
}
