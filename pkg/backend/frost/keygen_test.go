//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func TestFrostConfig_Validate_Success(t *testing.T) {
	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	err := config.Validate()
	assert.NoError(t, err)
}

func TestFrostConfig_Validate_ThresholdTooLow(t *testing.T) {
	config := FrostConfig{
		Threshold: 1,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold must be at least 2")
}

func TestFrostConfig_Validate_TotalLessThanThreshold(t *testing.T) {
	config := FrostConfig{
		Threshold: 5,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must be >= threshold")
}

func TestFrostConfig_Validate_ThresholdTooHigh(t *testing.T) {
	config := FrostConfig{
		Threshold: 256,
		Total:     256,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "threshold cannot exceed 255")
}

func TestFrostConfig_Validate_TotalTooHigh(t *testing.T) {
	config := FrostConfig{
		Threshold: 2,
		Total:     256,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "total cannot exceed 255")
}

func TestFrostConfig_Validate_ParticipantsMismatch(t *testing.T) {
	config := FrostConfig{
		Threshold:    2,
		Total:        3,
		Algorithm:    types.FrostAlgorithmEd25519,
		Participants: []string{"alice", "bob"}, // 2 instead of 3
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "participants length")
}

func TestFrostConfig_Validate_InvalidAlgorithm(t *testing.T) {
	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: "invalid",
	}

	err := config.Validate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid algorithm")
}

func TestSecretKeyShare_Zeroize(t *testing.T) {
	share := &SecretKeyShare{
		Value: []byte{1, 2, 3, 4, 5},
	}

	share.Zeroize()

	for i, b := range share.Value {
		assert.Equal(t, byte(0), b, "Value[%d] should be zero", i)
	}
}

func TestSecretKeyShare_Zeroize_Nil(t *testing.T) {
	share := &SecretKeyShare{}
	// Should not panic
	share.Zeroize()
}

func TestNewTrustedDealer(t *testing.T) {
	dealer := NewTrustedDealer()
	assert.NotNil(t, dealer)
}

func TestTrustedDealer_Generate_Success(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	packages, publicPkg, err := dealer.Generate(config)
	require.NoError(t, err)
	require.NotNil(t, packages)
	require.NotNil(t, publicPkg)

	// Should have 3 packages
	assert.Len(t, packages, 3)

	// Verify public package
	assert.NotEmpty(t, publicPkg.GroupPublicKey)
	assert.Equal(t, uint32(2), publicPkg.MinSigners)
	assert.Equal(t, uint32(3), publicPkg.MaxSigners)
	assert.Equal(t, types.FrostAlgorithmEd25519, publicPkg.Algorithm)
	assert.NotEmpty(t, publicPkg.VerificationShares)

	// Verify each package
	for i, pkg := range packages {
		t.Run("Package"+string(rune('1'+i)), func(t *testing.T) {
			assert.Equal(t, uint32(i+1), pkg.ParticipantID)
			assert.NotNil(t, pkg.SecretShare)
			assert.NotEmpty(t, pkg.SecretShare.Value)
			assert.NotEmpty(t, pkg.GroupPublicKey)
			assert.Equal(t, uint32(2), pkg.MinSigners)
			assert.Equal(t, uint32(3), pkg.MaxSigners)
			assert.Equal(t, types.FrostAlgorithmEd25519, pkg.Algorithm)
			assert.NotEmpty(t, pkg.VerificationShares)

			// All packages should have the same group public key
			assert.Equal(t, publicPkg.GroupPublicKey, pkg.GroupPublicKey)
		})
	}
}

func TestTrustedDealer_Generate_AllAlgorithms(t *testing.T) {
	dealer := NewTrustedDealer()

	algorithms := []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmEd448,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			config := FrostConfig{
				Threshold: 2,
				Total:     3,
				Algorithm: algo,
			}

			packages, publicPkg, err := dealer.Generate(config)
			require.NoError(t, err)
			assert.Len(t, packages, 3)
			assert.NotNil(t, publicPkg)

			// Verify public key size matches expected
			expectedSize := GetPublicKeySize(algo)
			assert.Len(t, publicPkg.GroupPublicKey, expectedSize)
		})
	}
}

func TestTrustedDealer_Generate_InvalidConfig(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 1, // Invalid
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	packages, publicPkg, err := dealer.Generate(config)
	require.Error(t, err)
	assert.Nil(t, packages)
	assert.Nil(t, publicPkg)
	assert.Contains(t, err.Error(), "invalid config")
}

func TestTrustedDealer_Generate_ThresholdVariations(t *testing.T) {
	dealer := NewTrustedDealer()

	tests := []struct {
		name      string
		threshold int
		total     int
	}{
		{"2-of-2", 2, 2},
		{"2-of-3", 2, 3},
		{"3-of-5", 3, 5},
		{"5-of-10", 5, 10},
		{"10-of-10", 10, 10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := FrostConfig{
				Threshold: tt.threshold,
				Total:     tt.total,
				Algorithm: types.FrostAlgorithmEd25519,
			}

			packages, publicPkg, err := dealer.Generate(config)
			require.NoError(t, err)
			assert.Len(t, packages, tt.total)
			assert.Equal(t, uint32(tt.threshold), publicPkg.MinSigners)
			assert.Equal(t, uint32(tt.total), publicPkg.MaxSigners)
		})
	}
}

func TestTrustedDealer_GenerateSinglePackage_Success(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	pkg, publicPkg, err := dealer.GenerateSinglePackage(config, 2)
	require.NoError(t, err)
	require.NotNil(t, pkg)
	require.NotNil(t, publicPkg)

	assert.Equal(t, uint32(2), pkg.ParticipantID)
	assert.NotEmpty(t, pkg.SecretShare.Value)
}

func TestTrustedDealer_GenerateSinglePackage_InvalidParticipantID(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	// Participant ID 0 is invalid
	pkg, publicPkg, err := dealer.GenerateSinglePackage(config, 0)
	require.Error(t, err)
	assert.Nil(t, pkg)
	assert.Nil(t, publicPkg)
	assert.Contains(t, err.Error(), "invalid participant ID")

	// Participant ID 4 is invalid for 3 participants
	pkg, publicPkg, err = dealer.GenerateSinglePackage(config, 4)
	require.Error(t, err)
	assert.Nil(t, pkg)
	assert.Nil(t, publicPkg)
	assert.Contains(t, err.Error(), "invalid participant ID")
}

func TestTrustedDealer_GenerateSinglePackage_InvalidConfig(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 1, // Invalid
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	pkg, publicPkg, err := dealer.GenerateSinglePackage(config, 1)
	require.Error(t, err)
	assert.Nil(t, pkg)
	assert.Nil(t, publicPkg)
}

func TestKeyPackage_VerificationShares(t *testing.T) {
	dealer := NewTrustedDealer()

	config := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	packages, _, err := dealer.Generate(config)
	require.NoError(t, err)

	// All packages should have the same verification shares
	for i := 1; i < len(packages); i++ {
		assert.Equal(t, packages[0].VerificationShares, packages[i].VerificationShares)
	}

	// Should have verification shares - at least threshold number
	assert.GreaterOrEqual(t, len(packages[0].VerificationShares), config.Threshold)

	// Check that the verification shares are valid (non-empty)
	for id, share := range packages[0].VerificationShares {
		assert.NotEmpty(t, share, "Verification share for participant %d should not be empty", id)
	}
}

func TestPublicKeyPackage(t *testing.T) {
	pkg := &PublicKeyPackage{
		GroupPublicKey:     []byte{1, 2, 3},
		VerificationShares: map[uint32][]byte{1: {4, 5, 6}},
		MinSigners:         2,
		MaxSigners:         3,
		Algorithm:          types.FrostAlgorithmEd25519,
	}

	assert.Equal(t, []byte{1, 2, 3}, pkg.GroupPublicKey)
	assert.Equal(t, uint32(2), pkg.MinSigners)
	assert.Equal(t, uint32(3), pkg.MaxSigners)
	assert.Equal(t, types.FrostAlgorithmEd25519, pkg.Algorithm)
}
