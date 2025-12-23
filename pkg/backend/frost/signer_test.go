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

func createTestSignerBackend(t *testing.T) *FrostBackend {
	config := &Config{
		PublicStorage:       newMockStorageBackend(),
		SecretBackend:       newMockSecretBackend(),
		Algorithm:           types.FrostAlgorithmEd25519,
		DefaultThreshold:    2,
		DefaultTotal:        3,
		ParticipantID:       1,
		EnableNonceTracking: true,
	}

	backend, err := NewBackend(config)
	require.NoError(t, err)
	return backend
}

func createTestSigner(t *testing.T) (*FrostSigner, *FrostBackend) {
	backend := createTestSignerBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-signer-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err := backend.GenerateKey(attrs)
	require.NoError(t, err)

	signer, err := backend.Signer(attrs)
	require.NoError(t, err)

	return signer.(*FrostSigner), backend
}

func TestFrostSigner_Public(t *testing.T) {
	signer, _ := createTestSigner(t)

	pubKey := signer.Public()
	require.NotNil(t, pubKey)

	// Should be the group public key bytes
	pubBytes, ok := pubKey.([]byte)
	require.True(t, ok)
	assert.NotEmpty(t, pubBytes)
	assert.Len(t, pubBytes, 32) // Ed25519 public key size
}

func TestFrostSigner_Algorithm(t *testing.T) {
	signer, _ := createTestSigner(t)

	algo := signer.Algorithm()
	assert.Equal(t, types.FrostAlgorithmEd25519, algo)
}

func TestFrostSigner_KeyID(t *testing.T) {
	signer, _ := createTestSigner(t)

	keyID := signer.KeyID()
	assert.Equal(t, "test-signer-key", keyID)
}

func TestFrostSigner_ParticipantID(t *testing.T) {
	signer, _ := createTestSigner(t)

	participantID := signer.ParticipantID()
	assert.Equal(t, uint32(1), participantID)
}

func TestFrostSigner_Threshold(t *testing.T) {
	signer, _ := createTestSigner(t)

	threshold := signer.Threshold()
	assert.Equal(t, uint32(2), threshold)
}

func TestFrostSigner_Total(t *testing.T) {
	signer, _ := createTestSigner(t)

	total := signer.Total()
	assert.Equal(t, uint32(3), total)
}

func TestFrostSigner_GroupPublicKey(t *testing.T) {
	signer, _ := createTestSigner(t)

	pubKey := signer.GroupPublicKey()
	assert.NotEmpty(t, pubKey)
	assert.Len(t, pubKey, 32) // Ed25519 public key size
}

func TestFrostSigner_VerificationShare(t *testing.T) {
	signer, _ := createTestSigner(t)

	// Should have verification shares for at least threshold participants
	// Note: go-frost may only return threshold verification shares, not all total
	threshold := signer.Threshold()
	shareCount := 0

	for i := uint32(1); i <= 3; i++ {
		share := signer.VerificationShare(i)
		if share != nil {
			shareCount++
			assert.NotEmpty(t, share)
		}
	}

	// Should have at least threshold verification shares
	assert.GreaterOrEqual(t, uint32(shareCount), threshold)

	// Should return nil for non-existent participant
	share100 := signer.VerificationShare(100)
	assert.Nil(t, share100)
}

func TestFrostSigner_Sign_ThresholdGreaterThanOne(t *testing.T) {
	signer, _ := createTestSigner(t)

	// For threshold > 1, Sign() should return an error
	// because orchestrated multi-participant signing is not implemented
	digest := []byte("test message to sign")
	sig, err := signer.Sign(nil, digest, nil)

	require.Error(t, err)
	assert.Nil(t, sig)
	assert.Contains(t, err.Error(), "orchestrated multi-participant signing not implemented")
}

// Note: threshold=1 is not allowed by the FROST config validation (minimum is 2)
// The Sign function's single-participant path is therefore unused in standard config

func TestFrostSigner_AllAlgorithms(t *testing.T) {
	algorithms := []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			config := &Config{
				PublicStorage:       newMockStorageBackend(),
				SecretBackend:       newMockSecretBackend(),
				Algorithm:           algo,
				DefaultThreshold:    2,
				DefaultTotal:        3,
				ParticipantID:       1,
				EnableNonceTracking: true,
			}

			backend, err := NewBackend(config)
			require.NoError(t, err)

			attrs := &types.KeyAttributes{
				CN:        "test-key",
				KeyType:   types.KeyTypeSigning,
				StoreType: types.StoreFrost,
				FrostAttributes: &types.FrostAttributes{
					Threshold:     2,
					Total:         3,
					Algorithm:     algo,
					ParticipantID: 1,
				},
			}
			_, err = backend.GenerateKey(attrs)
			require.NoError(t, err)

			signer, err := backend.Signer(attrs)
			require.NoError(t, err)

			frostSigner := signer.(*FrostSigner)
			assert.Equal(t, algo, frostSigner.Algorithm())

			// Verify public key size matches expected
			expectedSize := GetPublicKeySize(algo)
			assert.Len(t, frostSigner.GroupPublicKey(), expectedSize)
		})
	}
}
