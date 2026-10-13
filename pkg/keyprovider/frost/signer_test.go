//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package frost

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

func createTestSignerBackend(t *testing.T) *FrostBackend {
	config := &Config{
		DAOs:                testutil.NewMemoryDAOFactory(),
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

// createTestSigner builds a FrostSigner directly from real DKG key
// material so the accessor tests below exercise genuine threshold=2/total=3
// key data. It bypasses FrostBackend.Signer, which refuses to construct a
// signer for a threshold greater than 1 (see
// TestFrostBackend_Signer_RefusesThresholdGreaterThanOne).
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
	_, err := backend.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	pkg, _, err := backend.KeyStore().LoadKeyPackage(context.Background(), "test-signer-key", 1)
	require.NoError(t, err)

	return &FrostSigner{backend: backend, keyID: "test-signer-key", keyPackage: pkg}, backend
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

func TestFrostBackend_Signer_RefusesThresholdGreaterThanOne(t *testing.T) {
	backend := createTestSignerBackend(t)

	attrs := &types.KeyAttributes{
		CN:        "test-threshold-key",
		KeyType:   types.KeyTypeSigning,
		StoreType: types.StoreFrost,
		FrostAttributes: &types.FrostAttributes{
			Threshold:     2,
			Total:         3,
			ParticipantID: 1,
			Algorithm:     types.FrostAlgorithmEd25519,
		},
	}
	_, err := backend.GenerateKey(context.Background(), attrs)
	require.NoError(t, err)

	// A crypto.Signer performs one synchronous Sign call and cannot
	// coordinate a multi-party FROST round, so construction must be
	// refused with a typed error rather than deferring failure to Sign.
	signer, err := backend.Signer(context.Background(), attrs)
	require.Error(t, err)
	assert.Nil(t, signer)

	var thresholdErr *ThresholdSigningNotSupportedError
	require.ErrorAs(t, err, &thresholdErr)
	assert.Equal(t, "test-threshold-key", thresholdErr.KeyID)
	assert.Equal(t, uint32(2), thresholdErr.Threshold)
	assert.ErrorIs(t, err, ErrThresholdSigningNotSupported)
	assert.Contains(t, err.Error(), "GenerateNonces")
}

// Note: threshold=1 key material cannot be constructed through any
// generator in this codebase. go-frost's own trusted-dealer
// implementation hard-refuses minSigners < 2
// (frost.ErrInvalidThreshold, "must be at least 2"), matching
// types.FrostAttributes.Validate and frost.FrostConfig.Validate here.
// FrostSigner.Sign's single-participant round is therefore
// unreachable through any real key today; FrostBackend.Signer exists
// to serve it if that library constraint is ever relaxed, and refuses
// construction for every other threshold instead of deferring failure
// to Sign (see TestFrostBackend_Signer_RefusesThresholdGreaterThanOne).

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
				DAOs:                testutil.NewMemoryDAOFactory(),
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
			_, err = backend.GenerateKey(context.Background(), attrs)
			require.NoError(t, err)

			// backend.Signer refuses this threshold=2 key (see
			// TestFrostBackend_Signer_RefusesThresholdGreaterThanOne), so
			// the accessor methods are exercised directly against the
			// loaded key package instead.
			pkg, _, err := backend.KeyStore().LoadKeyPackage(context.Background(), "test-key", 1)
			require.NoError(t, err)

			frostSigner := &FrostSigner{backend: backend, keyID: "test-key", keyPackage: pkg}
			assert.Equal(t, algo, frostSigner.Algorithm())

			// Verify public key size matches expected
			expectedSize := GetPublicKeySize(algo)
			assert.Len(t, frostSigner.GroupPublicKey(), expectedSize)
		})
	}
}
