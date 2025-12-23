//go:build integration && frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost_test

import (
	"fmt"
	"testing"

	"github.com/jeremyhahn/go-keychain/pkg/backend/frost"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	"github.com/jeremyhahn/go-keychain/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// multiParticipantSetup creates backends for all participants with properly distributed key packages.
// This simulates a real distributed FROST deployment where each participant has their own backend.
type multiParticipantSetup struct {
	Backends []*frost.FrostBackend
	KeyID    string
	Packages []*frost.KeyPackage
}

// createMultiParticipantSetup creates a test setup with properly distributed key packages.
func createMultiParticipantSetup(t *testing.T, keyID string, threshold, total int, algorithm types.FrostAlgorithm) *multiParticipantSetup {
	t.Helper()

	// Generate all key packages using TrustedDealer directly
	td := frost.NewTrustedDealer()
	config := frost.FrostConfig{
		Threshold:     threshold,
		Total:         total,
		Algorithm:     algorithm,
		ParticipantID: 1,
	}

	packages, _, err := td.Generate(config)
	require.NoError(t, err)
	require.Len(t, packages, total)

	// Create backends for each participant and store their key packages
	backends := make([]*frost.FrostBackend, total)
	for i := 0; i < total; i++ {
		participantID := uint32(i + 1)

		publicStore, err := storage.NewMemoryBackend()
		require.NoError(t, err)

		secretBackend := newTestSecretBackend()

		backendConfig := &frost.Config{
			PublicStorage:       publicStore,
			SecretBackend:       secretBackend,
			Algorithm:           algorithm,
			DefaultThreshold:    threshold,
			DefaultTotal:        total,
			ParticipantID:       participantID,
			EnableNonceTracking: true,
		}

		backend, err := frost.NewBackend(backendConfig)
		require.NoError(t, err)
		backends[i] = backend

		// Store the key package for this participant
		pkg := packages[i]

		// Store public components (metadata, group public key, verification shares)
		err = publicStore.Put("frost/keys/"+keyID+"/metadata.json",
			[]byte(fmt.Sprintf(`{"key_id":"%s","algorithm":"%s","threshold":%d,"total":%d,"participant_id":%d,"created_at":0,"secret_backend_type":"pkcs8"}`,
				keyID, algorithm, threshold, total, participantID)), nil)
		require.NoError(t, err)

		err = publicStore.Put("frost/keys/"+keyID+"/group_public.bin", pkg.GroupPublicKey, nil)
		require.NoError(t, err)

		// Store verification shares for all participants
		for pid, vs := range pkg.VerificationShares {
			path := fmt.Sprintf("frost/keys/%s/verification_shares/%d.bin", keyID, pid)
			err = publicStore.Put(path, vs, nil)
			require.NoError(t, err)
		}

		// Store secret share
		err = secretBackend.Storage().Put("frost/secrets/"+keyID+".secret", pkg.SecretShare.Value, nil)
		require.NoError(t, err)
	}

	return &multiParticipantSetup{
		Backends: backends,
		KeyID:    keyID,
		Packages: packages,
	}
}

// Close cleans up all backends in the setup.
func (s *multiParticipantSetup) Close() {
	for _, b := range s.Backends {
		if b != nil {
			_ = b.Close()
		}
	}
}

// TestFrostSigning_MinimalThreshold tests signing with minimum threshold (2-of-2)
// This test properly sets up two separate backends (one per participant) and
// distributes key packages to simulate a real distributed signing scenario.
func TestFrostSigning_MinimalThreshold(t *testing.T) {
	keyID := "minimal-threshold-key"
	threshold := 2
	total := 2

	// Generate all key packages using TrustedDealer directly
	td := frost.NewTrustedDealer()
	config := frost.FrostConfig{
		Threshold:     threshold,
		Total:         total,
		Algorithm:     types.FrostAlgorithmEd25519,
		ParticipantID: 1,
	}

	packages, _, err := td.Generate(config)
	require.NoError(t, err)
	require.Len(t, packages, total)

	// Create backends for each participant and store their key packages
	backends := make([]*frost.FrostBackend, total)
	for i := 0; i < total; i++ {
		participantID := uint32(i + 1)

		publicStore, err := storage.NewMemoryBackend()
		require.NoError(t, err)

		secretBackend := newTestSecretBackend()

		backendConfig := &frost.Config{
			PublicStorage:       publicStore,
			SecretBackend:       secretBackend,
			Algorithm:           types.FrostAlgorithmEd25519,
			DefaultThreshold:    threshold,
			DefaultTotal:        total,
			ParticipantID:       participantID,
			EnableNonceTracking: true,
		}

		backend, err := frost.NewBackend(backendConfig)
		require.NoError(t, err)
		backends[i] = backend

		// Store the key package for this participant using the backend's internal KeyStore
		pkg := packages[i]
		metadata := &frost.KeyMetadata{
			KeyID:             keyID,
			Algorithm:         types.FrostAlgorithmEd25519,
			Threshold:         threshold,
			Total:             total,
			ParticipantID:     participantID,
			CreatedAt:         0,
			SecretBackendType: types.BackendTypeSoftware,
		}

		// Store public components
		err = publicStore.Put("frost/keys/"+keyID+"/metadata.json",
			[]byte(fmt.Sprintf(`{"key_id":"%s","algorithm":"%s","threshold":%d,"total":%d,"participant_id":%d,"created_at":0,"secret_backend_type":"pkcs8"}`,
				keyID, types.FrostAlgorithmEd25519, threshold, total, participantID)), nil)
		require.NoError(t, err)

		err = publicStore.Put("frost/keys/"+keyID+"/group_public.bin", pkg.GroupPublicKey, nil)
		require.NoError(t, err)

		// Store verification shares for all participants
		for pid, vs := range pkg.VerificationShares {
			path := fmt.Sprintf("frost/keys/%s/verification_shares/%d.bin", keyID, pid)
			err = publicStore.Put(path, vs, nil)
			require.NoError(t, err)
		}

		// Store secret share
		err = secretBackend.Storage().Put("frost/secrets/"+keyID+".secret", pkg.SecretShare.Value, nil)
		require.NoError(t, err)

		t.Logf("Stored key package for participant %d", participantID)
		_ = metadata // used in setup
	}

	// Clean up all backends at the end
	defer func() {
		for _, b := range backends {
			if b != nil {
				_ = b.Close()
			}
		}
	}()

	// Round 1: Each participant generates their nonces
	noncePackages := make([]*frost.NoncePackage, total)
	for i := 0; i < total; i++ {
		np, err := backends[i].GenerateNonces(keyID)
		require.NoError(t, err, "Participant %d should generate nonces", i+1)
		noncePackages[i] = np
		t.Logf("Participant %d generated nonces", i+1)
	}

	// Create commitments from all participants
	commitments := make([]*frost.Commitment, total)
	for i := 0; i < total; i++ {
		commitments[i] = &frost.Commitment{
			ParticipantID: noncePackages[i].ParticipantID,
			Commitments:   noncePackages[i].Commitments,
		}
	}

	message := []byte("Test message for 2-of-2 FROST signing")

	// Round 2: Each participant generates their signature share
	shares := make([]*frost.SignatureShare, total)
	for i := 0; i < total; i++ {
		share, err := backends[i].SignRound(keyID, message, noncePackages[i], commitments)
		require.NoError(t, err, "Participant %d should generate signature share", i+1)
		shares[i] = share
		t.Logf("Participant %d generated signature share", i+1)
	}

	// Aggregate signature shares (any participant can do this with the public info)
	signature, err := backends[0].Aggregate(keyID, message, commitments, shares)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	t.Logf("2-of-2 signature size: %d bytes", len(signature))

	// Verify signature (any participant can verify with the public key)
	err = backends[0].Verify(keyID, message, signature)
	require.NoError(t, err, "Signature verification should pass")

	t.Log("2-of-2 threshold signing completed successfully!")
}

// TestFrostSigning_ExplicitRounds tests the explicit round API for distributed signing
// This tests a 2-of-3 threshold signing with all 3 participants generating nonces
// but only 2 participating in the actual signing.
func TestFrostSigning_ExplicitRounds(t *testing.T) {
	numParticipants := 3
	threshold := 2

	// Create properly distributed multi-participant setup
	setup := createMultiParticipantSetup(t, "distributed-signing-key", threshold, numParticipants, types.FrostAlgorithmEd25519)
	defer setup.Close()

	t.Log("FROST key distributed to all participants")

	message := []byte("Test message for distributed FROST signing")

	// Round 1: Each participant generates their nonces
	noncePackages := make([]*frost.NoncePackage, numParticipants)
	for i := 0; i < numParticipants; i++ {
		np, err := setup.Backends[i].GenerateNonces(setup.KeyID)
		require.NoError(t, err, "Participant %d should generate nonces", i+1)
		noncePackages[i] = np
		t.Logf("Participant %d generated nonces (session: %s)", i+1, np.SessionID)
	}

	// Create commitments for threshold participants (first 2 of 3)
	commitments := make([]*frost.Commitment, threshold)
	for i := 0; i < threshold; i++ {
		commitments[i] = &frost.Commitment{
			ParticipantID: noncePackages[i].ParticipantID,
			Commitments:   noncePackages[i].Commitments,
		}
	}

	// Round 2: Generate signature shares from threshold participants
	shares := make([]*frost.SignatureShare, threshold)
	for i := 0; i < threshold; i++ {
		share, err := setup.Backends[i].SignRound(setup.KeyID, message, noncePackages[i], commitments)
		require.NoError(t, err, "Participant %d should generate signature share", i+1)
		shares[i] = share
		t.Logf("Participant %d generated signature share", i+1)
	}

	// Aggregate signature shares
	signature, err := setup.Backends[0].Aggregate(setup.KeyID, message, commitments, shares)
	require.NoError(t, err, "Should aggregate signature shares")
	require.NotEmpty(t, signature)

	t.Logf("Aggregated signature size: %d bytes", len(signature))

	// Verify the final signature (any participant can verify)
	err = setup.Backends[2].Verify(setup.KeyID, message, signature)
	require.NoError(t, err, "Signature verification should pass")

	t.Log("Distributed 2-of-3 signing workflow completed successfully!")
}

// TestFrostSigning_NonceReuseProtection tests nonce reuse detection
func TestFrostSigning_NonceReuseProtection(t *testing.T) {
	// Use 2-of-2 setup for proper multi-participant testing
	setup := createMultiParticipantSetup(t, "nonce-reuse-test-key", 2, 2, types.FrostAlgorithmEd25519)
	defer setup.Close()

	// Each participant generates their nonces
	np1, err := setup.Backends[0].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	np2, err := setup.Backends[1].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	// Create commitments for both participants
	commitments := []*frost.Commitment{
		{ParticipantID: np1.ParticipantID, Commitments: np1.Commitments},
		{ParticipantID: np2.ParticipantID, Commitments: np2.Commitments},
	}

	message := []byte("Test message")

	// First use of participant 1's nonces should succeed
	share1, err := setup.Backends[0].SignRound(setup.KeyID, message, np1, commitments)
	require.NoError(t, err, "First use of nonces should succeed")
	require.NotNil(t, share1)

	// Attempting to reuse participant 1's nonces should fail
	_, err = setup.Backends[0].SignRound(setup.KeyID, message, np1, commitments)
	assert.Error(t, err, "Nonce reuse should be detected and rejected")

	t.Log("Nonce reuse protection is working correctly")
}

// TestFrostSigning_InsufficientShares tests that signing fails with fewer than threshold commitments
func TestFrostSigning_InsufficientShares(t *testing.T) {
	// Use 3-of-5 setup
	setup := createMultiParticipantSetup(t, "insufficient-shares-key", 3, 5, types.FrostAlgorithmEd25519)
	defer setup.Close()

	// Generate nonces for only 2 participants (below threshold of 3)
	np1, err := setup.Backends[0].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	np2, err := setup.Backends[1].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	// Create commitments for only 2 participants (below threshold)
	commitments := []*frost.Commitment{
		{ParticipantID: np1.ParticipantID, Commitments: np1.Commitments},
		{ParticipantID: np2.ParticipantID, Commitments: np2.Commitments},
	}

	message := []byte("Test message")

	// SignRound should fail because we have fewer commitments than threshold (need 3, have 2)
	_, err = setup.Backends[0].SignRound(setup.KeyID, message, np1, commitments)
	assert.Error(t, err, "Should fail with insufficient commitments")

	t.Log("Insufficient shares detection is working correctly")
}

// TestFrostSigning_VerifyInvalidSignature tests signature verification failure
func TestFrostSigning_VerifyInvalidSignature(t *testing.T) {
	// Use 2-of-2 setup
	setup := createMultiParticipantSetup(t, "verify-test-key", 2, 2, types.FrostAlgorithmEd25519)
	defer setup.Close()

	// Generate nonces for both participants
	np1, err := setup.Backends[0].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	np2, err := setup.Backends[1].GenerateNonces(setup.KeyID)
	require.NoError(t, err)

	commitments := []*frost.Commitment{
		{ParticipantID: np1.ParticipantID, Commitments: np1.Commitments},
		{ParticipantID: np2.ParticipantID, Commitments: np2.Commitments},
	}

	message := []byte("Original message")

	// Generate signature shares from each participant
	share1, err := setup.Backends[0].SignRound(setup.KeyID, message, np1, commitments)
	require.NoError(t, err)

	share2, err := setup.Backends[1].SignRound(setup.KeyID, message, np2, commitments)
	require.NoError(t, err)

	shares := []*frost.SignatureShare{share1, share2}

	// Aggregate signature
	signature, err := setup.Backends[0].Aggregate(setup.KeyID, message, commitments, shares)
	require.NoError(t, err)

	// Verify with correct message should pass
	err = setup.Backends[0].Verify(setup.KeyID, message, signature)
	require.NoError(t, err, "Correct message should verify")

	// Verify with wrong message should fail
	wrongMessage := []byte("Wrong message")
	err = setup.Backends[0].Verify(setup.KeyID, wrongMessage, signature)
	assert.Error(t, err, "Wrong message should fail verification")

	// Verify with corrupted signature should fail
	corruptedSig := make([]byte, len(signature))
	copy(corruptedSig, signature)
	corruptedSig[0] ^= 0xFF // Flip bits
	err = setup.Backends[0].Verify(setup.KeyID, message, corruptedSig)
	assert.Error(t, err, "Corrupted signature should fail verification")

	t.Log("Signature verification correctly rejects invalid signatures")
}

// TestFrostSigning_AllAlgorithms tests signing with all supported algorithms
func TestFrostSigning_AllAlgorithms(t *testing.T) {
	algorithms := []types.FrostAlgorithm{
		types.FrostAlgorithmEd25519,
		types.FrostAlgorithmRistretto255,
		types.FrostAlgorithmP256,
		types.FrostAlgorithmSecp256k1,
	}

	for _, algo := range algorithms {
		t.Run(string(algo), func(t *testing.T) {
			keyID := "sign-test-" + string(algo)

			// Create properly distributed 2-of-2 setup for each algorithm
			setup := createMultiParticipantSetup(t, keyID, 2, 2, algo)
			defer setup.Close()

			// Generate nonces for both participants
			np1, err := setup.Backends[0].GenerateNonces(keyID)
			require.NoError(t, err)

			np2, err := setup.Backends[1].GenerateNonces(keyID)
			require.NoError(t, err)

			commitments := []*frost.Commitment{
				{ParticipantID: np1.ParticipantID, Commitments: np1.Commitments},
				{ParticipantID: np2.ParticipantID, Commitments: np2.Commitments},
			}

			message := []byte("Test message for " + string(algo))

			// Generate signature shares from each participant
			share1, err := setup.Backends[0].SignRound(keyID, message, np1, commitments)
			require.NoError(t, err)

			share2, err := setup.Backends[1].SignRound(keyID, message, np2, commitments)
			require.NoError(t, err)

			shares := []*frost.SignatureShare{share1, share2}

			// Aggregate signature
			signature, err := setup.Backends[0].Aggregate(keyID, message, commitments, shares)
			require.NoError(t, err, "Signing with %s should succeed", algo)

			t.Logf("%s: signature size = %d bytes", algo, len(signature))

			// Verify
			err = setup.Backends[0].Verify(keyID, message, signature)
			require.NoError(t, err, "Verification with %s should succeed", algo)
		})
	}
}
