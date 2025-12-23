//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-keychain/pkg/types"
)

func createMultiParticipantBackends(t *testing.T) []*FrostBackend {
	// Generate keys using trusted dealer
	dealer := NewTrustedDealer()
	genConfig := FrostConfig{
		Threshold: 2,
		Total:     3,
		Algorithm: types.FrostAlgorithmEd25519,
	}

	packages, _, err := dealer.Generate(genConfig)
	require.NoError(t, err)

	var backends []*FrostBackend
	for i, pkg := range packages {
		storage := newMockStorageBackend()
		secret := newMockSecretBackend()

		config := &Config{
			PublicStorage:       storage,
			SecretBackend:       secret,
			Algorithm:           types.FrostAlgorithmEd25519,
			DefaultThreshold:    2,
			DefaultTotal:        3,
			ParticipantID:       uint32(i + 1),
			EnableNonceTracking: true,
		}

		backend, err := NewBackend(config)
		require.NoError(t, err)

		// Store the key package directly
		keyID := "test-signing-key"
		metadata := &KeyMetadata{
			KeyID:         keyID,
			Algorithm:     types.FrostAlgorithmEd25519,
			Threshold:     2,
			Total:         3,
			ParticipantID: uint32(i + 1),
		}
		err = backend.keystore.StoreKeyPackage(keyID, pkg, metadata)
		require.NoError(t, err)

		backends = append(backends, backend)
	}

	return backends
}

func TestGenerateNonces_Success(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"

	noncePackage, err := backends[0].GenerateNonces(keyID)
	require.NoError(t, err)
	require.NotNil(t, noncePackage)

	assert.Equal(t, uint32(1), noncePackage.ParticipantID)
	assert.NotEmpty(t, noncePackage.SessionID)
	assert.NotNil(t, noncePackage.Nonces)
	assert.NotNil(t, noncePackage.Commitments)

	// Check nonces
	assert.NotEmpty(t, noncePackage.Nonces.HidingNonce)
	assert.NotEmpty(t, noncePackage.Nonces.BindingNonce)

	// Check commitments
	assert.Equal(t, uint32(1), noncePackage.Commitments.ParticipantID)
	assert.NotEmpty(t, noncePackage.Commitments.HidingCommitment)
	assert.NotEmpty(t, noncePackage.Commitments.BindingCommitment)
}

func TestGenerateNonces_BackendClosed(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	backend := backends[0]
	backend.Close()

	_, err := backend.GenerateNonces("test-signing-key")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestGenerateNonces_KeyNotFound(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	_, err := backends[0].GenerateNonces("nonexistent-key")
	require.Error(t, err)
}

func TestSignRound_Success(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	// Generate nonces for both participants
	nonce1, err := backends[0].GenerateNonces(keyID)
	require.NoError(t, err)

	nonce2, err := backends[1].GenerateNonces(keyID)
	require.NoError(t, err)

	// Collect commitments
	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
		{ParticipantID: nonce2.ParticipantID, Commitments: nonce2.Commitments},
	}

	// Generate signature share from participant 1
	share, err := backends[0].SignRound(keyID, message, nonce1, commitments)
	require.NoError(t, err)
	require.NotNil(t, share)

	assert.Equal(t, uint32(1), share.ParticipantID)
	assert.Equal(t, nonce1.SessionID, share.SessionID)
	assert.NotEmpty(t, share.Share)
}

func TestSignRound_NilNonces(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	_, err := backends[0].SignRound(keyID, message, nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNonceNotFound))
}

func TestSignRound_EmptyCommitments(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	nonce1, err := backends[0].GenerateNonces(keyID)
	require.NoError(t, err)

	_, err = backends[0].SignRound(keyID, message, nonce1, []*Commitment{})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidCommitment))
}

func TestSignRound_InsufficientCommitments(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	nonce1, err := backends[0].GenerateNonces(keyID)
	require.NoError(t, err)

	// Only 1 commitment but threshold is 2
	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
	}

	_, err = backends[0].SignRound(keyID, message, nonce1, commitments)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInsufficientShares))
}

func TestSignRound_BackendClosed(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	backend := backends[0]

	keyID := "test-signing-key"
	nonce, _ := backend.GenerateNonces(keyID)

	backend.Close()

	_, err := backend.SignRound(keyID, []byte("message"), nonce, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestAggregate_Success(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message for aggregation")

	// Generate nonces
	nonce1, err := backends[0].GenerateNonces(keyID)
	require.NoError(t, err)

	nonce2, err := backends[1].GenerateNonces(keyID)
	require.NoError(t, err)

	// Collect commitments
	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
		{ParticipantID: nonce2.ParticipantID, Commitments: nonce2.Commitments},
	}

	// Generate signature shares
	share1, err := backends[0].SignRound(keyID, message, nonce1, commitments)
	require.NoError(t, err)

	share2, err := backends[1].SignRound(keyID, message, nonce2, commitments)
	require.NoError(t, err)

	shares := []*SignatureShare{share1, share2}

	// Aggregate
	signature, err := backends[0].Aggregate(keyID, message, commitments, shares)
	require.NoError(t, err)
	require.NotEmpty(t, signature)

	// Ed25519 signature should be 64 bytes
	assert.Len(t, signature, 64)
}

func TestAggregate_InsufficientShares(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	// Only 1 share but threshold is 2
	nonce1, _ := backends[0].GenerateNonces(keyID)
	nonce2, _ := backends[1].GenerateNonces(keyID)

	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
		{ParticipantID: nonce2.ParticipantID, Commitments: nonce2.Commitments},
	}

	share1, _ := backends[0].SignRound(keyID, message, nonce1, commitments)

	_, err := backends[0].Aggregate(keyID, message, commitments, []*SignatureShare{share1})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInsufficientShares))
}

func TestAggregate_BackendClosed(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	backend := backends[0]
	backend.Close()

	_, err := backend.Aggregate("test-signing-key", []byte("message"), nil, nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestVerify_Success(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message for verification")

	// Generate full signature
	nonce1, _ := backends[0].GenerateNonces(keyID)
	nonce2, _ := backends[1].GenerateNonces(keyID)

	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
		{ParticipantID: nonce2.ParticipantID, Commitments: nonce2.Commitments},
	}

	share1, _ := backends[0].SignRound(keyID, message, nonce1, commitments)
	share2, _ := backends[1].SignRound(keyID, message, nonce2, commitments)

	signature, err := backends[0].Aggregate(keyID, message, commitments, []*SignatureShare{share1, share2})
	require.NoError(t, err)

	// Verify the signature
	err = backends[0].Verify(keyID, message, signature)
	assert.NoError(t, err)
}

func TestVerify_InvalidSignature(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	// Create a fake signature (wrong bytes but correct size)
	// Note: The bytes might fail deserialization before verification
	fakeSignature := make([]byte, 64)
	for i := range fakeSignature {
		fakeSignature[i] = byte(i)
	}

	err := backends[0].Verify(keyID, message, fakeSignature)
	require.Error(t, err)
	// The error can be either ErrInvalidSignature or a deserialization error
	// (invalid curve points can't be deserialized)
	assert.True(t, errors.Is(err, ErrInvalidSignature) ||
		strings.Contains(err.Error(), "failed to deserialize") ||
		strings.Contains(err.Error(), "invalid"))
}

func TestVerify_WrongMessage(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message1 := []byte("original message")
	message2 := []byte("different message")

	// Generate signature for message1
	nonce1, _ := backends[0].GenerateNonces(keyID)
	nonce2, _ := backends[1].GenerateNonces(keyID)

	commitments := []*Commitment{
		{ParticipantID: nonce1.ParticipantID, Commitments: nonce1.Commitments},
		{ParticipantID: nonce2.ParticipantID, Commitments: nonce2.Commitments},
	}

	share1, _ := backends[0].SignRound(keyID, message1, nonce1, commitments)
	share2, _ := backends[1].SignRound(keyID, message1, nonce2, commitments)

	signature, _ := backends[0].Aggregate(keyID, message1, commitments, []*SignatureShare{share1, share2})

	// Verify against different message should fail
	err := backends[0].Verify(keyID, message2, signature)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidSignature))
}

func TestVerify_WrongSignatureSize(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	keyID := "test-signing-key"
	message := []byte("test message")

	// Wrong size signature (Ed25519 should be 64 bytes)
	wrongSizeSignature := make([]byte, 32)

	err := backends[0].Verify(keyID, message, wrongSizeSignature)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "invalid signature size")
}

func TestVerify_BackendClosed(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	backend := backends[0]
	backend.Close()

	err := backend.Verify("test-signing-key", []byte("message"), make([]byte, 64))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrBackendClosed))
}

func TestVerify_KeyNotFound(t *testing.T) {
	backends := createMultiParticipantBackends(t)
	defer func() {
		for _, b := range backends {
			b.Close()
		}
	}()

	err := backends[0].Verify("nonexistent-key", []byte("message"), make([]byte, 64))
	require.Error(t, err)
}

func TestSignatureShare_Fields(t *testing.T) {
	share := &SignatureShare{
		ParticipantID: 3,
		SessionID:     "test-session",
		Share:         []byte{1, 2, 3, 4, 5},
	}

	assert.Equal(t, uint32(3), share.ParticipantID)
	assert.Equal(t, "test-session", share.SessionID)
	assert.Equal(t, []byte{1, 2, 3, 4, 5}, share.Share)
}

func TestDefaultSessionTimeout(t *testing.T) {
	// Verify the default timeout constant is reasonable
	assert.Greater(t, DefaultSessionTimeout.Minutes(), float64(0))
	assert.LessOrEqual(t, DefaultSessionTimeout.Minutes(), float64(60))
}
