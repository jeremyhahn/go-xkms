//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.

package frost

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgstorage "github.com/jeremyhahn/go-keychain/pkg/storage"
)

func TestNewNonceTracker(t *testing.T) {
	stg := newMockStorageBackend()
	tracker := NewNonceTracker(stg)

	assert.NotNil(t, tracker)
	assert.Equal(t, stg, tracker.storage)
}

func TestNonceTracker_MarkUsed(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment := []byte("test-commitment-1234567890")

	// First use should succeed
	err := tracker.MarkUsed("key1", commitment)
	assert.NoError(t, err)

	// Second use should fail with ErrNonceAlreadyUsed
	err = tracker.MarkUsed("key1", commitment)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNonceAlreadyUsed))
}

func TestNonceTracker_MarkUsed_DifferentCommitments(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment1 := []byte("commitment-1")
	commitment2 := []byte("commitment-2")

	// Both should succeed as they are different
	err := tracker.MarkUsed("key1", commitment1)
	assert.NoError(t, err)

	err = tracker.MarkUsed("key1", commitment2)
	assert.NoError(t, err)
}

func TestNonceTracker_MarkUsed_DifferentKeys(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment := []byte("same-commitment")

	// Same commitment can be used for different keys
	err := tracker.MarkUsed("key1", commitment)
	assert.NoError(t, err)

	err = tracker.MarkUsed("key2", commitment)
	assert.NoError(t, err)
}

func TestNonceTracker_IsUsed(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment := []byte("test-commitment")

	// Initially not used
	used, err := tracker.IsUsed("key1", commitment)
	require.NoError(t, err)
	assert.False(t, used)

	// Mark as used
	err = tracker.MarkUsed("key1", commitment)
	require.NoError(t, err)

	// Now should be marked as used
	used, err = tracker.IsUsed("key1", commitment)
	require.NoError(t, err)
	assert.True(t, used)
}

func TestNonceTracker_MarkUsedWithDetails(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment := []byte("test-commitment")

	// First use should succeed
	err := tracker.MarkUsedWithDetails("key1", 2, "session-123", commitment)
	assert.NoError(t, err)

	// Second use should fail with detailed error
	err = tracker.MarkUsedWithDetails("key1", 2, "session-123", commitment)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNonceAlreadyUsed))

	var nonceErr *NonceReuseError
	assert.True(t, errors.As(err, &nonceErr))
	assert.Equal(t, "key1", nonceErr.KeyID)
	assert.Equal(t, uint32(2), nonceErr.ParticipantID)
	assert.Equal(t, "session-123", nonceErr.SessionID)
}

func TestNonceTracker_DeleteKeyNonces(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	commitment1 := []byte("commitment-1")
	commitment2 := []byte("commitment-2")

	// Mark some nonces as used
	err := tracker.MarkUsed("key1", commitment1)
	require.NoError(t, err)
	err = tracker.MarkUsed("key1", commitment2)
	require.NoError(t, err)

	// Verify they're marked as used
	used, _ := tracker.IsUsed("key1", commitment1)
	assert.True(t, used)
	used, _ = tracker.IsUsed("key1", commitment2)
	assert.True(t, used)

	// Delete all nonces for key1
	err = tracker.DeleteKeyNonces("key1")
	assert.NoError(t, err)

	// Verify they're no longer marked as used
	used, _ = tracker.IsUsed("key1", commitment1)
	assert.False(t, used)
	used, _ = tracker.IsUsed("key1", commitment2)
	assert.False(t, used)
}

func TestNonceTracker_DeleteKeyNonces_NoNonces(t *testing.T) {
	storage := newMockStorageBackend()
	tracker := NewNonceTracker(storage)

	// Should not error even when no nonces exist
	err := tracker.DeleteKeyNonces("nonexistent-key")
	assert.NoError(t, err)
}

func TestSigningNonces_Zeroize(t *testing.T) {
	nonces := &SigningNonces{
		HidingNonce:  []byte{1, 2, 3, 4, 5},
		BindingNonce: []byte{6, 7, 8, 9, 10},
	}

	nonces.Zeroize()

	// All bytes should be zero
	for i, b := range nonces.HidingNonce {
		assert.Equal(t, byte(0), b, "HidingNonce[%d] should be zero", i)
	}
	for i, b := range nonces.BindingNonce {
		assert.Equal(t, byte(0), b, "BindingNonce[%d] should be zero", i)
	}
}

func TestSigningNonces_Zeroize_Nil(t *testing.T) {
	nonces := &SigningNonces{}
	// Should not panic
	nonces.Zeroize()
}

func TestSigningCommitments_Serialize(t *testing.T) {
	commitments := &SigningCommitments{
		ParticipantID:     1,
		HidingCommitment:  []byte{1, 2, 3, 4},
		BindingCommitment: []byte{5, 6, 7, 8},
	}

	serialized := commitments.Serialize()

	// Should contain participant ID (4 bytes) + hiding + binding
	expectedLen := 4 + len(commitments.HidingCommitment) + len(commitments.BindingCommitment)
	assert.Len(t, serialized, expectedLen)

	// Check participant ID encoding (big endian)
	assert.Equal(t, byte(0), serialized[0])
	assert.Equal(t, byte(0), serialized[1])
	assert.Equal(t, byte(0), serialized[2])
	assert.Equal(t, byte(1), serialized[3])

	// Check commitments are included
	assert.Equal(t, commitments.HidingCommitment, serialized[4:8])
	assert.Equal(t, commitments.BindingCommitment, serialized[8:12])
}

func TestSigningCommitments_Serialize_LargeParticipantID(t *testing.T) {
	commitments := &SigningCommitments{
		ParticipantID:     0x12345678,
		HidingCommitment:  []byte{1},
		BindingCommitment: []byte{2},
	}

	serialized := commitments.Serialize()

	// Check big-endian encoding of participant ID
	assert.Equal(t, byte(0x12), serialized[0])
	assert.Equal(t, byte(0x34), serialized[1])
	assert.Equal(t, byte(0x56), serialized[2])
	assert.Equal(t, byte(0x78), serialized[3])
}

func TestCommitment_Serialize(t *testing.T) {
	commitment := &Commitment{
		ParticipantID: 5,
		Commitments: &SigningCommitments{
			ParticipantID:     5,
			HidingCommitment:  []byte{10, 20},
			BindingCommitment: []byte{30, 40},
		},
	}

	serialized := commitment.Serialize()

	// Should delegate to SigningCommitments.Serialize
	expected := commitment.Commitments.Serialize()
	assert.Equal(t, expected, serialized)
}

func TestNoncePackage(t *testing.T) {
	pkg := &NoncePackage{
		ParticipantID: 1,
		SessionID:     "test-session",
		Nonces: &SigningNonces{
			HidingNonce:  []byte{1, 2, 3},
			BindingNonce: []byte{4, 5, 6},
		},
		Commitments: &SigningCommitments{
			ParticipantID:     1,
			HidingCommitment:  []byte{7, 8, 9},
			BindingCommitment: []byte{10, 11, 12},
		},
	}

	assert.Equal(t, uint32(1), pkg.ParticipantID)
	assert.Equal(t, "test-session", pkg.SessionID)
	assert.NotNil(t, pkg.Nonces)
	assert.NotNil(t, pkg.Commitments)
}

func TestHashCommitment(t *testing.T) {
	commitment := []byte("test-commitment")

	hash1 := hashCommitment(commitment)
	hash2 := hashCommitment(commitment)

	// Same input should produce same hash
	assert.Equal(t, hash1, hash2)
	assert.Len(t, hash1, 32) // SHA-256 produces 32 bytes

	// Different input should produce different hash
	differentCommitment := []byte("different-commitment")
	hash3 := hashCommitment(differentCommitment)
	assert.NotEqual(t, hash1, hash3)
}

func TestNoncePath(t *testing.T) {
	commitmentHash := []byte{0x12, 0x34, 0x56, 0x78}
	path := noncePath("my-key", commitmentHash)

	assert.Contains(t, path, "frost/nonces")
	assert.Contains(t, path, "my-key")
	assert.Contains(t, path, "12345678")
}

// failingStorageBackend is a mock that fails on specific operations
type failingStorageBackend struct {
	*mockStorageBackend
	failOn string
}

func newFailingStorageBackend(failOn string) *failingStorageBackend {
	return &failingStorageBackend{
		mockStorageBackend: newMockStorageBackend(),
		failOn:             failOn,
	}
}

func (f *failingStorageBackend) Exists(key string) (bool, error) {
	if f.failOn == "exists" {
		return false, errors.New("storage error")
	}
	return f.mockStorageBackend.Exists(key)
}

func (f *failingStorageBackend) Put(key string, value []byte, opts *pkgstorage.Options) error {
	if f.failOn == "put" {
		return errors.New("storage error")
	}
	return f.mockStorageBackend.Put(key, value, nil)
}

func (f *failingStorageBackend) List(prefix string) ([]string, error) {
	if f.failOn == "list" {
		return nil, errors.New("storage error")
	}
	return f.mockStorageBackend.List(prefix)
}

func TestNonceTracker_MarkUsed_ExistsError(t *testing.T) {
	storage := newFailingStorageBackend("exists")
	tracker := NewNonceTracker(storage)

	err := tracker.MarkUsed("key1", []byte("commitment"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check nonce status")
}

func TestNonceTracker_MarkUsed_PutError(t *testing.T) {
	storage := newFailingStorageBackend("put")
	tracker := NewNonceTracker(storage)

	err := tracker.MarkUsed("key1", []byte("commitment"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mark nonce as used")
}

func TestNonceTracker_MarkUsedWithDetails_ExistsError(t *testing.T) {
	storage := newFailingStorageBackend("exists")
	tracker := NewNonceTracker(storage)

	err := tracker.MarkUsedWithDetails("key1", 1, "session", []byte("commitment"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to check nonce status")
}

func TestNonceTracker_MarkUsedWithDetails_PutError(t *testing.T) {
	storage := newFailingStorageBackend("put")
	tracker := NewNonceTracker(storage)

	err := tracker.MarkUsedWithDetails("key1", 1, "session", []byte("commitment"))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to mark nonce as used")
}

func TestNonceTracker_DeleteKeyNonces_ListError(t *testing.T) {
	storage := newFailingStorageBackend("list")
	tracker := NewNonceTracker(storage)

	err := tracker.DeleteKeyNonces("key1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to list nonces")
}
