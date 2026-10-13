//go:build frost

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package frost

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newTestNonceTracker(t *testing.T) *NonceTracker {
	t.Helper()
	tracker, err := NewNonceTracker(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	return tracker
}

func requireNonceReuse(t *testing.T, err error, keyID string) {
	t.Helper()
	require.ErrorIs(t, err, ErrNonceAlreadyUsed)
	var reuse *NonceReuseError
	require.ErrorAs(t, err, &reuse)
	assert.Equal(t, keyID, reuse.KeyID)
}

func TestNewNonceTracker(t *testing.T) {
	tracker, err := NewNonceTracker(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	assert.NotNil(t, tracker.nonces)
}

func TestNewNonceTracker_NilFactory(t *testing.T) {
	tracker, err := NewNonceTracker(nil)
	assert.Nil(t, tracker)
	assert.ErrorIs(t, err, ErrNilDAOFactory)
}

func TestNonceName(t *testing.T) {
	name := nonceName("key-a", []byte("commitment"))
	assert.Equal(t, "key-a/", name[:len("key-a/")])
	assert.Len(t, name, len("key-a/")+64, "the commitment is named by its hex SHA-256")
	assert.Equal(t, name, nonceName("key-a", []byte("commitment")))
}

func TestNonceName_Distinct(t *testing.T) {
	base := nonceName("key-a", []byte("commitment"))
	assert.NotEqual(t, base, nonceName("key-a", []byte("commitment2")))
	assert.NotEqual(t, base, nonceName("key-b", []byte("commitment")))
}

func TestNonceTracker_Claim(t *testing.T) {
	tracker := newTestNonceTracker(t)
	ctx := context.Background()
	commitment := []byte("commitment")

	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "session-1", commitment))

	stored, err := tracker.nonces.GetByNaturalKey(ctx, nonceName("key-a", commitment))
	require.NoError(t, err)
	assert.Equal(t, "key-a", stored.KeyID)
	assert.Equal(t, uint32(1), stored.ParticipantID)
	assert.Equal(t, "session-1", stored.SessionID)
}

func TestNonceTracker_Claim_Reuse(t *testing.T) {
	tracker := newTestNonceTracker(t)
	ctx := context.Background()
	commitment := []byte("commitment")
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "session-1", commitment))

	err := tracker.Claim(ctx, "key-a", 2, "session-2", commitment)
	requireNonceReuse(t, err, "key-a")
	var reuse *NonceReuseError
	require.ErrorAs(t, err, &reuse)
	assert.Equal(t, uint32(2), reuse.ParticipantID)
	assert.Equal(t, "session-2", reuse.SessionID)
}

func TestNonceTracker_Claim_DistinctCommitmentsAndKeys(t *testing.T) {
	tracker := newTestNonceTracker(t)
	ctx := context.Background()

	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")))
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-2")))
	require.NoError(t, tracker.Claim(ctx, "key-b", 1, "s", []byte("commitment-1")))
}

func TestNonceTracker_Claim_StoreFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	tracker, err := NewNonceTracker(daos)
	require.NoError(t, err)
	kv.failOn(failPut, nonceEntityType)

	err = tracker.Claim(context.Background(), "key-a", 1, "s", []byte("commitment"))
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "claim nonce", storeErr.Op)
	assert.ErrorIs(t, err, errInjected)
	assert.NotErrorIs(t, err, ErrNonceAlreadyUsed, "an unknown outcome must not read as reuse")
}

// TestNonceTracker_Claim_ConcurrentDoubleClaim races many signers, through
// separate trackers over one real in-memory go-qrdb store, to claim the same
// nonce. Exactly one claim may win; every other must be refused as reuse.
func TestNonceTracker_Claim_ConcurrentDoubleClaim(t *testing.T) {
	const claimers = 32
	daos := testutil.NewMemoryDAOFactory()
	trackers := make([]*NonceTracker, 2)
	for i := range trackers {
		tracker, err := NewNonceTracker(daos)
		require.NoError(t, err)
		trackers[i] = tracker
	}
	commitment := []byte("contended-commitment")

	start := make(chan struct{})
	results := make(chan error, claimers)
	var wg sync.WaitGroup
	for i := range claimers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			results <- trackers[i%len(trackers)].Claim(context.Background(), "key-a", uint32(i+1), "session", commitment)
		}()
	}
	close(start)
	wg.Wait()
	close(results)

	wins := 0
	for err := range results {
		if err == nil {
			wins++
			continue
		}
		requireNonceReuse(t, err, "key-a")
	}
	assert.Equal(t, 1, wins, "exactly one concurrent claim of a nonce may succeed")
}

func TestNonceTracker_DeleteKeyNonces(t *testing.T) {
	tracker := newTestNonceTracker(t)
	ctx := context.Background()
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")))
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-2")))
	require.NoError(t, tracker.Claim(ctx, "key-b", 1, "s", []byte("commitment-1")))

	require.NoError(t, tracker.DeleteKeyNonces(ctx, "key-a"))

	// key-a's nonces are gone, so they can be claimed again...
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")))
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-2")))
	// ...while key-b's are untouched.
	requireNonceReuse(t, tracker.Claim(ctx, "key-b", 1, "s", []byte("commitment-1")), "key-b")
}

func TestNonceTracker_DeleteKeyNonces_NoNonces(t *testing.T) {
	tracker := newTestNonceTracker(t)

	assert.NoError(t, tracker.DeleteKeyNonces(context.Background(), "nonexistent-key"))
}

func TestNonceTracker_DeleteKeyNonces_ListFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	tracker, err := NewNonceTracker(daos)
	require.NoError(t, err)
	require.NoError(t, tracker.Claim(context.Background(), "key-a", 1, "s", []byte("commitment")))
	kv.failOn(failScan, nonceEntityType)

	err = tracker.DeleteKeyNonces(context.Background(), "key-a")
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "list nonces", storeErr.Op)
	assert.ErrorIs(t, err, errInjected)
}

func TestNonceTracker_DeleteKeyNonces_DeleteFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	tracker, err := NewNonceTracker(daos)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")))
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-2")))
	kv.failOn(failDelete, nonceEntityType)

	err = tracker.DeleteKeyNonces(ctx, "key-a")
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "delete nonce", storeErr.Op)
	assert.ErrorIs(t, err, errInjected)

	// A failed delete leaves the claim in force.
	kv.failOn("", "")
	requireNonceReuse(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")), "key-a")
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

// TestNonceTracker_DeleteKeyNonces_ReportsEveryFailure guards the contract
// that every failed delete is reported: the joined error carries one
// StoreError per nonce.
func TestNonceTracker_DeleteKeyNonces_ReportsEveryFailure(t *testing.T) {
	kv, daos := newFailingDAOs()
	tracker, err := NewNonceTracker(daos)
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-1")))
	require.NoError(t, tracker.Claim(ctx, "key-a", 1, "s", []byte("commitment-2")))
	kv.failOn(failDelete, nonceEntityType)

	err = tracker.DeleteKeyNonces(ctx, "key-a")
	joined, ok := err.(interface{ Unwrap() []error })
	require.True(t, ok, "DeleteKeyNonces must join its failures")
	failed := 0
	for _, e := range joined.Unwrap() {
		var storeErr *StoreError
		if errors.As(e, &storeErr) {
			failed++
		}
	}
	assert.Equal(t, 2, failed)
}
