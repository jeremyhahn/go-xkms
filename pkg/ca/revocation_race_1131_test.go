// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package ca

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// go-xkms#1131: recordRevocation used to insert into the in-memory map
// before persisting, and its duplicate check read only that map. A failed
// store write still left the serial enforced on this node with no way to
// retry (the retry hit the in-memory entry and returned ErrAlreadyRevoked
// without ever persisting), and two nodes racing to revoke the same serial
// could each write a record, the second silently overwriting the first's
// reason and time. These tests drive recordRevocation directly, using the
// revocation_cluster_test.go harness (revocationFaultStore, newClusterPeer,
// issueTestCert).

// TestRecordRevocation_WriteFailure_LeavesMapUnchanged_RetrySucceeds proves a
// failed persist leaves the in-memory map untouched, so a retry after the
// store recovers is not rejected as a duplicate and actually persists.
func TestRecordRevocation_WriteFailure_LeavesMapUnchanged_RetrySucceeds(t *testing.T) {
	ctx := context.Background()
	ca := setupTestCA(t)
	cert := issueTestCert(t, ca, "write-fault-1131.example.com")
	serial := cert.SerialNumber

	faults := &revocationFaultStore{
		Backend:         ca.revocationStore,
		failPutIfAbsent: failKeysWithPrefix(revocationKeyPrefix),
	}
	ca.revocationStore = faults

	err := ca.recordRevocation(ctx, serial, ReasonKeyCompromise, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.ErrorIs(t, err, errRevocationFault)

	ca.revocationsMutex.RLock()
	_, cached := ca.revocations[serial.Text(10)]
	ca.revocationsMutex.RUnlock()
	assert.False(t, cached, "a failed persist must not populate the in-memory map")

	_, err = faults.Backend.Get(ctx, revocationKey(serial)+".json")
	assert.Error(t, err, "a failed persist must not have written a record either")

	// The store recovers; a retry must succeed rather than being rejected as
	// an already-revoked duplicate of the failed attempt.
	faults.failPutIfAbsent = nil

	err = ca.recordRevocation(ctx, serial, ReasonKeyCompromise, false)
	require.NoError(t, err)

	ca.revocationsMutex.RLock()
	info, cached := ca.revocations[serial.Text(10)]
	ca.revocationsMutex.RUnlock()
	require.True(t, cached, "a successful retry must populate the in-memory map")
	assert.Equal(t, ReasonKeyCompromise, info.Reason)

	data, err := ca.getRevocationBlob(ctx, serial)
	require.NoError(t, err)
	decoded, err := decodeRevocationRecord(revocationKey(serial)+".json", data)
	require.NoError(t, err)
	assert.Equal(t, ReasonKeyCompromise, decoded.Reason)
}

// TestRecordRevocation_TwoNodes_LoserGetsAlreadyRevoked_WinnerRecordPreserved
// proves the cross-node duplicate case: node B's revocation of a serial node
// A already revoked returns ErrAlreadyRevoked, and the persisted record --
// which both nodes read through -- still carries A's reason and time, never
// B's.
func TestRecordRevocation_TwoNodes_LoserGetsAlreadyRevoked_WinnerRecordPreserved(t *testing.T) {
	ctx := context.Background()
	nodeA := setupTestCA(t)
	nodeB := newClusterPeer(t, nodeA)

	cert := issueTestCert(t, nodeA, "two-node-race-1131.example.com")

	require.NoError(t, nodeA.RevokeCert(ctx, cert, RevokeOptions{Reason: ReasonKeyCompromise}))

	nodeA.revocationsMutex.RLock()
	winnerRecord, ok := nodeA.revocations[cert.SerialNumber.Text(10)]
	nodeA.revocationsMutex.RUnlock()
	require.True(t, ok)
	winnerTime := winnerRecord.RevocationTime

	err := nodeB.RevokeCert(ctx, cert, RevokeOptions{Reason: ReasonSuperseded})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrAlreadyRevoked)

	// The record every node reads through the shared store must still be
	// A's: reason KeyCompromise at A's time, not B's attempted Superseded.
	stored, err := nodeB.lookupRevocation(ctx, cert.SerialNumber)
	require.NoError(t, err)
	require.NotNil(t, stored)
	assert.Equal(t, ReasonKeyCompromise, stored.Reason)
	assert.True(t, stored.RevocationTime.Equal(winnerTime))
}

// TestRecordRevocation_DuplicateCheckStoreError_FailsClosed proves a store
// read fault during the duplicate check aborts the revocation attempt --
// never treated as "not yet revoked" -- and that nothing is written as a
// result.
func TestRecordRevocation_DuplicateCheckStoreError_FailsClosed(t *testing.T) {
	ctx := context.Background()
	ca := setupTestCA(t)
	cert := issueTestCert(t, ca, "duplicate-check-fault-1131.example.com")
	serial := cert.SerialNumber

	faults := &revocationFaultStore{
		Backend: ca.revocationStore,
		failGet: failKeysWithPrefix(revocationKeyPrefix),
	}
	ca.revocationStore = faults

	err := ca.recordRevocation(ctx, serial, ReasonKeyCompromise, false)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrStorageError)
	assert.ErrorIs(t, err, errRevocationFault)

	ca.revocationsMutex.RLock()
	_, cached := ca.revocations[serial.Text(10)]
	ca.revocationsMutex.RUnlock()
	assert.False(t, cached, "a failed duplicate check must not populate the in-memory map")

	_, err = faults.Backend.Get(ctx, revocationKey(serial)+".json")
	assert.Error(t, err, "a failed duplicate check must never reach the write")
}
