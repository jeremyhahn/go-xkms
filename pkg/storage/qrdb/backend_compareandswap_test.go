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

package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// #125: the transaction must never carry a read in a branch
// ---------------------------------------------------------------------------
//
// go-qrdb's transaction service rejects any op other than Put/Delete in a
// success or failure branch ("transaction branches support only Put and
// Delete") because a branch is applied atomically as a single Raft write with
// no per-op read-result channel. CompareAndSwap used to put an OpGet in
// FailureOps so a failed swap could report the current value; that made every
// CompareAndSwap fail once the request actually reached the service. These
// tests pin the corrected shape directly, and behaviourally.

func TestBackend_CompareAndSwap_RequestCarriesNoFailureOps(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, _, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))
	require.NoError(t, err)

	require.NotNil(t, client.lastReq)
	assert.Empty(t, client.lastReq.FailureOps,
		"a transaction branch may only contain Put/Delete; FailureOps must carry no read op (#125)")

	require.Len(t, client.lastReq.SuccessOps, 1)
	op := client.lastReq.SuccessOps[0]
	assert.Equal(t, transport.OpPut, op.Type)
	assert.Equal(t, "key", string(op.Key))
	assert.Equal(t, []byte("new"), op.Value)
}

// The same shape must hold on the failure path too -- FailureOps is empty
// whether or not the compare actually holds, because the field is never
// populated at all rather than conditionally populated.
func TestBackend_CompareAndSwap_RequestCarriesNoFailureOps_OnRefusal(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = false
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	_, _, err := backend.CompareAndSwap(ctx, "key", []byte("stale"), []byte("new"))
	require.NoError(t, err)

	require.NotNil(t, client.lastReq)
	assert.Empty(t, client.lastReq.FailureOps)
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

func TestBackend_CompareAndSwap_ValueMatches_Succeeds(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.store["key"] = []byte("old")
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Nil(t, current, "current is only meaningful on refusal")

	stored, getErr := client.Get(ctx, "key")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("new"), stored)

	// Precondition: a value compare, not PutIfAbsent's version compare.
	require.Len(t, client.lastReq.Compares, 1)
	cmp := client.lastReq.Compares[0]
	assert.Equal(t, "key", string(cmp.Key))
	assert.Equal(t, transport.CompareValue, cmp.Target)
	assert.Equal(t, transport.CompareEqual, cmp.Result)
	assert.Equal(t, []byte("old"), cmp.Value)
}

// expected == nil requires the key to be absent (version 0), the same
// precondition PutIfAbsent uses -- CompareAndSwap can also create.
func TestBackend_CompareAndSwap_ExpectedNil_UsesVersionPrecondition(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, _, err := backend.CompareAndSwap(ctx, "key", nil, []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped)

	require.Len(t, client.lastReq.Compares, 1)
	cmp := client.lastReq.Compares[0]
	assert.Equal(t, transport.CompareVersion, cmp.Target)
	assert.Equal(t, transport.CompareEqual, cmp.Result)
	assert.Equal(t, int64(0), cmp.Version)
}

// ---------------------------------------------------------------------------
// Refusal: stale expected value -- the behavioural contract
// ---------------------------------------------------------------------------

// A stale expected value is a refusal (swapped=false, err=nil), not an error
// -- the same convention CompareAndDelete and PutIfAbsent already use in this
// package. The stored value must be exactly what it was before the call, and
// current must report it so a read-modify-write caller can retry.
func TestBackend_CompareAndSwap_StaleExpectedValue_LeavesStoredValueIntact(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.store["key"] = []byte("orig")
	client.succeeded = false // the cluster's compare did not hold
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("stale-guess"), []byte("new"))

	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, []byte("orig"), current,
		"current must report the value actually present, fetched by a follow-up Get")

	stored, getErr := client.Get(ctx, "key")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("orig"), stored, "a refused swap must not mutate the stored value")
}

// When the key was never written, a refusal reports current=nil rather than
// surfacing the follow-up Get's KeyNotFoundError -- absence is the current
// value, not a failure to determine it.
func TestBackend_CompareAndSwap_RefusalOnAbsentKey_CurrentIsNil(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = false
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("anything"), []byte("new"))

	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

func TestBackend_CompareAndSwap_ClientLacksTransactionSupport(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient() // does not implement transport.TransactionClient
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.Error(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-swap", backendErr.Op)
	assert.ErrorIs(t, err, ErrTransactionsUnsupported)
}

func TestBackend_CompareAndSwap_TransactionError(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.txErr = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.Error(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-swap", backendErr.Op)
	assert.Equal(t, "key", backendErr.Key)
	assert.ErrorIs(t, err, client.txErr)
}

// A failure to fetch the current value after a refused swap is a real error
// -- it must surface as a typed *BackendError, the same wrapping every other
// failure in this file uses, rather than being swallowed into a plain
// refusal.
func TestBackend_CompareAndSwap_FollowUpGetError(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = false
	client.getErr = errors.New("transport: connection reset")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.Error(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-swap", backendErr.Op)
	assert.ErrorIs(t, err, client.getErr)
}
