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
// Scan: early stop when fn returns an error
// ---------------------------------------------------------------------------
//
// TestBackend_Scan_Success and TestBackend_Scan_Empty only ever pass a fn
// that returns nil, so the "stop iteration early" branch in Scan (the one
// that propagates fn's error straight back to the caller, unwrapped by
// BackendError) was never exercised.

func TestBackend_Scan_FnErrorStopsIterationAndPropagates(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient()
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	require.NoError(t, client.Put(ctx, "prefix/key1", []byte("value1")))
	require.NoError(t, client.Put(ctx, "prefix/key2", []byte("value2")))

	sentinel := errors.New("stop here")
	visited := 0
	err := backend.Scan(ctx, "prefix/", func(_ string, _ []byte) error {
		visited++
		return sentinel
	})

	require.Error(t, err)
	assert.Same(t, sentinel, err, "Scan must return fn's error unwrapped, not a *BackendError")
	assert.Equal(t, 1, visited, "Scan must stop calling fn after the first error")
}

// ---------------------------------------------------------------------------
// PutIfAbsent
// ---------------------------------------------------------------------------

// txClient is a mockKVClient that additionally implements
// transport.TransactionClient so PutIfAbsent's CAS path can be exercised.
type txClient struct {
	*mockKVClient

	// txErr, when set, is returned by ExecuteTransaction instead of
	// performing the transaction.
	txErr error

	// succeeded controls the TransactionResponse.Succeeded field returned
	// on a non-error execution.
	succeeded bool

	// lastReq captures the most recent request for assertions.
	lastReq *transport.TransactionRequest
}

var _ transport.TransactionClient = (*txClient)(nil)

func newTxClient() *txClient {
	return &txClient{mockKVClient: newMockKVClient()}
}

func (c *txClient) ExecuteTransaction(_ context.Context, req *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.lastReq = req
	if c.txErr != nil {
		return nil, c.txErr
	}
	if c.succeeded && len(req.SuccessOps) == 1 {
		op := req.SuccessOps[0]
		c.store[string(op.Key)] = append([]byte(nil), op.Value...)
	}
	return &transport.TransactionResponse{Succeeded: c.succeeded}, nil
}

func TestBackend_PutIfAbsent_ClientLacksTransactionSupport(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient() // does not implement transport.TransactionClient
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	ok, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.Error(t, err)
	assert.False(t, ok)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "put-if-absent", backendErr.Op)
	assert.ErrorIs(t, err, ErrTransactionsUnsupported)
}

func TestBackend_PutIfAbsent_KeyAbsent_Succeeds(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	ok, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.True(t, ok)

	stored, getErr := client.Get(ctx, "key")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("value"), stored)

	// Verify the compare-and-swap precondition: version 0 (never written).
	require.Len(t, client.lastReq.Compares, 1)
	cmp := client.lastReq.Compares[0]
	assert.Equal(t, "key", string(cmp.Key))
	assert.Equal(t, transport.CompareVersion, cmp.Target)
	assert.Equal(t, transport.CompareEqual, cmp.Result)
	assert.Equal(t, int64(0), cmp.Version)
}

func TestBackend_PutIfAbsent_KeyPresent_ReturnsNotSucceeded(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = false // simulates the CAS precondition failing
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	ok, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.False(t, ok, "PutIfAbsent must report false, not an error, when the key already exists")
}

func TestBackend_PutIfAbsent_TransactionError(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.txErr = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	ok, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.Error(t, err)
	assert.False(t, ok)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "put-if-absent", backendErr.Op)
	assert.Equal(t, "key", backendErr.Key)
	assert.ErrorIs(t, err, client.txErr)
}

func TestErrTransactionsUnsupported_Message(t *testing.T) {
	assert.Equal(t, "qrdb: client does not support compare-and-swap transactions", ErrTransactionsUnsupported.Error())
}

// ---------------------------------------------------------------------------
// PutIfAbsent: GuardedKVClient dispatch (#125)
// ---------------------------------------------------------------------------
//
// The tests above this section predate #125's fix and still hold: a client
// offering neither capability refuses, and a TransactionClient-only client
// (txClient) is served through the transaction. What follows pins the part
// that changed -- PutIfAbsent must prefer transport.GuardedKVClient over the
// transaction, the same ordering backend_compareanddelete_test.go pins for
// CompareAndDelete.

// guardedPutClient is a mockKVClient that additionally implements
// transport.GuardedKVClient, recording the call rather than implementing the
// semantics -- the point of these tests is the dispatch, not the guard.
type guardedPutClient struct {
	*mockKVClient

	calls  int
	gotKey string
	gotVal []byte
	stored bool
	err    error
}

var _ transport.GuardedKVClient = (*guardedPutClient)(nil)

func newGuardedPutClient() *guardedPutClient {
	return &guardedPutClient{mockKVClient: newMockKVClient()}
}

func (c *guardedPutClient) PutIfAbsent(_ context.Context, key string, value []byte) (bool, error) {
	c.calls++
	c.gotKey = key
	c.gotVal = value
	return c.stored, c.err
}

func (c *guardedPutClient) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, error) {
	panic("CompareAndSwap must not be called by PutIfAbsent")
}

func (c *guardedPutClient) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	panic("CompareAndDelete must not be called by PutIfAbsent")
}

// guardedPutTxClient carries both capabilities; its ExecuteTransaction fails
// the test rather than returning a plausible answer, so a dispatch that fell
// through to the transaction cannot pass by coincidence.
type guardedPutTxClient struct {
	*guardedPutClient
	t *testing.T
}

var (
	_ transport.GuardedKVClient   = (*guardedPutTxClient)(nil)
	_ transport.TransactionClient = (*guardedPutTxClient)(nil)
)

func (c *guardedPutTxClient) ExecuteTransaction(_ context.Context, _ *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.t.Helper()
	c.t.Fatal("PutIfAbsent must prefer the GuardedKVClient capability over a transaction")
	return nil, nil
}

func TestBackend_PutIfAbsent_UsesGuardedClient(t *testing.T) {
	ctx := context.Background()
	client := newGuardedPutClient()
	client.stored = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.True(t, stored, "the client's answer must be returned, not recomputed")
	assert.Equal(t, 1, client.calls)
	assert.Equal(t, "key", client.gotKey)
	assert.Equal(t, []byte("value"), client.gotVal)
}

func TestBackend_PutIfAbsent_GuardedClientRefusal(t *testing.T) {
	ctx := context.Background()
	client := newGuardedPutClient()
	client.stored = false
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.False(t, stored)
	assert.Equal(t, 1, client.calls)
}

func TestBackend_PutIfAbsent_GuardedClientError(t *testing.T) {
	ctx := context.Background()
	client := newGuardedPutClient()
	client.err = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.Error(t, err)
	assert.False(t, stored)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "put-if-absent", backendErr.Op)
	assert.ErrorIs(t, err, client.err)
}

// The ordering is load-bearing, not cosmetic: the embedded transport
// implements GuardedKVClient but wires no transaction service (#125), so a
// dispatch that tried the transaction first would fail on exactly the
// transports that can serve the verb.
func TestBackend_PutIfAbsent_PrefersGuardedOverTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedPutClient()
	guarded.stored = true
	client := &guardedPutTxClient{guardedPutClient: guarded, t: t}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.True(t, stored)
	assert.Equal(t, 1, guarded.calls)
}

// guardedPutFallbackClient carries both capabilities and lets its transaction
// half actually run -- the fixture for the rule that a CAPABILITY refusal from
// the guarded path, and only that, falls through.
type guardedPutFallbackClient struct {
	*guardedPutClient

	txCalls   int
	lastReq   *transport.TransactionRequest
	succeeded bool
}

var (
	_ transport.GuardedKVClient   = (*guardedPutFallbackClient)(nil)
	_ transport.TransactionClient = (*guardedPutFallbackClient)(nil)
)

func (c *guardedPutFallbackClient) ExecuteTransaction(_ context.Context, req *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.txCalls++
	c.lastReq = req
	return &transport.TransactionResponse{Succeeded: c.succeeded}, nil
}

func TestBackend_PutIfAbsent_CapabilityRefusalFallsThroughToTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedPutClient()
	guarded.err = &transport.CapabilityUnsupportedError{Message: "statemachine: unknown opcode: 65"}
	client := &guardedPutFallbackClient{guardedPutClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.NoError(t, err)
	assert.True(t, stored, "the transaction's answer must be returned")
	assert.Equal(t, 1, guarded.calls, "the guarded path is still tried first")
	assert.Equal(t, 1, client.txCalls, "and the capability refusal falls through to it")
}

// Every OTHER failure must stop. A capability refusal is the one error that
// means the operation was not performed; anything else may have reached the
// state machine, and re-issuing a write after one that might have applied is
// how a guarded verb quietly becomes an unguarded one.
func TestBackend_PutIfAbsent_NonCapabilityErrorDoesNotFallThrough(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedPutClient()
	guarded.err = errors.New("connection reset mid-apply")
	client := &guardedPutFallbackClient{guardedPutClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	stored, err := backend.PutIfAbsent(ctx, "key", []byte("value"))

	require.Error(t, err)
	assert.False(t, stored)
	assert.Equal(t, 0, client.txCalls,
		"a write that may already have applied must not be retried by another route")

	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "put-if-absent", backendErr.Op)
	assert.ErrorIs(t, err, guarded.err, "the original cause must survive")
}
