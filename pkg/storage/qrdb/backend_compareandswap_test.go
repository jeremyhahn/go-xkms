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

	// TWO preconditions: the key must exist AND its value must equal expected
	// -- the same shape CompareAndDelete uses, and for the same reason (#186).
	require.Len(t, client.lastReq.Compares, 2)
	existence := client.lastReq.Compares[0]
	assert.Equal(t, "key", string(existence.Key))
	assert.Equal(t, transport.CompareVersion, existence.Target)
	assert.Equal(t, transport.CompareGreater, existence.Result)
	assert.Equal(t, int64(0), existence.Version)

	value := client.lastReq.Compares[1]
	assert.Equal(t, "key", string(value.Key))
	assert.Equal(t, transport.CompareValue, value.Target)
	assert.Equal(t, transport.CompareEqual, value.Result)
	assert.Equal(t, []byte("old"), value.Value)
}

// expected == nil is no longer a "require absent" wildcard (#186): a swap does
// not create. The transaction still carries the existence precondition -- now
// paired with a value compare against nil/empty rather than a version==0
// compare -- so the request can only succeed against a key that both exists
// and holds an empty value.
func TestBackend_CompareAndSwap_ExpectedNil_RequiresExistenceAndEmptyValue(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, _, err := backend.CompareAndSwap(ctx, "key", nil, []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped, "the mock client answers whatever client.succeeded says; this test pins the REQUEST SHAPE, not the mock's evaluation")

	require.Len(t, client.lastReq.Compares, 2)
	existence := client.lastReq.Compares[0]
	assert.Equal(t, transport.CompareVersion, existence.Target)
	assert.Equal(t, transport.CompareGreater, existence.Result)
	assert.Equal(t, int64(0), existence.Version)

	value := client.lastReq.Compares[1]
	assert.Equal(t, transport.CompareValue, value.Target)
	assert.Equal(t, transport.CompareEqual, value.Result)
	assert.Nil(t, value.Value)
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

// ---------------------------------------------------------------------------
// GuardedKVClient dispatch (#125)
// ---------------------------------------------------------------------------
//
// Everything above this section predates #125's fix and still holds: a client
// offering neither capability refuses, and a TransactionClient-only client
// (txClient) is served through the transaction. What follows pins the part
// that changed -- CompareAndSwap must prefer transport.GuardedKVClient over
// the transaction, the same ordering backend_compareanddelete_test.go pins
// for CompareAndDelete.

// guardedSwapClient is a mockKVClient that additionally implements
// transport.GuardedKVClient, recording the call rather than implementing the
// semantics -- the point of these tests is the dispatch, not the guard.
type guardedSwapClient struct {
	*mockKVClient

	calls       int
	gotKey      string
	gotExpected []byte
	gotNext     []byte
	swapped     bool
	err         error
}

var _ transport.GuardedKVClient = (*guardedSwapClient)(nil)

func newGuardedSwapClient() *guardedSwapClient {
	return &guardedSwapClient{mockKVClient: newMockKVClient()}
}

func (c *guardedSwapClient) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	panic("PutIfAbsent must not be called by CompareAndSwap")
}

func (c *guardedSwapClient) CompareAndDelete(_ context.Context, _ string, _ []byte) (bool, error) {
	panic("CompareAndDelete must not be called by CompareAndSwap")
}

func (c *guardedSwapClient) CompareAndSwap(_ context.Context, key string, expected, next []byte) (bool, error) {
	c.calls++
	c.gotKey = key
	c.gotExpected = expected
	c.gotNext = next
	return c.swapped, c.err
}

// guardedSwapTxClient carries both capabilities; its ExecuteTransaction fails
// the test rather than returning a plausible answer, so a dispatch that fell
// through to the transaction cannot pass by coincidence.
type guardedSwapTxClient struct {
	*guardedSwapClient
	t *testing.T
}

var (
	_ transport.GuardedKVClient   = (*guardedSwapTxClient)(nil)
	_ transport.TransactionClient = (*guardedSwapTxClient)(nil)
)

func (c *guardedSwapTxClient) ExecuteTransaction(_ context.Context, _ *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.t.Helper()
	c.t.Fatal("CompareAndSwap must prefer the GuardedKVClient capability over a transaction")
	return nil, nil
}

func TestBackend_CompareAndSwap_UsesGuardedClient(t *testing.T) {
	ctx := context.Background()
	client := newGuardedSwapClient()
	client.swapped = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped, "the client's answer must be returned, not recomputed")
	assert.Nil(t, current, "current is only meaningful on refusal")
	assert.Equal(t, 1, client.calls)
	assert.Equal(t, "key", client.gotKey)
	assert.Equal(t, []byte("old"), client.gotExpected)
	assert.Equal(t, []byte("new"), client.gotNext)
}

// A refusal from the guarded path is not an error, and current is fetched by
// a follow-up Get: transport.GuardedKVClient.CompareAndSwap reports only
// swapped/err, with no current value, so this is the one place that follow-up
// read is unconditional.
func TestBackend_CompareAndSwap_GuardedClientRefusal_FetchesCurrent(t *testing.T) {
	ctx := context.Background()
	client := newGuardedSwapClient()
	client.swapped = false
	require.NoError(t, client.Put(context.Background(), "key", []byte("orig")))
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("stale-guess"), []byte("new"))

	require.NoError(t, err)
	assert.False(t, swapped)
	assert.Equal(t, []byte("orig"), current)
	assert.Equal(t, 1, client.calls)

	stored, getErr := client.Get(ctx, "key")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("orig"), stored, "a refused swap must not mutate the stored value")
}

func TestBackend_CompareAndSwap_GuardedClientError(t *testing.T) {
	ctx := context.Background()
	client := newGuardedSwapClient()
	client.err = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.Error(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-swap", backendErr.Op)
	assert.ErrorIs(t, err, client.err)
}

// The ordering is load-bearing, not cosmetic: the embedded transport
// implements GuardedKVClient but wires no transaction service (#125), so a
// dispatch that tried the transaction first would fail on exactly the
// transports that can serve the verb.
func TestBackend_CompareAndSwap_PrefersGuardedOverTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedSwapClient()
	guarded.swapped = true
	client := &guardedSwapTxClient{guardedSwapClient: guarded, t: t}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, _, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped)
	assert.Equal(t, 1, guarded.calls)
}

// guardedSwapFallbackClient carries both capabilities and lets its
// transaction half actually run -- the fixture for the rule that a
// CAPABILITY refusal from the guarded path, and only that, falls through.
type guardedSwapFallbackClient struct {
	*guardedSwapClient

	txCalls   int
	lastReq   *transport.TransactionRequest
	succeeded bool
}

var (
	_ transport.GuardedKVClient   = (*guardedSwapFallbackClient)(nil)
	_ transport.TransactionClient = (*guardedSwapFallbackClient)(nil)
)

func (c *guardedSwapFallbackClient) ExecuteTransaction(_ context.Context, req *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.txCalls++
	c.lastReq = req
	return &transport.TransactionResponse{Succeeded: c.succeeded}, nil
}

func TestBackend_CompareAndSwap_CapabilityRefusalFallsThroughToTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedSwapClient()
	guarded.err = &transport.CapabilityUnsupportedError{Message: "statemachine: unknown opcode: 67"}
	client := &guardedSwapFallbackClient{guardedSwapClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, _, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.NoError(t, err)
	assert.True(t, swapped, "the transaction's answer must be returned")
	assert.Equal(t, 1, guarded.calls, "the guarded path is still tried first")
	assert.Equal(t, 1, client.txCalls, "and the capability refusal falls through to it")
}

// Every OTHER failure must stop. A capability refusal is the one error that
// means the operation was not performed; anything else may have reached the
// state machine, and re-issuing a write after one that might have applied is
// how a guarded verb quietly becomes an unguarded one.
func TestBackend_CompareAndSwap_NonCapabilityErrorDoesNotFallThrough(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedSwapClient()
	guarded.err = errors.New("connection reset mid-apply")
	client := &guardedSwapFallbackClient{guardedSwapClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	swapped, current, err := backend.CompareAndSwap(ctx, "key", []byte("old"), []byte("new"))

	require.Error(t, err)
	assert.False(t, swapped)
	assert.Nil(t, current)
	assert.Equal(t, 0, client.txCalls,
		"a write that may already have applied must not be retried by another route")

	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-swap", backendErr.Op)
	assert.ErrorIs(t, err, guarded.err, "the original cause must survive")
}
