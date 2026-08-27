// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

// THE SHARED storagetest CONTRACT IS NOT RUN IN THIS PACKAGE, and the reason is
// measured, not assumed: no constructor in factory.go yields a backend that can
// serve the verb. See TestEmbeddedConstructors_CompareAndDeleteUnavailable
// below, which records what they do instead. Running the contract against a
// hand-rolled fake would only be testing the fake, so what is tested here is the
// part this package actually owns — WHICH client capability the operation
// dispatches to, and what it does when neither is present.

// ---------------------------------------------------------------------------
// Fake clients for the dispatch tests
// ---------------------------------------------------------------------------

// guardedClient is a mockKVClient that additionally implements
// transport.GuardedKVClient — the SDK's native guarded-write capability, which
// CompareAndDelete must prefer over a transaction.
//
// It records the arguments rather than implementing the semantics: the point of
// these tests is the dispatch, and a fake that also arbitrated the guard would
// let a broken dispatch look correct because the fake did the right thing on its
// own.
type guardedClient struct {
	*mockKVClient

	calls       int
	gotKey      string
	gotExpected []byte

	// deleted and err are what CompareAndDelete hands back, so the test can
	// pin that the client's answer is returned rather than recomputed.
	deleted bool
	err     error
}

var _ transport.GuardedKVClient = (*guardedClient)(nil)

func newGuardedClient() *guardedClient {
	return &guardedClient{mockKVClient: newMockKVClient()}
}

func (c *guardedClient) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	panic("PutIfAbsent must not be called by CompareAndDelete")
}

func (c *guardedClient) CompareAndSwap(_ context.Context, _ string, _, _ []byte) (bool, error) {
	panic("CompareAndSwap must not be called by CompareAndDelete")
}

func (c *guardedClient) CompareAndDelete(_ context.Context, key string, expected []byte) (bool, error) {
	c.calls++
	c.gotKey = key
	c.gotExpected = expected
	return c.deleted, c.err
}

// guardedTxClient carries BOTH capabilities, which is the case the preference
// ordering exists for. Its ExecuteTransaction fails the test rather than
// returning a plausible answer, so a dispatch that fell through to the
// transaction cannot pass by coincidence.
type guardedTxClient struct {
	*guardedClient
	t *testing.T
}

var (
	_ transport.GuardedKVClient   = (*guardedTxClient)(nil)
	_ transport.TransactionClient = (*guardedTxClient)(nil)
)

func (c *guardedTxClient) ExecuteTransaction(_ context.Context, _ *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.t.Helper()
	c.t.Fatal("CompareAndDelete must prefer the GuardedKVClient capability over a transaction")
	return nil, nil
}

// ---------------------------------------------------------------------------
// (a) GuardedKVClient — the preferred path
// ---------------------------------------------------------------------------

func TestBackend_CompareAndDelete_UsesGuardedClient(t *testing.T) {
	ctx := context.Background()
	client := newGuardedClient()
	client.deleted = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.True(t, deleted, "the client's answer must be returned, not recomputed")
	assert.Equal(t, 1, client.calls)
	assert.Equal(t, "key", client.gotKey)
	assert.Equal(t, []byte("expected"), client.gotExpected)
}

// A refusal from the cluster is a refusal here: deleted=false with a nil error,
// never an error. A backend that turned "the guard did not match" into a failure
// would stall a caller over a deterministic, expected outcome.
func TestBackend_CompareAndDelete_GuardedClientRefusal(t *testing.T) {
	ctx := context.Background()
	client := newGuardedClient()
	client.deleted = false
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.False(t, deleted)
	assert.Equal(t, 1, client.calls)
}

func TestBackend_CompareAndDelete_GuardedClientError(t *testing.T) {
	ctx := context.Background()
	client := newGuardedClient()
	client.err = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.Error(t, err)
	assert.False(t, deleted)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-delete", backendErr.Op)
	assert.Equal(t, "key", backendErr.Key)
	assert.ErrorIs(t, err, client.err)
}

// The ordering is load-bearing, not cosmetic: the embedded transport implements
// GuardedKVClient but wires no transaction service (#125), so a dispatch that
// tried the transaction first would fail on exactly the transports that can
// serve the verb.
func TestBackend_CompareAndDelete_PrefersGuardedOverTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedClient()
	guarded.deleted = true
	client := &guardedTxClient{guardedClient: guarded, t: t}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.True(t, deleted)
	assert.Equal(t, 1, guarded.calls)
}

// ---------------------------------------------------------------------------
// (b) TransactionClient — the fallback path
// ---------------------------------------------------------------------------

// The transaction is the reason a remote transport that carries transactions but
// not the guarded verbs is still linearizable here, so its SHAPE is pinned: a
// value compare (not PutIfAbsent's version compare) with a single Delete as the
// success op. A version compare would release a key whose value had changed,
// which is the defect the verb exists to close.
func TestBackend_CompareAndDelete_FallsBackToTransaction(t *testing.T) {
	ctx := context.Background()
	client := newTxClient() // implements TransactionClient, not GuardedKVClient
	client.succeeded = true
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.True(t, deleted, "resp.Succeeded must be returned as deleted")

	require.NotNil(t, client.lastReq)
	require.Len(t, client.lastReq.Compares, 2, "presence AND value, not value alone")

	presence := client.lastReq.Compares[0]
	assert.Equal(t, "key", string(presence.Key))
	assert.Equal(t, transport.CompareVersion, presence.Target)
	assert.Equal(t, transport.CompareGreater, presence.Result)
	assert.Equal(t, int64(0), presence.Version)

	cmp := client.lastReq.Compares[1]
	assert.Equal(t, "key", string(cmp.Key))
	assert.Equal(t, transport.CompareValue, cmp.Target)
	assert.Equal(t, transport.CompareEqual, cmp.Result)
	assert.Equal(t, []byte("expected"), cmp.Value)

	require.Len(t, client.lastReq.SuccessOps, 1)
	op := client.lastReq.SuccessOps[0]
	assert.Equal(t, transport.OpDelete, op.Type)
	assert.Equal(t, "key", string(op.Key))
}

// The transaction fallback must not delete an absent key when the guard is
// empty. QRDB evaluates a value compare against a nil value for a key that does
// not exist, and bytes.Compare(nil, nil) == 0, so a value-only precondition
// MATCHES an absent key: the Delete would run, remove nothing, and the
// transaction would report Succeeded=true — deleted=true for a key that was
// never there, which the contract forbids.
//
// The version>0 precondition is what excludes it, so the assertion is that the
// request carries it for an empty guard exactly as for a non-empty one. Without
// it, this is a silent false success on any transaction-only transport.
func TestBackend_CompareAndDelete_TransactionRequiresPresenceForAnEmptyGuard(t *testing.T) {
	ctx := context.Background()

	for _, tc := range []struct {
		name     string
		expected []byte
	}{
		{"nil guard", nil},
		{"empty guard", []byte{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := newTxClient()
			client.succeeded = true
			backend := NewBackend(client)
			defer func() { _ = backend.Close() }()

			if _, err := backend.CompareAndDelete(ctx, "key", tc.expected); err != nil {
				t.Fatalf("CompareAndDelete: %v", err)
			}

			require.NotNil(t, client.lastReq)
			require.Len(t, client.lastReq.Compares, 2,
				"an empty guard needs the presence precondition MORE than a non-empty one, not less")

			presence := client.lastReq.Compares[0]
			assert.Equal(t, transport.CompareVersion, presence.Target)
			assert.Equal(t, transport.CompareGreater, presence.Result)
			assert.Equal(t, int64(0), presence.Version,
				"version > 0 is what makes an absent key fail the transaction")
		})
	}
}

// A failed compare is Succeeded=false, which is the refusal the contract asks
// for — not an error.
func TestBackend_CompareAndDelete_TransactionRefusal(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.succeeded = false
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.False(t, deleted)
}

func TestBackend_CompareAndDelete_TransactionError(t *testing.T) {
	ctx := context.Background()
	client := newTxClient()
	client.txErr = errors.New("raft: no quorum")
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.Error(t, err)
	assert.False(t, deleted)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-delete", backendErr.Op)
	assert.Equal(t, "key", backendErr.Key)
	assert.ErrorIs(t, err, client.txErr)
}

// ---------------------------------------------------------------------------
// (c) Neither capability — refuse rather than degrade
// ---------------------------------------------------------------------------

// A client offering neither capability gets an error, NOT a read followed by an
// unguarded delete. That fallback would reintroduce exactly the window the verb
// closes, and a deleted=true from it would be a lie about a guard that never
// ran.
func TestBackend_CompareAndDelete_ClientLacksBothCapabilities(t *testing.T) {
	ctx := context.Background()
	client := newMockKVClient() // plain KVClient: neither guarded nor transactional
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	require.NoError(t, client.Put(ctx, "key", []byte("expected")))

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.Error(t, err)
	assert.False(t, deleted)
	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-delete", backendErr.Op)
	assert.Equal(t, "key", backendErr.Key)
	assert.ErrorIs(t, err, ErrTransactionsUnsupported)

	// The refusal must be total: nothing was deleted on the way out.
	stored, getErr := client.Get(ctx, "key")
	require.NoError(t, getErr)
	assert.Equal(t, []byte("expected"), stored, "an unsupported guard must not delete anything")
}

// ---------------------------------------------------------------------------
// Characterization: the embedded constructors
// ---------------------------------------------------------------------------

// CompareAndDelete IS NOT AVAILABLE FROM ANY CONSTRUCTOR IN factory.go, measured
// 2026-08-27 against go-qrdb v0.13.0-alpha through the constructors themselves:
//
//	memory  ->  transport: unsupported capability: statemachine: unknown opcode: 66
//	file    ->  transport: unsupported capability: statemachine: unknown opcode: 66
//	pebble  ->  transport: unsupported capability: statemachine: unknown opcode: 66
//
// The failure is NOT the missing transaction service that blocks PutIfAbsent and
// CompareAndSwap (#125). Dispatch takes the preferred path exactly as designed —
// the embedded transport does implement transport.GuardedKVClient and does
// delegate to the KV service — and gets one layer further before stopping: the
// FastStateMachine that newEmbedded builds has no handler for the guarded-delete
// opcode. Transport capability and state-machine capability are different
// questions, and go-qrdb's own CapabilityUnsupportedError doc says so; here the
// first is satisfied and the second is not.
//
// This is a characterization test in the same spirit as
// factory_cas_characterization_test.go: it records what happens TODAY, including
// the part that is a defect. When the state machine gains the opcode this test
// is expected to FAIL, and the failure is the point — it forces the note above
// CompareAndDelete to be re-derived from measurement rather than left to drift.
func TestEmbeddedConstructors_CompareAndDeleteUnavailable(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key := "compare-and-delete-characterization"

		require.NoError(t, b.Put(ctx, key, []byte("v1")))

		deleted, err := b.CompareAndDelete(ctx, key, []byte("v1"))
		if err == nil {
			t.Fatalf("%s: CompareAndDelete succeeded (deleted=%v): the embedded state "+
				"machine now serves the guarded delete, so the availability note above "+
				"Backend.CompareAndDelete must be re-derived by measurement", name, deleted)
		}
		assert.False(t, deleted)

		// Identify the cause structurally, by TYPE, not by matching the rendered
		// message: a reworded diagnostic upstream would otherwise fail this test
		// while the behaviour it characterizes was unchanged.
		var backendErr *BackendError
		require.True(t, errors.As(err, &backendErr), "want *BackendError, got %T: %v", err, err)
		assert.Equal(t, "compare-and-delete", backendErr.Op)

		// The guarded path's capability refusal must have FALLEN THROUGH to the
		// transaction path, so the surfaced cause is no longer the state
		// machine's capability refusal but the embedded transport's missing
		// transaction service (#125) -- both routes exhausted. Asserting the
		// absence of CapabilityUnsupportedError is what pins the fallthrough:
		// if it regressed to returning the guarded error directly, this fails.
		var unsupported *transport.CapabilityUnsupportedError
		assert.False(t, errors.As(err, &unsupported),
			"%s: a guarded capability refusal must fall through to the transaction "+
				"path rather than being returned directly: %v", name, err)

		// The value must survive: a refusal this backend could not evaluate must
		// not have removed anything.
		got, getErr := b.Get(ctx, key)
		require.NoError(t, getErr)
		assert.Equal(t, []byte("v1"), got)
	})
}

// guardedFallbackClient carries BOTH capabilities and, unlike guardedTxClient,
// lets its transaction half actually run. It is the fixture for the rule that a
// CAPABILITY refusal from the guarded path — and only that — falls through.
type guardedFallbackClient struct {
	*guardedClient

	txCalls   int
	lastReq   *transport.TransactionRequest
	succeeded bool
}

var (
	_ transport.GuardedKVClient   = (*guardedFallbackClient)(nil)
	_ transport.TransactionClient = (*guardedFallbackClient)(nil)
)

func (c *guardedFallbackClient) ExecuteTransaction(_ context.Context, req *transport.TransactionRequest, _ ...transport.WriteOption) (*transport.TransactionResponse, error) {
	c.txCalls++
	c.lastReq = req
	return &transport.TransactionResponse{Succeeded: c.succeeded}, nil
}

// A transport can advertise the guarded capability while the SERVER cannot
// execute it — the embedded stack is exactly that, and so is a partially
// upgraded cluster. The capability refusal must not become the caller's answer
// when a linearizable transaction is sitting right there.
func TestBackend_CompareAndDelete_CapabilityRefusalFallsThroughToTransaction(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedClient()
	guarded.err = &transport.CapabilityUnsupportedError{Message: "statemachine: unknown opcode: 66"}
	client := &guardedFallbackClient{guardedClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.NoError(t, err)
	assert.True(t, deleted, "the transaction's answer must be returned")
	assert.Equal(t, 1, guarded.calls, "the guarded path is still tried first")
	assert.Equal(t, 1, client.txCalls, "and the capability refusal falls through to it")

	// The fallback must be the same guarded transaction, not a weaker one.
	require.NotNil(t, client.lastReq)
	require.Len(t, client.lastReq.Compares, 2, "presence AND value")
	require.Len(t, client.lastReq.SuccessOps, 1)
	assert.Equal(t, transport.OpDelete, client.lastReq.SuccessOps[0].Type)
}

// Every OTHER failure must stop. A capability refusal is the one error that
// means the operation was not performed; anything else may have reached the
// state machine, and re-issuing a delete after one that might have applied is
// how a guarded verb quietly becomes an unguarded one.
func TestBackend_CompareAndDelete_NonCapabilityErrorDoesNotFallThrough(t *testing.T) {
	ctx := context.Background()
	guarded := newGuardedClient()
	guarded.err = errors.New("connection reset mid-apply")
	client := &guardedFallbackClient{guardedClient: guarded, succeeded: true}
	backend := NewBackend(client)
	defer func() { _ = backend.Close() }()

	deleted, err := backend.CompareAndDelete(ctx, "key", []byte("expected"))

	require.Error(t, err)
	assert.False(t, deleted)
	assert.Equal(t, 0, client.txCalls,
		"a delete that may already have applied must not be retried by another route")

	var backendErr *BackendError
	require.True(t, errors.As(err, &backendErr))
	assert.Equal(t, "compare-and-delete", backendErr.Op)
	assert.ErrorIs(t, err, guarded.err, "the original cause must survive")
}
