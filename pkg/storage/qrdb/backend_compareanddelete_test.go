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
// structural rather than a judgment call: storagetest imports pkg/storage, and
// pkg/storage imports this package, so a fixture here is an import cycle the
// compiler refuses. TestEmbeddedConstructors_CompareAndDelete below therefore
// restates the contract's properties in-package against the real constructors.
// Everything else here tests the part this package actually owns — WHICH client
// capability the operation dispatches to, and what it does when neither is
// present.

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

// CompareAndDelete IS AVAILABLE FROM EVERY CONSTRUCTOR IN factory.go, measured
// 2026-09-06 against go-qrdb v0.16.3-alpha through the constructors themselves.
//
// It was not, and this test used to characterize the refusal: the
// FastStateMachine that newEmbedded builds had no handler for the guarded-delete
// opcode (go-qrdb#175), so the guarded path refused with a
// CapabilityUnsupportedError and fell through to the transaction, which the
// embedded transport does not wire (#125). The characterization was written to
// FAIL the day the state machine gained the opcode, which is exactly what
// happened on the go-qrdb v0.16.3-alpha bump; what follows is the re-derivation
// it asked for.
//
// The properties asserted are the storagetest CompareAndDelete contract, stated
// in-package because storagetest cannot be imported here (see the note at the
// top of this file). PutIfAbsent and CompareAndSwap are NOT covered by this
// change and remain unavailable through the transaction route — see
// factory_cas_characterization_test.go.
func TestEmbeddedConstructors_CompareAndDelete(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key := "compare-and-delete-conformance"
		valueA := []byte("v1")
		valueB := []byte("v2")

		// An absent key is a refusal, NOT an error: a replicated backend that
		// errored here would stall consensus over a deterministic consequence
		// of valid input.
		deleted, err := b.CompareAndDelete(ctx, key, valueA)
		require.NoError(t, err, "%s: an absent key must not be an error", name)
		assert.False(t, deleted, "%s: an absent key must report deleted=false", name)

		require.NoError(t, b.Put(ctx, key, valueA))

		// A mismatched guard refuses and leaves the value untouched.
		deleted, err = b.CompareAndDelete(ctx, key, valueB)
		require.NoError(t, err, "%s: a mismatched guard must not be an error", name)
		assert.False(t, deleted, "%s: a mismatched guard must report deleted=false", name)
		stored, err := b.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, valueA, stored, "%s: a refused delete must not alter the value", name)

		// nil is not a wildcard. A backend that treated it as "delete whatever
		// is there" would turn every guarded release into an unguarded one.
		deleted, err = b.CompareAndDelete(ctx, key, nil)
		require.NoError(t, err, "%s: a nil guard must not be an error", name)
		assert.False(t, deleted, "%s: a nil expected must NOT act as a wildcard", name)
		exists, err := b.Exists(ctx, key)
		require.NoError(t, err)
		assert.True(t, exists, "%s: a refused delete must leave the store unchanged", name)

		// A matching guard deletes.
		deleted, err = b.CompareAndDelete(ctx, key, valueA)
		require.NoError(t, err, "%s: a matching guard must succeed", name)
		assert.True(t, deleted, "%s: a matching guard must report deleted=true", name)
		exists, err = b.Exists(ctx, key)
		require.NoError(t, err)
		assert.False(t, exists, "%s: the key must be gone after a successful delete", name)
	})
}

// TestEmbeddedConstructors_CompareAndDeleteTakesTheGuardedPath pins WHICH route
// serves the verb, which the conformance test above cannot see: a transaction
// fallback that happened to produce the same answers would satisfy it. The
// embedded transport wires no transaction service, so if the guarded path were
// not answering, every case above would be an error rather than a refusal --
// asserting that a mismatched guard is a clean refusal is therefore the
// in-package evidence that the guarded path, not the fallback, ran.
func TestEmbeddedConstructors_CompareAndDeleteTakesTheGuardedPath(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key := "compare-and-delete-route"

		guarded, ok := b.client.(transport.GuardedKVClient)
		require.True(t, ok, "%s: the embedded transport must implement GuardedKVClient", name)

		require.NoError(t, b.Put(ctx, key, []byte("v1")))

		// Straight through the capability, bypassing the backend's dispatch:
		// a refusal here would mean the state machine still lacks the opcode.
		deleted, err := guarded.CompareAndDelete(ctx, key, []byte("v2"))
		require.NoError(t, err, "%s: the guarded capability must serve the verb", name)
		assert.False(t, deleted)

		var unsupported *transport.CapabilityUnsupportedError
		assert.False(t, errors.As(err, &unsupported),
			"%s: the guarded path must not refuse on capability", name)
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
