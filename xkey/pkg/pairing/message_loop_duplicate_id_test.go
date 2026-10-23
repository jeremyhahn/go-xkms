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

package pairing

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// A second request registering under an ID that is already in flight used to
// replace the first request's channel in the pending map. The response then
// reached whichever request registered last while the other waited out its
// cancellation, and either deferred cleanup could delete the surviving route.
// On a signing backend that is the wrong signature returned to the wrong
// caller, so the collision is refused rather than resolved.
//
// This is independent of generation matching (go-xkms#128): it is about not
// losing a route at all, not about which of two DIFFERENT attempts a response
// belongs to.
func TestMessageRouter_SendRequest_DuplicateIDRefused(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Hold the first request open: the remote reads it but does not answer
	// until the duplicate has been attempted, so the ID is genuinely in flight.
	firstSent := make(chan struct{})
	release := make(chan struct{})
	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		close(firstSent)
		<-release

		plaintext, err := remoteSession.Decrypt(ciphertext)
		if err != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		respBytes, _ := json.Marshal(resp)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		_ = remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first := pairingproto.NewRequest(pairingproto.MethodPing, nil)

	firstDone := make(chan *pairingproto.Response, 1)
	firstErr := make(chan error, 1)
	go func() {
		resp, err := router.SendRequest(ctx, first)
		firstDone <- resp
		firstErr <- err
	}()

	select {
	case <-firstSent:
	case <-time.After(5 * time.Second):
		t.Fatal("first request was never sent")
	}

	// Same ID, different operation.
	duplicate := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	duplicate.ID = first.ID

	_, err := router.SendRequest(ctx, duplicate)
	require.Error(t, err, "a request reusing an in-flight ID must be refused")
	assert.True(t, errors.Is(err, pairingproto.ErrDuplicateRequestID),
		"want pairingproto.ErrDuplicateRequestID, got %v", err)

	// The refusal must not have disturbed the first request's route: it still
	// receives its own response.
	close(release)
	select {
	case resp := <-firstDone:
		require.NoError(t, <-firstErr)
		require.NotNil(t, resp, "the original request must still receive its response")
		assert.Equal(t, first.ID, resp.ID)
	case <-time.After(5 * time.Second):
		t.Fatal("the original request never completed; its route was disturbed")
	}
}

// Once the first request completes its ID is free again — the refusal is
// scoped to requests actually in flight, not a permanent ban on the value.
func TestMessageRouter_SendRequest_IDReusableAfterCompletion(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Answer every request the remote sees.
	go func() {
		for {
			ciphertext, err := remoteTransport.Receive(context.Background())
			if err != nil {
				return
			}
			plaintext, err := remoteSession.Decrypt(ciphertext)
			if err != nil {
				return
			}
			var req pairingproto.Request
			if err := json.Unmarshal(plaintext, &req); err != nil {
				return
			}
			resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
			respBytes, _ := json.Marshal(resp)
			respCiphertext, _ := remoteSession.Encrypt(respBytes)
			if err := remoteTransport.Send(context.Background(), respCiphertext); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	first := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, first)
	require.NoError(t, err)
	require.NotNil(t, resp)

	again := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	again.ID = first.ID

	resp, err = router.SendRequest(ctx, again)
	require.NoError(t, err, "an ID that is no longer in flight must be usable again")
	require.NotNil(t, resp)
	assert.Equal(t, first.ID, resp.ID)
}

// Two senders racing on the same ID must not both pass the check: exactly one
// registers and the other is refused. Run this under -race.
func TestMessageRouter_SendRequest_DuplicateIDRaceAdmitsOne(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// Drain the wire so neither sender blocks in Send; neither is answered, so
	// both stay pending until the context expires.
	go func() {
		for {
			if _, err := remoteTransport.Receive(context.Background()); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 750*time.Millisecond)
	defer cancel()

	const id uint64 = 424242

	var (
		wg         sync.WaitGroup
		mu         sync.Mutex
		duplicates int
		others     int
	)

	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
			req.ID = id

			_, err := router.SendRequest(ctx, req)

			mu.Lock()
			defer mu.Unlock()
			if errors.Is(err, pairingproto.ErrDuplicateRequestID) {
				duplicates++
				return
			}
			others++
		}()
	}
	wg.Wait()

	// One sender registers and then waits out the context; the other is
	// refused. Whichever order they arrive in, exactly one refusal is correct
	// and two registrations would mean the check is not atomic with the insert.
	assert.Equal(t, 1, duplicates, "exactly one of two racing senders must be refused")
	assert.Equal(t, 1, others, "exactly one of two racing senders must register")
}

// The collision a bare ID check cannot stop: request A is cancelled, its
// pending entry is freed, and the peer answers A late -- carrying A's
// generation, not the generation of whatever later reuses the ID. If B has
// since registered under the same ID, A's late answer must not be delivered
// to B; it must be dropped as a generation mismatch, and B must still get its
// own real answer (go-xkms#128; formerly guarded by a permanent per-ID
// tombstone, now closed at the point of delivery instead).
func TestMessageRouter_SendRequest_StaleGenerationDroppedReuserGetsRealAnswer(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	bg := context.Background()
	answerFor := func(id, generation uint64) []byte {
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: id, Generation: generation, Result: json.RawMessage(`{"pong":true}`)}
		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)
		ct, err := remoteSession.Encrypt(respBytes)
		require.NoError(t, err)
		return ct
	}

	aReceived := make(chan pairingproto.Request, 1)
	proceed := make(chan struct{})
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		// 1. Read the abandoned request A but hold its answer.
		ctA, err := remoteTransport.Receive(bg)
		if err != nil {
			return
		}
		ptA, err := remoteSession.Decrypt(ctA)
		if err != nil {
			return
		}
		var reqA pairingproto.Request
		if err := json.Unmarshal(ptA, &reqA); err != nil {
			return
		}
		aReceived <- reqA

		// 2. Once A has been cancelled and B has registered on the same ID,
		//    send A's LATE answer (A's generation, now stale), then read and
		//    answer B. Noise decrypts in strict nonce order, so B's answer
		//    cannot be processed by the router before A's late answer is: B
		//    completing proves A's late answer was handled (and dropped).
		<-proceed
		if err := remoteTransport.Send(bg, answerFor(reqA.ID, reqA.Generation)); err != nil {
			return
		}
		ctB, err := remoteTransport.Receive(bg)
		if err != nil {
			return
		}
		ptB, err := remoteSession.Decrypt(ctB)
		if err != nil {
			return
		}
		var reqB pairingproto.Request
		if err := json.Unmarshal(ptB, &reqB); err != nil {
			return
		}
		_ = remoteTransport.Send(bg, answerFor(reqB.ID, reqB.Generation))
	}()

	abandoned := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	cancelCtx, cancel := context.WithCancel(bg)
	sendDone := make(chan error, 1)
	go func() { _, err := router.SendRequest(cancelCtx, abandoned); sendDone <- err }()

	var reqA pairingproto.Request
	select {
	case reqA = <-aReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned request was never sent")
	}

	cancel()
	select {
	case err := <-sendDone:
		require.Error(t, err, "the cancelled request must not succeed")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled request never returned")
	}

	// The ID is free again: reuse it for B before A's late answer arrives.
	reuse := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	reuse.ID = reqA.ID

	bctx, bcancel := context.WithTimeout(bg, 5*time.Second)
	defer bcancel()
	respDone := make(chan *pairingproto.Response, 1)
	reuseErrCh := make(chan error, 1)
	go func() {
		resp, err := router.SendRequest(bctx, reuse)
		respDone <- resp
		reuseErrCh <- err
	}()

	// Give SendRequest a moment to register B's pending entry before the
	// remote is released to send A's stale answer.
	time.Sleep(100 * time.Millisecond)
	close(proceed)

	select {
	case resp := <-respDone:
		require.NoError(t, <-reuseErrCh, "the reused ID must receive its own real answer, not time out")
		require.NotNil(t, resp)
		assert.Equal(t, reuse.ID, resp.ID)
		assert.Equal(t, reuse.Generation, resp.Generation,
			"the delivered response must carry B's generation, not A's stale one")
		assert.NotEqual(t, reqA.Generation, reuse.Generation,
			"the test is only meaningful if B's generation differs from A's")
	case <-time.After(5 * time.Second):
		t.Fatal("the reused ID never completed: A's stale answer may have cross-talked into it, " +
			"or B's own answer was lost")
	}

	<-remoteDone
}

// A response with no generation at all (the JSON field absent, decoding to
// the zero value) can never match a pending entry: valid generations start at
// 1. It must be dropped exactly like a mismatched one, not treated as a
// wildcard.
func TestMessageRouter_SendRequest_MissingGenerationDropped(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		plaintext, err := remoteSession.Decrypt(ciphertext)
		if err != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}
		// A response that omits generation entirely -- marshalled from a
		// struct whose Generation field was never set.
		noGeneration := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		respBytes, _ := json.Marshal(noGeneration)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		_ = remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	resp, err := router.SendRequest(ctx, req)
	require.Error(t, err, "a response missing its generation must be dropped, not delivered")
	assert.Nil(t, resp)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

// The ordinary success path: SendRequest assigns a generation, the responder
// echoes it, and routeResponse accepts the match. This is what every other
// test in this file relies on; asserted directly here.
func TestMessageRouter_SendRequest_GenerationAssignedAndValidated(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		plaintext, err := remoteSession.Decrypt(ciphertext)
		if err != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}
		if req.Generation == 0 {
			t.Error("SendRequest sent a request with no generation assigned")
		}
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
		respBytes, _ := json.Marshal(resp)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		_ = remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	require.Zero(t, req.Generation, "pairingproto.NewRequest must not assign a generation; only SendRequest, per connection, does")

	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotZero(t, req.Generation, "SendRequest must assign a generation before sending")
	assert.Equal(t, req.Generation, resp.Generation)
}

// Successive requests on one connection never repeat a generation, even
// across different IDs -- the counter is per-connection, not per-ID.
func TestMessageRouter_SendRequest_GenerationNeverRepeats(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	const rounds = 5
	seen := make(chan uint64, rounds)

	go func() {
		for range rounds {
			ciphertext, err := remoteTransport.Receive(context.Background())
			if err != nil {
				return
			}
			plaintext, err := remoteSession.Decrypt(ciphertext)
			if err != nil {
				return
			}
			var req pairingproto.Request
			if err := json.Unmarshal(plaintext, &req); err != nil {
				return
			}
			seen <- req.Generation
			resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Generation: req.Generation, Result: json.RawMessage(`{"pong":true}`)}
			respBytes, _ := json.Marshal(resp)
			respCiphertext, _ := remoteSession.Encrypt(respBytes)
			if err := remoteTransport.Send(context.Background(), respCiphertext); err != nil {
				return
			}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	generations := make(map[uint64]bool, rounds)
	for i := 0; i < rounds; i++ {
		req := pairingproto.NewRequest(pairingproto.MethodPing, nil)
		req.ID = uint64(i % 2) // reuse only two IDs across the five rounds
		_, err := router.SendRequest(ctx, req)
		require.NoError(t, err)
		require.False(t, generations[req.Generation], "generation %d was reused within the connection", req.Generation)
		generations[req.Generation] = true
	}
}

// error responses must echo the request's generation exactly like success
// responses do -- routeResponse does not special-case Error.
func TestMessageRouter_SendRequest_ErrorResponseValidatesGeneration(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		plaintext, err := remoteSession.Decrypt(ciphertext)
		if err != nil {
			return
		}
		var req pairingproto.Request
		if err := json.Unmarshal(plaintext, &req); err != nil {
			return
		}
		resp := &pairingproto.Response{
			JSONRPC:    pairingproto.JSONRPCVersion,
			ID:         req.ID,
			Generation: req.Generation,
			Error:      &pairingproto.RPCError{Code: pairingproto.ErrorCodeKeyNotFound, Message: "key not found"},
		}
		respBytes, _ := json.Marshal(resp)
		respCiphertext, _ := remoteSession.Encrypt(respBytes)
		_ = remoteTransport.Send(context.Background(), respCiphertext)
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req := pairingproto.NewRequest(pairingproto.MethodSign, nil)
	resp, err := router.SendRequest(ctx, req)
	require.NoError(t, err, "the transport round trip itself must succeed")
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Equal(t, req.Generation, resp.Generation, "an error response must echo the request's generation")
	assert.Equal(t, pairingproto.ErrorCodeKeyNotFound, resp.Error.Code)
}

// NewMessageRouterWithNotifier built the router from its own struct literal,
// which used to omit the retired map -- any responseless exit through a
// router from that constructor then panicked with "assignment to entry in
// nil map", and every existing test used NewMessageRouter, so nothing caught
// it. retired is gone (go-xkms#128), but the constructor-drift risk it
// exposed is general, so this test now guards the router's other lazily-used
// maps (pending) instead.
//
// The path exercised here is the most ordinary one there is: a cancelled
// request.
func TestMessageRouterWithNotifier_AbandonedRequestDoesNotPanic(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouterWithNotifier(initiatorTransport, initiatorSession, nil, nil, testLogger())
	router.Start()
	defer router.Stop()

	go func() {
		_, _ = remoteTransport.Receive(context.Background())
	}()

	ctx, cancel := context.WithCancel(context.Background())
	sendDone := make(chan error, 1)
	go func() {
		_, err := router.SendRequest(ctx, pairingproto.NewRequest(pairingproto.MethodPing, nil))
		sendDone <- err
	}()

	cancel()
	select {
	case err := <-sendDone:
		require.Error(t, err, "the cancelled request must not succeed")
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled request never returned")
	}

	// Both constructors must produce equally usable routers.
	require.NotNil(t, router.pending, "NewMessageRouterWithNotifier left pending nil")
}

// TestMessageRouter_PreSendFailureLeavesIDReusable covers the #39 pre-send
// finding (Codex): a request that fails to ENCODE (or encrypt) transmitted
// nothing, so no late response is possible and its ID must stay reusable.
func TestMessageRouter_PreSendFailureLeavesIDReusable(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// A channel is not JSON-encodable, so pairingproto.EncodeRequest fails before anything is
	// sent.
	bad := pairingproto.NewRequest(pairingproto.MethodPing, make(chan int))
	_, err := router.SendRequest(context.Background(), bad)
	require.Error(t, err, "an unencodable request must fail")

	router.mu.Lock()
	_, stillPending := router.pending[bad.ID]
	router.mu.Unlock()
	require.False(t, stillPending, "a failed send must free its pending route")

	// The ID is still usable: reusing it is NOT refused as a duplicate (it will
	// time out waiting for a peer that never answers, which is a different
	// error).
	reuse := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	reuse.ID = bad.ID
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = router.SendRequest(ctx, reuse)
	require.Error(t, err)
	require.NotErrorIs(t, err, pairingproto.ErrDuplicateRequestID,
		"the ID from a pre-send failure must remain reusable")
}

// TestMessageRouter_Finalize exercises the pending-route cleanup directly:
// whatever state SendRequest left behind, finalize must free the route for
// that ID so a later request can reuse it.
func TestMessageRouter_Finalize(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)
	r := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())

	const id uint64 = 7
	r.mu.Lock()
	r.pending[id] = pendingRequest{ch: make(chan *pairingproto.Response, 1), generation: 1}
	r.mu.Unlock()

	r.finalize(id)

	r.mu.Lock()
	_, ok := r.pending[id]
	r.mu.Unlock()
	require.False(t, ok, "finalize must delete the pending route")
}
