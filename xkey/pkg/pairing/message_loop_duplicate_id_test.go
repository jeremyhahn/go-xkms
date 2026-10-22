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
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
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
			resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
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

// The collision the duplicate check alone does not stop: request A is
// cancelled, its pending entry is cleaned up, and the peer answers A late. If
// the ID were free again, request B could have taken it and received A's
// answer as its own — the same wrong-result-to-wrong-caller confusion, reached
// through a cancellation rather than a concurrent collision.
//
// An ID abandoned without a response is therefore retired for the rest of the
// connection.
func TestMessageRouter_SendRequest_AbandonedIDCannotBeReused(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, remoteTransport := newPipeTransports()
	initiatorSession, remoteSession := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// The remote reads A but withholds its answer until after A has given up.
	received := make(chan []byte, 1)
	go func() {
		ciphertext, err := remoteTransport.Receive(context.Background())
		if err != nil {
			return
		}
		received <- ciphertext
	}()

	abandoned := pairingproto.NewRequest(pairingproto.MethodPing, nil)

	cancelCtx, cancel := context.WithCancel(context.Background())
	sendDone := make(chan error, 1)
	go func() {
		_, err := router.SendRequest(cancelCtx, abandoned)
		sendDone <- err
	}()

	var ciphertext []byte
	select {
	case ciphertext = <-received:
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

	// Reusing the abandoned ID is refused, so no later request can be sitting
	// on it when the late answer arrives.
	reuse := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	reuse.ID = abandoned.ID

	ctx, ctxCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer ctxCancel()

	_, err := router.SendRequest(ctx, reuse)
	require.Error(t, err, "an abandoned ID must not be reusable on the same connection")
	assert.True(t, errors.Is(err, pairingproto.ErrDuplicateRequestID),
		"want pairingproto.ErrDuplicateRequestID, got %v", err)

	// Deliver the late answer to prove nothing is waiting to receive it. The
	// router logs it as unknown and drops it; the test asserts by not hanging
	// and by the reuse having already been refused above.
	plaintext, err := remoteSession.Decrypt(ciphertext)
	require.NoError(t, err)
	var req pairingproto.Request
	require.NoError(t, json.Unmarshal(plaintext, &req))
	resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
	respBytes, err := json.Marshal(resp)
	require.NoError(t, err)
	respCiphertext, err := remoteSession.Encrypt(respBytes)
	require.NoError(t, err)
	require.NoError(t, remoteTransport.Send(context.Background(), respCiphertext))
}

// Retiring is scoped to abandoned requests only. An ID whose response was
// delivered cannot be answered a second time, so it stays reusable — otherwise
// a long-lived connection would exhaust a caller's ID space.
func TestMessageRouter_SendRequest_AnsweredIDIsNotRetired(t *testing.T) {
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
			resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
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
	_, err := router.SendRequest(ctx, first)
	require.NoError(t, err)

	again := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	again.ID = first.ID
	_, err = router.SendRequest(ctx, again)
	require.NoError(t, err, "an answered ID must remain reusable")
}

// NewMessageRouterWithNotifier built the router from its own struct literal,
// which omitted the retired map. Any responseless exit through a router from
// that constructor then panicked with "assignment to entry in nil map" -- and
// every existing test used NewMessageRouter, so nothing caught it.
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
	require.NotNil(t, router.retired, "NewMessageRouterWithNotifier left retired nil")
}

// "Bounded by the number of abandoned requests" is not a bound: a long-lived
// connection with repeated transient failures abandons requests indefinitely,
// and the caller chooses the IDs. This proves the retained state cannot grow
// without limit, and that the limit is enforced by REFUSING rather than by
// evicting -- evicting a tombstone would restore the cross-talk it exists to
// prevent.
func TestMessageRouter_RetiredIDsAreBounded(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())

	// Fill the tombstone set directly. Driving 4096 real abandoned requests
	// through the transport would test the pipe's throughput, not the bound.
	router.mu.Lock()
	for id := uint64(1); id <= maxRetiredIDs; id++ {
		router.retired[id] = struct{}{}
	}
	router.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	// An ID outside the seeded range, so the refusal is the CAP and not the
	// per-ID tombstone check that runs before it.
	fresh := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	fresh.ID = maxRetiredIDs + 1

	_, err := router.SendRequest(ctx, fresh)
	require.Error(t, err, "the router accepted a new request at the tombstone cap")
	assert.True(t, errors.Is(err, pairingproto.ErrTooManyAbandonedRequests),
		"want pairingproto.ErrTooManyAbandonedRequests, got %v", err)

	// Refused, not evicted: every tombstone must survive, or a reused ID could
	// still collect a stale answer.
	router.mu.Lock()
	held := len(router.retired)
	router.mu.Unlock()
	assert.Equal(t, maxRetiredIDs, held,
		"the cap must refuse new work, never drop a tombstone")
}

// A late answer to an abandoned request does NOT clear the tombstone: "a
// request is answered once" is not enforced on the wire, so a faulty or
// malicious authenticated peer can send a second valid response for the same
// abandoned ID. If the first answer freed the ID and the caller reused it, that
// second answer would cross-talk into the reuser. So an abandoned ID stays
// retired for the connection lifetime, and the cap forces a reconnect instead.
func TestMessageRouter_LateResponseKeepsTheTombstone(t *testing.T) {
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
	answer := func(reqCipher []byte) []byte {
		pt, err := remoteSession.Decrypt(reqCipher)
		require.NoError(t, err)
		var req pairingproto.Request
		require.NoError(t, json.Unmarshal(pt, &req))
		resp := &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: req.ID, Result: json.RawMessage(`{"pong":true}`)}
		respBytes, err := json.Marshal(resp)
		require.NoError(t, err)
		ct, err := remoteSession.Encrypt(respBytes)
		require.NoError(t, err)
		return ct
	}

	aReceived := make(chan []byte, 1)
	aRetired := make(chan struct{})
	remoteDone := make(chan struct{})
	go func() {
		defer close(remoteDone)
		// 1. Read the abandoned request A but hold its answer.
		ctA, err := remoteTransport.Receive(bg)
		if err != nil {
			return
		}
		aReceived <- ctA
		// 2. Once A has been cancelled and retired, send its LATE answer, then
		//    read and answer a follow-up request B. Noise decrypts in strict
		//    nonce order, so B's answer cannot be processed by the router before
		//    A's late answer is: B completing proves A's late answer was handled.
		<-aRetired
		if err := remoteTransport.Send(bg, answer(ctA)); err != nil {
			return
		}
		ctB, err := remoteTransport.Receive(bg)
		if err != nil {
			return
		}
		_ = remoteTransport.Send(bg, answer(ctB))
	}()

	abandoned := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	cancelCtx, cancel := context.WithCancel(bg)
	sendDone := make(chan error, 1)
	go func() { _, err := router.SendRequest(cancelCtx, abandoned); sendDone <- err }()

	select {
	case <-aReceived:
	case <-time.After(5 * time.Second):
		t.Fatal("the abandoned request was never sent")
	}

	cancel()
	select {
	case err := <-sendDone:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("the cancelled request never returned")
	}

	router.mu.Lock()
	_, retired := router.retired[abandoned.ID]
	router.mu.Unlock()
	require.True(t, retired, "the abandoned ID should be retired")

	// Release the remote: it sends A's late answer, then answers B.
	close(aRetired)

	// Completing B proves the router processed A's late answer first (FIFO /
	// strict Noise nonce order).
	followUp := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	bctx, bcancel := context.WithTimeout(bg, 5*time.Second)
	defer bcancel()
	respB, err := router.SendRequest(bctx, followUp)
	require.NoError(t, err, "the follow-up request must complete")
	require.NotNil(t, respB)

	// The tombstone must have SURVIVED the late answer, so the abandoned ID is
	// still refused. Under the old drop-on-answer behaviour it would be reusable
	// here, letting a second late answer cross-talk into the reuser.
	router.mu.Lock()
	_, still := router.retired[abandoned.ID]
	router.mu.Unlock()
	require.True(t, still, "the abandoned ID's tombstone must survive its late answer")

	reuse := pairingproto.NewRequest(pairingproto.MethodPing, nil)
	reuse.ID = abandoned.ID
	rctx, rcancel := context.WithTimeout(bg, 500*time.Millisecond)
	defer rcancel()
	_, reuseErr := router.SendRequest(rctx, reuse)
	require.ErrorIs(t, reuseErr, pairingproto.ErrDuplicateRequestID,
		"an abandoned ID must remain non-reusable after its late answer")

	<-remoteDone
}

// TestMessageRouter_PreSendFailureDoesNotRetire covers the #39 pre-send finding
// (Codex): a request that fails to ENCODE (or encrypt) transmitted nothing, so
// no late response is possible and its ID must stay reusable. Retiring it there
// would let a burst of locally-invalid requests fill the tombstone cap and wedge
// an otherwise healthy connection.
func TestMessageRouter_PreSendFailureDoesNotRetire(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	initiatorTransport, _ := newPipeTransports()
	initiatorSession, _ := setupHandshakedNoiseSessions(t)
	router := NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	router.Start()
	defer router.Stop()

	// A channel is not JSON-encodable, so EncodeRequest fails before anything is
	// sent.
	bad := pairingproto.NewRequest(pairingproto.MethodPing, make(chan int))
	_, err := router.SendRequest(context.Background(), bad)
	require.Error(t, err, "an unencodable request must fail")

	router.mu.Lock()
	_, retired := router.retired[bad.ID]
	router.mu.Unlock()
	require.False(t, retired, "a request that never reached the wire must not retire its ID")

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

// TestMessageRouter_FinalizeAbandon exercises the retirement decision directly,
// deterministically, including the cancel-vs-delivery race (F3) that cannot be
// forced through SendRequest's select. finalizeAbandon is the security-sensitive
// core: given (sent, answered, whether a response is sitting in respCh) it
// decides whether an ID is tombstoned.
func TestMessageRouter_FinalizeAbandon(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	newRouter := func() *MessageRouter {
		initiatorTransport, _ := newPipeTransports()
		initiatorSession, _ := setupHandshakedNoiseSessions(t)
		return NewMessageRouter(initiatorTransport, initiatorSession, nil, testLogger())
	}
	isRetired := func(r *MessageRouter, id uint64) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, ok := r.retired[id]
		return ok
	}
	inPending := func(r *MessageRouter, id uint64) bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		_, ok := r.pending[id]
		return ok
	}

	const id uint64 = 7

	t.Run("answered is never retired", func(t *testing.T) {
		r := newRouter()
		ch := make(chan *pairingproto.Response, 1)
		r.mu.Lock()
		r.pending[id] = ch
		r.mu.Unlock()
		r.finalizeAbandon(id, ch, true /*sent*/, true /*answered*/)
		require.False(t, isRetired(r, id), "an answered ID must not be retired")
		require.False(t, inPending(r, id), "the pending route must be freed")
	})

	t.Run("pre-send failure is not retired", func(t *testing.T) {
		r := newRouter()
		ch := make(chan *pairingproto.Response, 1)
		r.finalizeAbandon(id, ch, false /*sent*/, false /*answered*/)
		require.False(t, isRetired(r, id), "a request that never reached the wire must stay reusable")
	})

	t.Run("sent and unanswered is retired", func(t *testing.T) {
		r := newRouter()
		ch := make(chan *pairingproto.Response, 1) // empty: no response arrived
		r.finalizeAbandon(id, ch, true /*sent*/, false /*answered*/)
		require.True(t, isRetired(r, id), "a genuinely abandoned sent request must be retired")
	})

	t.Run("a raced-in response is drained, not retired (F3)", func(t *testing.T) {
		r := newRouter()
		ch := make(chan *pairingproto.Response, 1)
		ch <- &pairingproto.Response{JSONRPC: pairingproto.JSONRPCVersion, ID: id} // delivered while ctx.Done won the select
		r.finalizeAbandon(id, ch, true /*sent*/, false /*answered as far as the select knew*/)
		require.False(t, isRetired(r, id),
			"a response delivered under a racing cancellation must not leave a tombstone")
	})
}
