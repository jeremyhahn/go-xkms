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

package pairing

import (
	"context"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
)

const joinTestWait = 5 * time.Second

// gatedSendTransport parks inside Send until released, so a SendRequest can be
// held mid-flight while Join runs.
type gatedSendTransport struct {
	gate    chan struct{}
	entered chan struct{}
	once    sync.Once
	closed  chan struct{}
	closeOn sync.Once

	// sends counts how many times a sender reached the transport. After Stop
	// and Join it must stay at whatever it was: a sender that gets that far
	// has already encrypted through the session.
	mu    sync.Mutex
	sends int
}

func (g *gatedSendTransport) sendCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.sends
}

func newGatedSendTransport() *gatedSendTransport {
	return &gatedSendTransport{
		gate:    make(chan struct{}),
		entered: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (g *gatedSendTransport) Connect(context.Context) error { return nil }
func (g *gatedSendTransport) IsConnected() bool             { return true }

func (g *gatedSendTransport) Close() error {
	g.closeOn.Do(func() { close(g.closed) })
	return nil
}

func (g *gatedSendTransport) Send(context.Context, []byte) error {
	g.mu.Lock()
	g.sends++
	g.mu.Unlock()

	g.once.Do(func() { close(g.entered) })
	<-g.gate
	return nil
}

func (g *gatedSendTransport) Receive(context.Context) ([]byte, error) {
	<-g.closed
	return nil, pairingproto.ErrBackendClosed
}

func (g *gatedSendTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	if err := g.Send(ctx, m); err != nil {
		return nil, err
	}
	return g.Receive(ctx)
}

// TestJoinWaitsForInFlightSendRequest is the reader Join used to miss.
//
// Join waited only for receiveLoop. SendRequest is public, and its constructor
// is re-exported from xkey/pkg/phone, so a consumer can hold a router directly
// without going through PhoneKeyBackend's lease. Such a sender could be
// encrypting through the session after Join reported success and the owner
// freed the key's protected pages.
func TestJoinWaitsForInFlightSendRequest(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	session, _ := setupHandshakedNoiseSessions(t)

	transport := newGatedSendTransport()
	router := NewMessageRouter(transport, session, nil, slog.Default())
	router.Start()

	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		_, _ = router.SendRequest(context.Background(), pairingproto.NewRequest("probe", nil))
	}()

	// The sender is now parked inside Send, mid-exchange.
	select {
	case <-transport.entered:
	case <-time.After(joinTestWait):
		t.Fatal("SendRequest never reached the transport")
	}

	router.Stop()
	_ = transport.Close() // unblocks receiveLoop

	joined := make(chan bool, 1)
	go func() { joined <- router.Join(joinTestWait) }()

	// Join must not report success while a sender is still in the session.
	select {
	case ok := <-joined:
		t.Fatalf("Join returned %v while a SendRequest was still in flight", ok)
	case <-time.After(100 * time.Millisecond):
	}

	close(transport.gate)

	select {
	case <-sendDone:
	case <-time.After(joinTestWait):
		t.Fatal("SendRequest never returned after the gate opened")
	}
	select {
	case ok := <-joined:
		if !ok {
			t.Fatal("Join reported the router had not drained even after the sender returned")
		}
	case <-time.After(joinTestWait):
		t.Fatal("Join never returned")
	}
}

// TestSendRequestRefusedAfterStop stops a sender registering after Join has
// already drained, which would be a WaitGroup Add from zero racing Wait.
//
// It asserts the sender never reached the transport, not merely that it
// returned an error. Once Stop has closed the done channel a sender that got
// past the closed check would still end up erroring on the select at the
// bottom — so "an error came back" cannot distinguish being refused up front
// from encrypting through the session and only then noticing.
func TestSendRequestRefusedAfterStop(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	session, _ := setupHandshakedNoiseSessions(t)

	transport := newGatedSendTransport()
	close(transport.gate)

	router := NewMessageRouter(transport, session, nil, slog.Default())
	router.Start()
	router.Stop()
	_ = transport.Close()

	if !router.Join(joinTestWait) {
		t.Fatal("Join did not drain an idle router")
	}
	before := transport.sendCount()
	if _, err := router.SendRequest(context.Background(), pairingproto.NewRequest("probe", nil)); err == nil {
		t.Fatal("SendRequest was accepted after Stop and Join")
	}
	if got := transport.sendCount(); got != before {
		t.Fatalf("a refused SendRequest still encrypted and reached the transport: sends went %d -> %d", before, got)
	}
}

// TestJoinBeforeStopDoesNotLatchADrain covers the defect the single-waiter
// Joiner introduced.
//
// The Joiner starts one waiter for the router's life, so whatever that waiter
// observes becomes the answer every later Join gets. A Join before Start
// would create the waiter against an empty WaitGroup, latch "drained", and
// then keep reporting success after the receive loop started — telling the
// owner it was safe to destroy a session key that was actively being read.
//
// Per-call waiters did not have this failure, which is why bounding the leak
// had to be paired with this guard rather than shipped alone.
func TestJoinBeforeStopDoesNotLatchADrain(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	session, _ := setupHandshakedNoiseSessions(t)

	transport := newGatedSendTransport()
	router := NewMessageRouter(transport, session, nil, slog.Default())

	// Before Start, and before Stop: the group is genuinely empty, and that
	// is exactly the state a latch would freeze.
	if router.Join(joinTestWait) {
		t.Fatal("Join reported a drain on a router that had not been stopped")
	}

	router.Start()
	router.Stop()
	_ = transport.Close()

	if !router.Join(joinTestWait) {
		t.Fatal("Join never observed the receive loop exiting")
	}
}

// immediateErrorTransport fails every Receive right away, so a receiveLoop
// reading from it exits on its own almost immediately regardless of when
// Stop runs — Receive's error branch always returns, whether or not the
// router has been marked closed yet.
type immediateErrorTransport struct{}

func (immediateErrorTransport) Connect(context.Context) error { return nil }
func (immediateErrorTransport) IsConnected() bool             { return true }
func (immediateErrorTransport) Close() error                  { return nil }
func (immediateErrorTransport) Send(context.Context, []byte) error {
	return nil
}
func (immediateErrorTransport) Receive(context.Context) ([]byte, error) {
	return nil, pairingproto.ErrBackendClosed
}
func (t immediateErrorTransport) SendAndReceive(ctx context.Context, m []byte) ([]byte, error) {
	if err := t.Send(ctx, m); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

// TestStopAndJoin_DrainsIdleRouter proves the StopAndJoin convenience method
// combines Stop and Join correctly: a router whose receive loop has already
// exited drains within the timeout.
func TestStopAndJoin_DrainsIdleRouter(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	session, _ := setupHandshakedNoiseSessions(t)

	router := NewMessageRouter(immediateErrorTransport{}, session, nil, slog.Default())
	router.Start()

	if !router.StopAndJoin(joinTestWait) {
		t.Fatal("StopAndJoin did not drain a router whose receive loop had already exited")
	}
}

// TestStartAfterStopDoesNotRegister keeps the other half of the same
// invariant: once Stop has run, nothing may take the WaitGroup from zero to
// one, because a waiter may already be parked on it.
func TestStartAfterStopDoesNotRegister(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	session, _ := setupHandshakedNoiseSessions(t)

	transport := newGatedSendTransport()
	close(transport.gate)
	router := NewMessageRouter(transport, session, nil, slog.Default())

	router.Stop()
	router.Start() // must not launch a receive loop

	if !router.Join(joinTestWait) {
		t.Fatal("Start registered work on a stopped router, so Join could not drain")
	}
}
