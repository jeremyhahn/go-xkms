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

package usb

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testWait bounds every wait in this file. A regression must fail this test,
// not hang the package until the go test timeout fires and reports as
// infrastructure trouble.
const testWait = 5 * time.Second

// gatedPhone blocks inside the handshake until released, which makes the
// Connect/Close interleaving deterministic instead of a timing bet.
type gatedPhone struct {
	*fakePhone

	// gate is closed to let the handshake proceed.
	gate chan struct{}
	// entered is closed once the handshake has actually blocked, so the test
	// knows Connect is mid-flight.
	entered chan struct{}

	once sync.Once

	// handshakes counts how many times a handshake started on this bus. The
	// serialization claim is about exactly this number.
	mu         sync.Mutex
	handshakes int
}

// Send is the first transport call PerformHandshake makes, so gating it puts
// the block squarely inside Connect's handshake.
func (g *gatedPhone) Send(ctx context.Context, message []byte) error {
	g.once.Do(func() { close(g.entered) })
	<-g.gate
	return g.fakePhone.Send(ctx, message)
}

// startHandshake is called by the transport-visible entry point of a
// handshake. Counting Connect's first frame is the observable proxy.
func (g *gatedPhone) countHandshake() {
	g.mu.Lock()
	g.handshakes++
	g.mu.Unlock()
}

func (g *gatedPhone) handshakeCount() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.handshakes
}

func (g *gatedPhone) Connect(ctx context.Context) error {
	g.countHandshake()
	return g.fakePhone.Connect(ctx)
}

// newGatedTransport returns nil, nil, false when the handshake key was
// refused for the expected GODEBUG=fips140=only reason (see
// requireStaticKey); the caller must return immediately in that case.
func newGatedTransport(t *testing.T) (*Transport, *gatedPhone, bool) {
	t.Helper()

	key, ok := requireStaticKey(t)
	if !ok {
		return nil, nil, false
	}
	t.Cleanup(key.Destroy)

	g := &gatedPhone{
		fakePhone: &fakePhone{},
		gate:      make(chan struct{}),
		entered:   make(chan struct{}),
	}

	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = g
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: privateKeyBytes(t, key)})
	return tr, g, true
}

// TestCloseWaitsForInFlightConnect is the race Codex named: Close landing
// between a successful handshake and its publication used to tear the
// transport down, after which Connect reinstated connected=true over a
// phoneUSB that had already been closed — a transport reporting a live
// encrypted session on a dead bus.
//
// lifecycleMu makes Close wait, so the two operations cannot interleave and
// the transport ends up closed, which is what the caller asked for last.
//
// Every wait here is bounded. An unbounded receive turns a regression into a
// package-wide timeout that reports as infrastructure trouble rather than as
// this test failing, and the gate is released from a cleanup so a failure
// midway cannot wedge the goroutines.
func TestCloseWaitsForInFlightConnect(t *testing.T) {
	tr, g, ok := newGatedTransport(t)
	if !ok {
		return
	}

	var gateOnce sync.Once
	releaseGate := func() { gateOnce.Do(func() { close(g.gate) }) }
	t.Cleanup(releaseGate)

	connectDone := make(chan error, 1)
	go func() { connectDone <- tr.Connect(context.Background()) }()

	// Connect is now blocked inside the handshake.
	select {
	case <-g.entered:
	case <-time.After(testWait):
		t.Fatal("Connect never reached the handshake")
	}

	closeReturned := make(chan struct{})
	go func() {
		_ = tr.Close()
		close(closeReturned)
	}()

	// Close must not complete while Connect holds the lifecycle lock.
	select {
	case <-closeReturned:
		t.Fatal("Close completed while a Connect was in flight")
	case <-time.After(50 * time.Millisecond):
	}

	releaseGate()
	select {
	case <-connectDone:
	case <-time.After(testWait):
		t.Fatal("Connect never returned after the gate opened")
	}
	select {
	case <-closeReturned:
	case <-time.After(testWait):
		t.Fatal("Close never returned after Connect finished")
	}

	// Close ran last, so the transport is down and its key is released.
	assert.False(t, tr.connected, "transport still reports connected after Close")
	assert.Nil(t, tr.session, "session survived Close")
	assert.Nil(t, tr.localKey, "protected key survived Close")
}

// TestConcurrentConnectsSerialize asserts the contract rather than mere
// internal consistency: of two racing Connects exactly one establishes the
// session and the other is rejected, and exactly one handshake reaches the bus.
//
// The earlier version accepted any pair of outcomes, so it passed even if both
// Connects failed — it could not fail for the right reason, and it went on
// passing after round 7 changed the contract underneath it.
func TestConcurrentConnectsSerialize(t *testing.T) {
	tr, g, ok := newGatedTransport(t)
	if !ok {
		return
	}
	close(g.gate) // no blocking; we only care that they do not overlap.

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i := range errs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = tr.Connect(context.Background())
		}(i)
	}
	wg.Wait()

	var succeeded, rejected int
	for _, err := range errs {
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrDirtyState):
			rejected++
		default:
			t.Fatalf("unexpected Connect error: %v", err)
		}
	}
	require.Equal(t, 1, succeeded, "expected exactly one Connect to establish the session, got %d", succeeded)
	require.Equal(t, 1, rejected, "expected exactly one Connect to be rejected with ErrDirtyState, got %d", rejected)

	// One handshake on the bus, not two.
	require.Equal(t, 1, g.handshakeCount(), "more than one handshake reached the bus")

	// And the winner left the transport fully established, never half-swapped.
	require.True(t, tr.connected, "the surviving Connect did not leave the transport connected")
	require.NotNil(t, tr.session, "connected transport has no session")
	require.NotNil(t, tr.localKey, "connected transport has no static key")

	require.NoError(t, tr.Close())
	assert.Nil(t, tr.localKey, "Close left a protected key behind")
}

// failingSendPhone completes the handshake and then fails the first RPC, which
// is what leaves the transport in the state this test is about.
type failingSendPhone struct {
	*fakePhone
	handshakeDone bool
}

func (f *failingSendPhone) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if !f.handshakeDone {
		return f.fakePhone.SendAndReceive(ctx, message)
	}
	return nil, errors.New("bus went away")
}

// TestConnectRejectsResidualStateAfterFailedRequest covers the gap between
// "not connected" and "nothing to release". Request clears connected on a send
// failure but leaves the bus, session and key in place. Connect used to test
// only connected, so it accepted that state, handshaked over a half-dead bus,
// and overwrote localKey — leaking the previous key's locked pages on every
// transient failure.
func TestConnectRejectsResidualStateAfterFailedRequest(t *testing.T) {
	key, ok := requireStaticKey(t)
	if !ok {
		return
	}
	t.Cleanup(key.Destroy)

	fake := &failingSendPhone{fakePhone: &fakePhone{}}

	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = fake
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: privateKeyBytes(t, key)})

	require.NoError(t, tr.Connect(context.Background()))
	fake.handshakeDone = true

	// Drive the failure that clears connected while leaving state behind.
	err = tr.Request(context.Background(), "noop", struct{}{}, nil)
	require.Error(t, err)
	require.False(t, tr.connected, "the failure should have cleared connected")
	require.NotNil(t, tr.localKey, "the failure leaves the key in place — that is the point")

	// Reconnecting in place must be refused, not silently accepted.
	err = tr.Connect(context.Background())
	require.ErrorIs(t, err, ErrDirtyState)

	// And Close is the way out, releasing the key.
	require.NoError(t, tr.Close())
	require.Nil(t, tr.localKey, "Close left the key behind")
}

// terminalPhone is a bus transport whose Close is terminal: once closed, it
// refuses to connect again. That is how the production USB transport behaves,
// and it is the behaviour the reusable fakes in these tests do not model.
type terminalPhone struct {
	fakePhone
	closed bool
}

func (p *terminalPhone) Close() error {
	p.closed = true
	p.connected.Store(false)
	return nil
}

func (p *terminalPhone) Connect(context.Context) error {
	if p.closed {
		return errors.New("usb accessory closed; this instance cannot reconnect")
	}
	p.connected.Store(true)
	return nil
}

// TestCloseDiscardsTheBusTransport pins the reconnect path that ErrDirtyState
// tells callers to take.
//
// ErrDirtyState says "Close first", and Close cleared the session, key and
// connected flag — so the dirty check passed on the next Connect. But Close
// left the CLOSED phoneUSB installed, and Connect only builds a new one when
// phoneUSB is nil. Against the production transport, whose Close is terminal,
// that meant every reconnect after a Close handshaked over a dead bus,
// permanently. The advice the error gives could not be followed.
func TestCloseDiscardsTheBusTransport(t *testing.T) {
	key, ok := requireStaticKey(t)
	if !ok {
		return
	}
	defer key.Destroy()

	tr, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	tr.WithNoiseConfig(&NoiseConfig{LocalStaticPrivateKey: privateKeyBytes(t, key)})

	first := &terminalPhone{}
	tr.phoneUSB = first

	if err := tr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !first.closed {
		t.Fatal("Close did not close the bus transport")
	}

	tr.mu.Lock()
	installed := tr.phoneUSB
	tr.mu.Unlock()
	if installed != nil {
		t.Fatal("Close left the closed bus transport installed; the next Connect will reuse it")
	}
}

// stalledPhone answers the handshake normally and then blocks inside
// SendAndReceive until its Close is called, which is what an unresponsive
// handset looks like from this side of the bus.
type stalledPhone struct {
	*fakePhone

	entered chan struct{} // closed once a post-handshake request has blocked
	release chan struct{} // closed by Close
	once    sync.Once
}

func newStalledPhone() *stalledPhone {
	return &stalledPhone{
		fakePhone: &fakePhone{},
		entered:   make(chan struct{}),
		release:   make(chan struct{}),
	}
}

func (p *stalledPhone) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	// The handshake must complete, or the request never reaches the bus at
	// all and the test would pass for the wrong reason.
	if !p.handshook {
		return p.fakePhone.SendAndReceive(ctx, message)
	}

	p.once.Do(func() { close(p.entered) })
	select {
	case <-p.release:
		return nil, errors.New("usb accessory closed while a request was in flight")
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *stalledPhone) Close() error {
	p.once.Do(func() { close(p.entered) })
	close(p.release)
	p.connected.Store(false)
	return nil
}

// TestCloseIsNotHostageToAStalledRequest covers the shutdown block this
// branch's own key-safety fix introduced.
//
// Request holds t.mu across phoneUSB.SendAndReceive so the session cannot be
// freed mid-encrypt. That is necessary — and it means mu is unavailable for as
// long as the device takes to answer. A Close that waited for mu before doing
// anything else therefore waited out the entire I/O timeout behind an
// unresponsive handset, and against a bus that ignores its context it would
// wait forever: shutdown held hostage by the device it is shutting down.
//
// Close now closes the bus BEFORE contending for mu, which is what ends the
// wait. The blocked request fails, releases mu, and Close frees the key under
// the lock exactly as before.
func TestCloseIsNotHostageToAStalledRequest(t *testing.T) {
	bus := newStalledPhone()
	tr, ok := newPairedTransport(t, bus.fakePhone)
	if !ok {
		return
	}

	// newPairedTransport handshakes through the embedded fake; swap in the
	// stalling wrapper for the request phase.
	tr.mu.Lock()
	tr.phoneUSB = bus
	tr.mu.Unlock()

	// A request that reaches the bus and stays there, holding mu.
	requestDone := make(chan struct{})
	go func() {
		defer close(requestDone)
		_ = tr.Request(context.Background(), "test.method", map[string]string{}, nil)
	}()

	select {
	case <-bus.entered:
	case <-time.After(testWait):
		t.Fatal("the request never reached the bus")
	}

	// Close must return without waiting for the device.
	closed := make(chan error, 1)
	go func() { closed <- tr.Close() }()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close: %v", err)
		}
	case <-time.After(testWait):
		t.Fatal("Close blocked behind a request stalled on the bus: shutdown is " +
			"hostage to an unresponsive device, and a bus that ignores its " +
			"context would block it forever")
	}

	select {
	case <-requestDone:
	case <-time.After(testWait):
		t.Fatal("closing the bus did not unblock the in-flight request")
	}

	// And the key is still freed under the lock, once the request is out.
	tr.mu.Lock()
	remaining := tr.localKey
	tr.mu.Unlock()
	if remaining != nil {
		t.Fatal("Close returned without releasing the protected key")
	}
}
