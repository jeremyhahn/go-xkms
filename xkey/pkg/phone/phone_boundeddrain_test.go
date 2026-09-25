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

package phone

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// shrinkOpsTimeout makes the lease drain bounded by something a test can
// afford to wait for, and restores the production window afterwards.
func shrinkOpsTimeout(t *testing.T, d time.Duration) {
	t.Helper()

	original := opsShutdownTimeout
	opsShutdownTimeout = d
	t.Cleanup(func() { opsShutdownTimeout = original })
}

// TestClose_BoundsTheLeaseDrain covers the hang this branch introduced.
//
// Close waits for in-flight operations to release their session lease. That
// wait used to be unconditional, and Transport.Close is not required by its
// contract to unblock a SendAndReceive already in flight — so a transport
// that does not (a custom one, or a faulty one) left Close waiting forever,
// holding b.mu, which is the mutex every other method needs.
//
// The lease here is taken directly rather than through a round trip, because
// the lease IS the window a round trip holds open.
func TestClose_BoundsTheLeaseDrain(t *testing.T) {
	shrinkOpsTimeout(t, 100*time.Millisecond)

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()
	local.connected.Store(true)

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	backend.connected.Store(true)

	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}

	closed := make(chan error, 1)
	go func() { closed <- backend.Close() }()

	select {
	case err := <-closed:
		if !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("Close returned %v, want ErrShutdownIncomplete", err)
		}
	case <-time.After(testWait):
		t.Fatal("Close never returned: the lease drain is still unbounded")
	}

	// The point of bounding the wait is that it does NOT license freeing the
	// key. An operation is still holding the session; its pages must stay.
	if destroyed(key) {
		t.Fatal("Close destroyed the static key while a lease was outstanding")
	}

	release()
}

// TestClose_ReportsIncompleteShutdownForABorrowedKey pins the case that
// matters most and is easiest to miss. When the caller kept ownership, this
// backend cannot retain the key on their behalf — the owner is the only one
// who can decide not to free it, and Close's return value is the only way
// they find out there is still a reader.
func TestClose_ReportsIncompleteShutdownForABorrowedKey(t *testing.T) {
	shrinkOpsTimeout(t, 100*time.Millisecond)

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	local, _ := newPipeTransports()
	local.connected.Store(true)

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	backend.connected.Store(true)

	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}

	closed := make(chan error, 1)
	go func() { closed <- backend.Close() }()

	select {
	case err := <-closed:
		if !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("Close returned %v, want ErrShutdownIncomplete for a borrowed key", err)
		}
	case <-time.After(testWait):
		t.Fatal("Close never returned")
	}

	if destroyed(key) {
		t.Fatal("Close destroyed a key it never owned")
	}

	release()
}

// TestClose_ReportsSuccessWhenEveryLeaseDrains is the other half of the
// contract, and it is what stops the error above from being returned
// unconditionally: a clean shutdown must still report nil and free the key.
func TestClose_ReportsSuccessWhenEveryLeaseDrains(t *testing.T) {
	shrinkOpsTimeout(t, testWait)

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()
	local.connected.Store(true)

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	backend.connected.Store(true)

	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}

	closed := make(chan error, 1)
	go func() { closed <- backend.Close() }()

	// No readiness wait needed: the lease was acquired before Close started,
	// so b.ops already has it in flight whenever Close reaches ops.Wait --
	// release() only needs to happen at some point, not after any particular
	// state Close reaches.
	release()

	select {
	case err := <-closed:
		if err != nil {
			t.Fatalf("Close returned %v on a clean shutdown, want nil", err)
		}
	case <-time.After(testWait):
		t.Fatal("Close never returned after the lease was released")
	}

	if !destroyed(key) {
		t.Fatal("Close left the owned key resident after a clean drain")
	}
}

// TestConstructorFailureWithOwnedNilKey pins the behaviour of a config that
// is valid but looks contradictory: OwnsStaticKey set with LocalStaticKey nil.
// The config documents that a nil key is generated by the constructor, so
// ownership of a not-yet-existing key is a legitimate thing for a caller to
// declare, and both constructors can reject the config before generation
// happens — the cleanup then runs on a nil key.
//
// That is safe: truststrap's StaticKey.Destroy opens with a nil-receiver
// check and is documented as safe on a nil receiver. Codex read this as a nil
// dereference in review 318 and it is not one; the path is reachable and the
// behaviour is correct. This test is here so the claim is settled by
// execution rather than re-litigated, and so a future change to Destroy's
// contract fails here rather than in a cleanup path nobody runs.
func TestConstructorFailureWithOwnedNilKey(t *testing.T) {
	cfg := &PhoneKeyBackendConfig{
		OwnsStaticKey:   true, // ownership of the key the constructor would make
		LocalStaticKey:  nil,
		TrustNewDevices: true,
	}

	backend, err := NewPhoneKeyBackendWithTransport(cfg, nil)
	if err == nil {
		t.Fatal("expected a nil transport to be rejected")
	}
	if backend != nil {
		t.Fatal("a rejected construction returned a backend")
	}
	if cfg.LocalStaticKey != nil {
		t.Fatal("cleanup left a key on the config")
	}
}

// TestReusedConfigDoesNotShareASuppliedOwnedKey covers the half of the
// config-reuse hazard the earlier test missed.
//
// TestReusedConfigDoesNotShareAnOwnedKey covers a nil key that the
// constructor generates — the case where the fix was to stop writing the
// generated key back into the caller's config. This is the other branch: a
// caller SUPPLIES a key and sets OwnsStaticKey. Ownership transfers, but the
// pointer stayed in the config, so a second construction from the same config
// took ownership of the same protected pages. Whichever backend closed first
// would free pages the other's session was still reading.
func TestReusedConfigDoesNotShareASuppliedOwnedKey(t *testing.T) {
	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	cfg := &PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}

	first, _ := newPipeTransports()
	first.connected.Store(true)
	backendA, err := NewPhoneKeyBackendWithTransport(cfg, first)
	if err != nil {
		t.Fatalf("first construction: %v", err)
	}

	// The transfer must have emptied the config. Anything else hands the next
	// backend a key this one destroys.
	if cfg.LocalStaticKey != nil {
		t.Fatal("the config still holds a key whose ownership it transferred")
	}

	second, _ := newPipeTransports()
	second.connected.Store(true)
	backendB, err := NewPhoneKeyBackendWithTransport(cfg, second)
	if err != nil {
		t.Fatalf("second construction: %v", err)
	}

	if backendA.ownedKey == backendB.ownedKey {
		t.Fatal("both backends own the same protected key")
	}

	// Closing the first must not touch the second's key, which is the
	// consequence that makes the sharing a use-after-free rather than an
	// accounting error.
	_ = backendA.Close()

	if destroyed(backendB.ownedKey) {
		t.Fatal("closing the first backend destroyed the second backend's key")
	}
	_ = backendB.Close()

	if !destroyed(key) {
		t.Fatal("the supplied key was never destroyed by the owner it transferred to")
	}
}

// TestSecondCloseDoesNotReportSuccessAfterIncompleteShutdown covers the third
// instance of the fail-open latch defect, in the phone backend.
//
// Close used to return nil to every caller after the first — including one
// arriving while the first Close was still draining, and including a second
// call after the first reported ErrShutdownIncomplete. For a BORROWED key
// that nil is the whole hazard: it tells the owner destroying the protected
// pages is safe while an operation may still be encrypting through them.
func TestSecondCloseDoesNotReportSuccessAfterIncompleteShutdown(t *testing.T) {
	shrinkOpsTimeout(t, 100*time.Millisecond)

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	local, _ := newPipeTransports()
	local.connected.Store(true)

	// Borrowed deliberately: this is the case the nil return endangers.
	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	backend.connected.Store(true)

	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}

	if err := backend.Close(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("first Close returned %v, want ErrShutdownIncomplete", err)
	}
	if err := backend.Close(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("second Close returned %v; a borrowed key's owner would read "+
			"that as permission to destroy pages still in use", err)
	}
	if destroyed(key) {
		t.Fatal("a borrowed key was destroyed by the backend")
	}

	release()
}

// TestConcurrentCloseObservesTheSameOutcome pins the other half: a caller
// arriving while the first Close is draining must wait for it and receive its
// result, not be told success immediately.
func TestConcurrentCloseObservesTheSameOutcome(t *testing.T) {
	shrinkOpsTimeout(t, 300*time.Millisecond)

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	local, _ := newPipeTransports()
	local.connected.Store(true)

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	backend.connected.Store(true)

	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}
	defer release()

	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		go func() { results <- backend.Close() }()
	}

	for i := 0; i < 2; i++ {
		select {
		case err := <-results:
			if !errors.Is(err, ErrShutdownIncomplete) {
				t.Fatalf("a concurrent Close returned %v while the drain was "+
					"still outstanding, want ErrShutdownIncomplete", err)
			}
		case <-time.After(testWait):
			t.Fatal("a Close never returned")
		}
	}
}

// handshakedResponder runs a complete Noise XX exchange in memory and returns
// the responder session, ready to encrypt. SendRequest fails at the cipher
// before it ever touches the transport without one, which is the reason the
// sibling test reached for the internal lease instead.
func handshakedResponder(t *testing.T) *pairing.NoiseSession {
	t.Helper()

	initKey, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("initiator key: %v", err)
	}
	respKey, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("responder key: %v", err)
	}

	initiator, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{LocalStaticKey: initKey, IsInitiator: true})
	if err != nil {
		t.Fatalf("initiator session: %v", err)
	}
	responder, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{LocalStaticKey: respKey, IsInitiator: false})
	if err != nil {
		t.Fatalf("responder session: %v", err)
	}
	if err := initiator.InitHandshake(); err != nil {
		t.Fatalf("initiator init: %v", err)
	}
	if err := responder.InitHandshake(); err != nil {
		t.Fatalf("responder init: %v", err)
	}

	msg1, _, err := initiator.HandshakeMessage(nil)
	if err != nil {
		t.Fatalf("msg1: %v", err)
	}
	msg2, _, err := responder.HandshakeMessage(msg1)
	if err != nil {
		t.Fatalf("msg2: %v", err)
	}
	msg3, _, err := initiator.HandshakeMessage(msg2)
	if err != nil {
		t.Fatalf("msg3: %v", err)
	}
	if _, complete, err := responder.HandshakeMessage(msg3); err != nil || !complete {
		t.Fatalf("responder handshake incomplete: complete=%v err=%v", complete, err)
	}
	return responder
}

// leaseObservingTransport records how many operations the backend counted as
// in flight at the moment the request reached the bus.
type leaseObservingTransport struct {
	*blockingReceiveTransport
	backend  *PhoneKeyBackend
	inFlight chan int
}

func (l *leaseObservingTransport) SendAndReceive(ctx context.Context, msg []byte) ([]byte, error) {
	l.backend.mu.RLock()
	n := l.backend.ops.InFlight()
	l.backend.mu.RUnlock()

	select {
	case l.inFlight <- n:
	default:
	}
	return l.blockingReceiveTransport.SendAndReceive(ctx, msg)
}

// TestSendRequestHoldsALeaseForItsRoundTrip closes the gap the sibling lease
// test leaves open.
//
// TestClose_WaitsForInFlightRequest takes the lease directly with
// acquireSession, which pins that CLOSE honours a lease and says nothing
// about whether SendRequest ever takes one. Delete the lease from SendRequest
// and that test still passes, while every request becomes free to encrypt
// through a session Close is tearing down.
//
// This one drives the real method and observes the backend's own counter from
// inside the bus call, so the lease under test is the one production takes.
func TestSendRequestHoldsALeaseForItsRoundTrip(t *testing.T) {
	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	parked := newBlockingReceiveTransport()
	observer := &leaseObservingTransport{
		blockingReceiveTransport: parked,
		inFlight:                 make(chan int, 1),
	}

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, observer)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	observer.backend = backend
	backend.connected.Store(true)

	backend.mu.Lock()
	backend.session = handshakedResponder(t)
	backend.mu.Unlock()

	go func() {
		_, _ = backend.SendRequest(context.Background(), pairing.NewRequest("probe", nil))
	}()

	select {
	case n := <-observer.inFlight:
		if n < 1 {
			t.Fatalf("SendRequest reached the bus with %d operations counted in "+
				"flight; it is not holding a session lease, so Close is free to "+
				"destroy the key it is encrypting through", n)
		}
	case <-time.After(testWait):
		t.Fatal("SendRequest never reached the transport")
	}

	_ = parked.Close()
	_ = backend.Close()
}
