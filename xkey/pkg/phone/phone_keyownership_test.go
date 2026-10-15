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

package phone

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/pkg/trust/bootstrap"
)

// testWait bounds every wait in this file. An unbounded receive turns a
// regression into a package-wide timeout that reads as infrastructure trouble
// rather than as this test failing on the thing it exists to check.
const testWait = 5 * time.Second

// destroyed reports whether a static key's protected pages have been released.
// Borrowing the private scalar of a destroyed key fails with
// enclave.ErrEnclaveDestroyed, which is the observable difference between a
// live key and a freed one.
func destroyed(key *bootstrap.NoiseStaticKey) bool {
	return key == nil || errors.Is(staticKeyAlive(key), enclave.ErrEnclaveDestroyed)
}

// TestNewPhoneKeyBackend_OwnedKeyDestroyedOnTrustFailure covers the ownership
// transfer OwnsStaticKey promises. The caller set the flag precisely because
// it kept no reference of its own, so a constructor that rejects the config
// must release the key: there is no backend to Close afterwards, and locked
// pages that nothing can free accumulate with every failed attempt.
func TestNewPhoneKeyBackend_OwnedKeyDestroyedOnTrustFailure(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()

	// No ExpectedRemoteStatic and TrustNewDevices false is the rejected
	// combination.
	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey: key,
		OwnsStaticKey:  true,
	}, local)
	if !errors.Is(err, ErrUntrustedDevice) {
		t.Fatalf("expected ErrUntrustedDevice, got backend=%v err=%v", backend, err)
	}
	if !destroyed(key) {
		t.Fatal("constructor took ownership of the key and then leaked it on the trust-validation path")
	}
}

// TestNewPhoneKeyBackend_BorrowedKeySurvivesFailure is the other half: without
// OwnsStaticKey the caller still holds the key, and destroying it would free
// pages the caller's next attempt is about to read.
func TestNewPhoneKeyBackend_BorrowedKeySurvivesFailure(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	defer key.Destroy()

	local, _ := newPipeTransports()

	_, err = NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey: key,
		// OwnsStaticKey deliberately left false.
	}, local)
	if !errors.Is(err, ErrUntrustedDevice) {
		t.Fatalf("expected ErrUntrustedDevice, got %v", err)
	}
	if destroyed(key) {
		t.Fatal("constructor destroyed a key it was only lent")
	}
}

// TestPhoneKeyBackend_CloseDestroysOwnedKey checks the success path: the
// backend accepted ownership at construction, so Close is where the key is
// released.
func TestPhoneKeyBackend_CloseDestroysOwnedKey(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	if destroyed(key) {
		t.Fatal("key destroyed by a successful construction")
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !destroyed(key) {
		t.Fatal("Close left the owned key resident")
	}

	// Close is idempotent and must not double-destroy.
	if err := backend.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
}

// TestWipeBytes clears the heap copy a decode leaves behind. LoadStaticKey
// copies the caller's slice into protected memory but cannot wipe it, so the
// caller's wipe is the only thing standing between a stored private key and
// garbage-collected memory that may be handed out again.
func TestWipeBytes(t *testing.T) {
	secret := []byte{1, 2, 3, 4, 5, 6, 7, 8}

	key, err := bootstrap.LoadNoiseStaticKey(append(make([]byte, 0, bootstrap.NoiseKeySize), bytes.Repeat([]byte{7}, bootstrap.NoiseKeySize)...))
	if err != nil {
		t.Fatalf("LoadStaticKey: %v", err)
	}
	defer key.Destroy()

	bootstrap.WipeNoiseBytes(secret)
	if !bytes.Equal(secret, make([]byte, len(secret))) {
		t.Fatalf("WipeBytes left data behind: %v", secret)
	}
}

// TestWipeBytes_Empty covers the degenerate inputs a caller reaches on an
// error path, where the decode produced nothing to wipe.
func TestWipeBytes_Empty(t *testing.T) {
	bootstrap.WipeNoiseBytes(nil)
	bootstrap.WipeNoiseBytes([]byte{})
}

// TestClose_WaitsForInFlightRequest covers the lease. SendRequest encrypts,
// does a bus round trip and decrypts outside b.mu; a Close landing in the
// middle used to clear the session and free the static key's protected pages
// while that request was still reading them.
func TestClose_WaitsForInFlightRequest(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
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

	// Take a lease directly: that is precisely the window SendRequest holds
	// open across its round trip, without needing a live phone to answer.
	_, _, release, ok := backend.acquireSession()
	if !ok {
		t.Fatal("acquireSession refused on a connected backend")
	}

	closeReturned := make(chan struct{})
	go func() {
		_ = backend.Close()
		close(closeReturned)
	}()

	// Close must not finish while the lease is outstanding.
	select {
	case <-closeReturned:
		t.Fatal("Close completed while an operation held a session lease")
	case <-time.After(50 * time.Millisecond):
	}

	if destroyed(key) {
		t.Fatal("key destroyed while an operation still held a lease on its session")
	}

	release()
	select {
	case <-closeReturned:
	case <-time.After(testWait):
		t.Fatal("Close never returned after the lease was released")
	}

	if !destroyed(key) {
		t.Fatal("Close left the owned key resident after the lease drained")
	}
}

// TestAcquireSession_RefusedAfterClose stops a leaseholder appearing after
// teardown has already drained and freed the key.
func TestAcquireSession_RefusedAfterClose(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
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

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, _, _, ok := backend.acquireSession(); ok {
		t.Fatal("acquireSession handed out a lease after Close")
	}
}

// blockingReceiveTransport models a real transport rather than the pipe mock:
// Receive parks until Close is called, and Close is what wakes it. That is the
// behaviour the shutdown ordering depends on, and the pipe mock does not have
// it — its Close leaves a parked Receive parked.
type blockingReceiveTransport struct {
	closeCh   chan struct{}
	closeOnce sync.Once

	enteredOnce sync.Once
	entered     chan struct{} // closed once Receive has actually parked
}

func newBlockingReceiveTransport() *blockingReceiveTransport {
	return &blockingReceiveTransport{
		closeCh: make(chan struct{}),
		entered: make(chan struct{}),
	}
}

func (b *blockingReceiveTransport) Connect(context.Context) error { return nil }
func (b *blockingReceiveTransport) IsConnected() bool             { return true }

func (b *blockingReceiveTransport) Close() error {
	b.closeOnce.Do(func() { close(b.closeCh) })
	return nil
}

func (b *blockingReceiveTransport) Send(context.Context, []byte) error { return nil }

func (b *blockingReceiveTransport) Receive(context.Context) ([]byte, error) {
	b.enteredOnce.Do(func() { close(b.entered) })
	<-b.closeCh
	return nil, ErrBackendClosed
}

func (b *blockingReceiveTransport) SendAndReceive(ctx context.Context, _ []byte) ([]byte, error) {
	return b.Receive(ctx)
}

// TestClose_UnblocksRouterBeforeJoining pins the shutdown ordering. receiveLoop
// parks in an uncancellable Receive, so signalling alone never wakes an idle
// one — closing the transport does. Joining before that close meant an idle
// backend burned the whole routerShutdownTimeout, concluded the loop was still
// running, and kept the owned key resident forever.
func TestClose_UnblocksRouterBeforeJoining(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	transport := newBlockingReceiveTransport()

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, transport)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}

	// Enabling routing is only valid after Connect, which is what sets this.
	backend.connected.Store(true)
	if err := backend.EnableBidirectional(nopRequestHandler{}); err != nil {
		t.Fatalf("EnableBidirectional: %v", err)
	}

	// Wait for the receive loop to actually park, so the test exercises the
	// idle case rather than racing startup.
	select {
	case <-transport.entered:
	case <-time.After(testWait):
		t.Fatal("receive loop never reached the transport read")
	}

	start := time.Now()
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	elapsed := time.Since(start)

	// The whole point: shutdown must not wait out the timeout it only needed
	// because it had not yet closed the transport.
	if elapsed >= routerShutdownTimeout {
		t.Fatalf("Close took %v, at or beyond the %v router timeout — it joined before unblocking the receive loop",
			elapsed, routerShutdownTimeout)
	}

	if !destroyed(key) {
		t.Fatal("Close left the owned key resident: the router join did not confirm shutdown")
	}
}

// nopRequestHandler satisfies the bidirectional router's handler contract
// without doing anything; this test never sends it a request.
type nopRequestHandler struct{}

func (nopRequestHandler) HandleRequest(_ context.Context, req *pairingproto.Request) *pairingproto.Response {
	return &pairingproto.Response{JSONRPC: "2.0", ID: req.ID}
}

// TestNewPhoneKeyBackend_NilKeyIsGeneratedAndOwned covers the config's
// documented "if nil, a key is generated" path. It used to be generated deep
// inside NewNoiseSession, where the backend never saw it and nothing could
// ever destroy it — the default configuration silently opted out of the whole
// protected-key lifecycle.
func TestNewPhoneKeyBackend_NilKeyIsGeneratedAndOwned(t *testing.T) {
	local, _ := newPipeTransports()

	cfg := &PhoneKeyBackendConfig{
		// LocalStaticKey deliberately nil.
		TrustNewDevices: true,
	}
	backend, err := NewPhoneKeyBackendWithTransport(cfg, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}

	// The backend holds a key it can release...
	generated := backend.ownedKey
	if generated == nil {
		t.Fatal("constructor did not resolve the nil key into an owned one")
	}

	// ...and the caller's config is untouched. A config is an input; writing
	// the generated key back into it would hand the next construction a key
	// this backend owns and will destroy.
	if cfg.LocalStaticKey != nil {
		t.Fatal("constructor wrote the generated key back into the caller's config")
	}
	if cfg.OwnsStaticKey {
		t.Fatal("constructor set OwnsStaticKey on the caller's config")
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !destroyed(generated) {
		t.Fatal("Close left the generated key resident")
	}
}

// TestNewPhoneKeyBackend_NilTransportReleasesOwnedKey covers a constructor exit
// that happens before the internal constructor's cleanup can run. Ownership
// transferred with the config, so rejecting the arguments still has to release
// the key — there is no backend to Close afterwards.
func TestNewPhoneKeyBackend_NilTransportReleasesOwnedKey(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	_, err = NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey: key,
		OwnsStaticKey:  true,
	}, nil)
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("expected ErrNotConnected, got %v", err)
	}
	if !destroyed(key) {
		t.Fatal("a rejected constructor stranded a key whose ownership it had accepted")
	}
}

// TestEnableBidirectional_IdempotentAndRefusedAfterClose pins both halves.
// Replacing the router unconditionally orphaned the first receive loop, so
// Close joined only the replacement and could free the key while the orphan
// still decrypted through it; calling after Close started a loop over a nil
// transport.
func TestEnableBidirectional_IdempotentAndRefusedAfterClose(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	transport := newBlockingReceiveTransport()
	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, transport)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}

	// Enabling is only valid after Connect, which is what sets connected.
	if err := backend.EnableBidirectional(nopRequestHandler{}); !errors.Is(err, ErrNotConnected) {
		t.Fatalf("EnableBidirectional before Connect: expected ErrNotConnected, got %v", err)
	}
	backend.connected.Store(true)

	if err := backend.EnableBidirectional(nopRequestHandler{}); err != nil {
		t.Fatalf("first EnableBidirectional: %v", err)
	}
	backend.mu.RLock()
	first := backend.router
	backend.mu.RUnlock()

	// Second call must keep the first router rather than orphaning it.
	if err := backend.EnableBidirectional(nopRequestHandler{}); err != nil {
		t.Fatalf("second EnableBidirectional: %v", err)
	}
	backend.mu.RLock()
	second := backend.router
	backend.mu.RUnlock()

	if first != second {
		t.Fatal("a second EnableBidirectional replaced the router, orphaning the first receive loop")
	}

	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !destroyed(key) {
		t.Fatal("Close left the owned key resident")
	}

	if err := backend.EnableBidirectional(nopRequestHandler{}); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("EnableBidirectional after Close: expected ErrBackendClosed, got %v", err)
	}
}

// TestReusedConfigDoesNotShareAnOwnedKey is the hazard a config write-back
// creates. A cfg is an input, and callers reasonably reuse one across
// constructions. If the constructor writes a generated key back into it, the
// second backend is handed a key the first one owns and will destroy — the
// exact use-after-free this whole change exists to eliminate, relocated into
// the caller's lap.
func TestReusedConfigDoesNotShareAnOwnedKey(t *testing.T) {
	t1, _ := newPipeTransports()
	t2, _ := newPipeTransports()

	// One config, reused. No key supplied, so each backend must generate and
	// own its own.
	cfg := &PhoneKeyBackendConfig{TrustNewDevices: true}

	first, err := NewPhoneKeyBackendWithTransport(cfg, t1)
	if err != nil {
		t.Fatalf("first construction: %v", err)
	}
	second, err := NewPhoneKeyBackendWithTransport(cfg, t2)
	if err != nil {
		t.Fatalf("second construction: %v", err)
	}

	firstKey, secondKey := first.ownedKey, second.ownedKey
	if firstKey == nil || secondKey == nil {
		t.Fatal("a generated key was not retained as owned")
	}
	if firstKey == secondKey {
		t.Fatal("both backends own the same key: the config was mutated and the key leaked into the next construction")
	}

	// Closing the first must not touch the second's key.
	if err := first.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if !destroyed(firstKey) {
		t.Fatal("first Close did not release its own key")
	}
	if destroyed(secondKey) {
		t.Fatal("first Close destroyed the second backend's key")
	}

	// The second is still usable, which is the property that matters.
	if _, _, release, ok := second.acquireSession(); !ok {
		t.Fatal("second backend unusable after the first was closed")
	} else {
		release()
	}

	if err := second.Close(); err != nil {
		t.Fatalf("second Close: %v", err)
	}
	if !destroyed(secondKey) {
		t.Fatal("second Close did not release its own key")
	}
}

// TestConnectAfterCloseIsRefused covers a nil dereference on a reachable
// reconnect path. Connect checked connected but never closed, while Close
// clears transport and session under the same lock — so a post-Close Connect
// fell through to performHandshake and dereferenced a nil session.
func TestConnectAfterCloseIsRefused(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		LocalStaticKey:  key,
		OwnsStaticKey:   true,
		TrustNewDevices: true,
	}, local)
	if err != nil {
		t.Fatalf("NewPhoneKeyBackendWithTransport: %v", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// The sequential case is caught by the check at the top of Connect, which
	// predates this change. The case that needs the in-lock guard is the race:
	// a Connect that passed that outer check BEFORE Close ran, and only then
	// acquired the mutex. Reproduce that state directly rather than trying to
	// win a scheduling race — clear closed so the outer check lets us through,
	// leaving the torn-down transport and session Close left behind.
	backend.closed.Store(false)

	// Must report, not dereference the nil session performHandshake reads.
	err = backend.Connect(context.Background())
	if err == nil {
		t.Fatal("Connect succeeded against a torn-down backend")
	}
	if !errors.Is(err, ErrNotConnected) {
		t.Fatalf("Connect racing Close: expected ErrNotConnected, got %v", err)
	}
}

// TestConstructorFailureDestroysTransferredKeyOnce checks that the outer and
// inner constructor guards do not both release the same transferred key. The
// underlying Destroy is documented idempotent, so this is about the ownership
// bookkeeping being right rather than about a crash: after the inner guard
// releases, the config must no longer name a key for anyone else to free.
func TestConstructorFailureDestroysTransferredKeyOnce(t *testing.T) {
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	local, _ := newPipeTransports()

	cfg := &PhoneKeyBackendConfig{
		LocalStaticKey: key,
		OwnsStaticKey:  true,
		// No ExpectedRemoteStatic and TrustNewDevices false: rejected.
	}
	if _, err := NewPhoneKeyBackendWithTransport(cfg, local); !errors.Is(err, ErrUntrustedDevice) {
		t.Fatalf("expected ErrUntrustedDevice, got %v", err)
	}

	if !destroyed(key) {
		t.Fatal("the rejected constructor did not release the transferred key")
	}
	if cfg.LocalStaticKey != nil {
		t.Fatal("the config still names a destroyed key, so another guard would free it again")
	}
}
