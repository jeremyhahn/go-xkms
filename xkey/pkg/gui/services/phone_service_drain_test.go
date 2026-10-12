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

package services

import (
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-enclave"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// newLeasedConnection wires a PhoneService with a live active connection and
// takes one lease against it, returning the key it published and the release
// that retires the lease.
func newLeasedConnection(t *testing.T) (*PhoneService, *pairing.StaticKey, func()) {
	t.Helper()

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: key,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("NewNoiseSession: %v", err)
	}

	svc := NewPhoneService()
	svc.connMu.Lock()
	svc.activeTransport = &phone.BLETransport{}
	svc.activeSession = session
	svc.activeStaticKey = key
	svc.connMu.Unlock()

	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}
	return svc, key, release
}

// teardown runs closeActiveConnectionLocked the way its callers do, and
// reports whether it returned inside the window.
func teardown(t *testing.T, svc *PhoneService, within time.Duration) bool {
	t.Helper()

	done := make(chan struct{})
	go func() {
		svc.connMu.Lock()
		svc.closeActiveConnectionLocked()
		svc.connMu.Unlock()
		close(done)
	}()

	select {
	case <-done:
		return true
	case <-time.After(within):
		return false
	}
}

// destroyed reports whether a StaticKey has had its protected pages released.
// Borrowing a destroyed key's private scalar fails with
// enclave.ErrEnclaveDestroyed, which is the observable difference without
// reading freed memory.
func destroyed(key *pairing.StaticKey) bool {
	err := pairing.WithPrivateKey(key, func([]byte) error { return nil })
	return errors.Is(err, enclave.ErrEnclaveDestroyed)
}

// TestCloseActiveConnection_BoundsTheDrain covers the hang this branch
// introduced into the GUI's teardown path. An attestation holds its lease
// across a BLE round trip with a handset that may simply never answer, and
// the wait for it used to be unconditional — an application that could not
// close because a phone went out of range.
func TestCloseActiveConnection_BoundsTheDrain(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 100 * time.Millisecond
	t.Cleanup(func() { connShutdownTimeout = original })

	svc, key, release := newLeasedConnection(t)

	if !teardown(t, svc, 5*time.Second) {
		t.Fatal("teardown never returned: the lease drain is still unbounded")
	}

	// Bounding the wait must not license freeing the key: the leaseholder is
	// still reading the session those pages back.
	if destroyed(key) {
		t.Fatal("teardown destroyed the static key while an operation held the connection")
	}

	release()
	key.Destroy()
}

// TestCloseActiveConnection_DestroysTheKeyOnACleanDrain is the other half,
// and it is what stops the retention above from being unconditional.
func TestCloseActiveConnection_DestroysTheKeyOnACleanDrain(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 5 * time.Second
	t.Cleanup(func() { connShutdownTimeout = original })

	svc, key, release := newLeasedConnection(t)

	go func() {
		// Wait for teardown to actually park in the drain instead of
		// sleeping a fixed duration, so this proves teardown genuinely
		// waits for the release rather than returning early by luck.
		awaitDrain(t, svc)
		release()
	}()

	if !teardown(t, svc, 5*time.Second) {
		t.Fatal("teardown never returned after the lease was released")
	}

	if !destroyed(key) {
		t.Fatal("teardown left the static key resident after a clean drain")
	}
}

// TestCloseActiveConnection_DoesNotDestroyANewGeneration covers the race the
// bounded drain opened up.
//
// Drain.Wait releases connMu — that is what lets leaseholders reach their
// release — so a concurrent Connect can acquire the lock during the wait and
// publish a new transport, session and protected key. Teardown code that
// read s.activeStaticKey AFTER the wait would then destroy the new
// generation's key while its session was live.
//
// The test publishes a second generation from inside the drain window, which
// is exactly what a user reconnecting during a slow disconnect does.
func TestCloseActiveConnection_DoesNotDestroyANewGeneration(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 2 * time.Second
	t.Cleanup(func() { connShutdownTimeout = original })

	svc, oldKey, release := newLeasedConnection(t)

	newKey, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	newSession, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
		LocalStaticKey: newKey,
		IsInitiator:    true,
	})
	if err != nil {
		t.Fatalf("NewNoiseSession: %v", err)
	}

	// Publish the new generation while teardown is parked in the drain, then
	// let the old lease go so the drain completes. awaitDrain proves teardown
	// has cleared the slot and is parked in Drain.Wait -- the exact window a
	// Connect can publish into -- rather than betting a fixed sleep lands in
	// it.
	go func() {
		awaitDrain(t, svc)
		svc.connMu.Lock()
		svc.activeTransport = &phone.BLETransport{}
		svc.activeSession = newSession
		svc.activeStaticKey = newKey
		svc.connMu.Unlock()

		release()
	}()

	if !teardown(t, svc, 5*time.Second) {
		t.Fatal("teardown never returned")
	}

	if destroyed(newKey) {
		t.Fatal("teardown destroyed the key belonging to the connection that replaced it")
	}
	if !destroyed(oldKey) {
		t.Fatal("teardown left its own generation's key resident after a clean drain")
	}

	svc.connMu.Lock()
	stillPublished := svc.activeStaticKey == newKey && svc.activeSession == newSession
	svc.connMu.Unlock()
	if !stillPublished {
		t.Fatal("teardown cleared the connection that replaced it")
	}

	newKey.Destroy()
}
