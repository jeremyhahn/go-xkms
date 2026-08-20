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

//go:build ble

package phone

import (
	"context"
	"errors"
	"testing"
	"time"
)

// shrinkPeripheralTimeout makes the connection join bounded by something a
// test can afford to wait for, and restores the production window after.
func shrinkPeripheralTimeout(t *testing.T, d time.Duration) {
	t.Helper()

	original := peripheralShutdownTimeout
	peripheralShutdownTimeout = d
	t.Cleanup(func() { peripheralShutdownTimeout = original })
}

// enterConnection registers on connWG the way AcceptConnection does — the
// closed check and the Add paired under lifeMu — and returns the function
// that retires it. Not retiring it is how this test holds Stop open.
func enterConnection(t *testing.T, p *BLEPeripheral) func() {
	t.Helper()

	p.lifeMu.Lock()
	if p.closed.Load() {
		p.lifeMu.Unlock()
		t.Fatal("peripheral already closed")
	}
	p.connWG.Add(1)
	p.lifeMu.Unlock()

	return func() { p.connWG.Done() }
}

// TestBLEPeripheral_StopBoundsTheConnectionJoin covers the hang this branch
// introduced into peripheral shutdown.
//
// AcceptConnection can be sitting inside a caller-supplied
// RequestHandler.HandleRequest, on a context this peripheral neither owns nor
// cancels. Waiting on connWG unconditionally therefore let a third party's
// stuck handler make Stop never return.
func TestBLEPeripheral_StopBoundsTheConnectionJoin(t *testing.T) {
	shrinkPeripheralTimeout(t, 100*time.Millisecond)

	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	p.lifeMu.Lock()
	p.generatedStaticKey = key
	p.lifeMu.Unlock()

	done := enterConnection(t, p)

	stopped := make(chan error, 1)
	go func() { stopped <- p.Stop() }()

	select {
	case err := <-stopped:
		if !errors.Is(err, ErrShutdownIncomplete) {
			t.Fatalf("Stop returned %v, want ErrShutdownIncomplete", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Stop never returned: the connection join is still unbounded")
	}

	// Bounding the join is not permission to free the key. The connection
	// still running may be encrypting through those pages.
	if len(key.Private) == 0 {
		t.Fatal("Stop destroyed the static key while a connection was still running")
	}

	done()
	key.Destroy()
}

// TestBLEPeripheral_StopDestroysTheKeyOnACleanJoin is the other half of the
// contract, and it is what stops the retention above from being
// unconditional: a peripheral with nothing in flight must still free its key
// and report success.
func TestBLEPeripheral_StopDestroysTheKeyOnACleanJoin(t *testing.T) {
	shrinkPeripheralTimeout(t, 5*time.Second)

	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}
	p.lifeMu.Lock()
	p.generatedStaticKey = key
	p.lifeMu.Unlock()

	done := enterConnection(t, p)
	go func() {
		time.Sleep(10 * time.Millisecond)
		done()
	}()

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop returned %v on a clean shutdown, want nil", err)
	}

	if len(key.Private) != 0 {
		t.Fatal("Stop left the static key resident after every connection finished")
	}
}

// TestAdoptedStaticKeyIsSeparateFromTheGeneratedOne pins a distinction that
// is easy to collapse and expensive to collapse.
//
// A key transferred with OwnsStaticKey is reused for every connection, like
// any supplied key. The key this peripheral generates when none is supplied
// is made PER CONNECTION, and whether that should instead be one stable
// per-peripheral identity is an open owner decision — per-connection keys
// give unlinkability between sessions, a stable key gives a peer something it
// can pin across reconnects.
//
// Storing an adopted key in generatedStaticKey would have answered that
// question by accident, because AcceptConnection would then find a key
// already present and stop regenerating. The two fields stay separate, and
// this test fails if they are merged.
func TestAdoptedStaticKeyIsSeparateFromTheGeneratedOne(t *testing.T) {
	key, err := GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	cfg := &BLEPeripheralConfig{LocalStaticKey: key, OwnsStaticKey: true}
	p, err := NewBLEPeripheral(cfg)
	if err != nil {
		t.Fatalf("NewBLEPeripheral: %v", err)
	}

	if p.adoptedStaticKey != key {
		t.Fatal("the transferred key was not adopted")
	}
	if p.generatedStaticKey != nil {
		t.Fatal("an adopted key was stored as a generated one; AcceptConnection " +
			"will stop generating per-connection keys and the open owner " +
			"decision has been answered by accident")
	}
	if cfg.LocalStaticKey != nil {
		t.Fatal("the config still holds a key whose ownership it transferred")
	}

	// And Stop releases it on the same terms as a generated key.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if len(key.Private) != 0 {
		t.Fatal("Stop left the adopted key resident after a clean join")
	}
}

// TestNoSuppliedKeyLeavesBothFieldsEmpty pins the precondition the
// per-connection generation depends on: with nothing supplied, construction
// must leave AcceptConnection with no key to find. The accept path itself
// needs a live transport and is not exercised here.
func TestNoSuppliedKeyLeavesBothFieldsEmpty(t *testing.T) {
	p, err := NewBLEPeripheral(&BLEPeripheralConfig{})
	if err != nil {
		t.Fatalf("NewBLEPeripheral: %v", err)
	}

	if p.adoptedStaticKey != nil || p.generatedStaticKey != nil {
		t.Fatal("construction pre-seeded a static key; per-connection generation is bypassed")
	}
}

// TestStopClearsTheAdvertisement pins the field discipline behind the
// Start/Stop race.
//
// The advertisement used to be a local inside Start, so Stop had no way to
// take it down: the peripheral kept advertising a service whose static key
// Stop had just destroyed, and a central connecting afterwards would read
// freed pages. Start now publishes it under lifeMu and Stop takes it down
// before draining.
//
// Bringing a real advertisement up needs a Bluetooth adapter, which CI does
// not have, so this asserts the ownership half — the part that made the race
// possible — rather than the radio behaviour.
func TestStopClearsTheAdvertisement(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	if p.adv != nil {
		t.Fatal("a peripheral that never started already holds an advertisement")
	}

	// Stop must be safe with nothing advertising, and must leave the field
	// empty so no later Stop can act on a stale handle.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop on an unstarted peripheral: %v", err)
	}
	if p.adv != nil {
		t.Fatal("Stop left an advertisement handle behind")
	}

	// And a Start arriving after Stop must refuse rather than advertise a key
	// that has been released.
	if err := p.Start(context.Background()); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("Start after Stop returned %v, want ErrBackendClosed", err)
	}
}
