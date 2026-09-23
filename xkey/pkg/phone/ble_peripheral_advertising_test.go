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
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
)

// probeAdvertiser records what the peripheral's lifecycle looked like from
// inside adv.Start and adv.Stop. Bringing a real advertisement up needs a
// Bluetooth adapter, which CI does not have, so the advertiser interface is
// what makes these two moments observable at all.
type probeAdvertiser struct {
	p *BLEPeripheral

	// startErr and stopErr are what the controller answers.
	startErr error
	stopErr  error

	// lockHeldDuringStart is whether lifeMu was held while advertising was
	// being raised, and publishedDuringStart whether the handle was already
	// installed. Both are read from inside Start, which runs on the caller's
	// goroutine — the one holding the lock — so reading p.adv here is safe.
	lockHeldDuringStart  bool
	publishedDuringStart bool

	// startCalls and stopCalls count what the controller was actually asked to
	// do. Asserting on the handle alone cannot tell "never advertised" from
	// "advertised and then rolled back", which are different peripherals as far
	// as anything within radio range is concerned.
	startCalls int
	stopCalls  int

	// keyDestroyedAtStop is whether the peripheral had already freed its
	// protected static key by the time it took advertising down.
	keyDestroyedAtStop bool
}

func (a *probeAdvertiser) Start() error {
	a.startCalls++

	// TryLock succeeds only if nobody holds lifeMu. A success here therefore
	// means advertising is being raised OUTSIDE the lifecycle lock, which is
	// the window a Stop can land in.
	if a.p.lifeMu.TryLock() {
		a.p.lifeMu.Unlock()
	} else {
		a.lockHeldDuringStart = true
	}
	a.publishedDuringStart = a.p.adv != nil

	return a.startErr
}

func (a *probeAdvertiser) Stop() error {
	a.stopCalls++
	if key := a.p.generatedStaticKey; key != nil {
		a.keyDestroyedAtStop = len(key.Private) == 0
	}
	return a.stopErr
}

// TestStartRaisesAdvertisingUnderTheSameLockThatPublishesIt covers the window
// the earlier fix left open.
//
// Publishing the advertisement under lifeMu gave Stop a handle to take down,
// but advertising was still RAISED before that publication and outside the
// lock. A Stop landing in between saw no advertisement, concluded there was
// nothing to take down, destroyed the static key and returned success — while
// Start went on to bring advertising up for a service backed by freed pages,
// taking it down again only once it noticed the closed flag.
//
// The two are one step now, so there is no in-between to land in. This asserts
// that directly: at the moment the controller is asked to advertise, the
// lifecycle lock is held and the handle is already installed.
func TestStartRaisesAdvertisingUnderTheSameLockThatPublishesIt(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	probe := &probeAdvertiser{p: p}

	if err := p.publishAdvertisement(probe); err != nil {
		t.Fatalf("publishAdvertisement: %v", err)
	}

	if !probe.lockHeldDuringStart {
		t.Fatal("advertising was raised without lifeMu held: a Stop in that " +
			"window finds no advertisement to take down and destroys the " +
			"static key while the peripheral goes on advertising")
	}
	if !probe.publishedDuringStart {
		t.Fatal("advertising was raised before the handle was published: Stop " +
			"cannot take down an advertisement it cannot see")
	}

	p.lifeMu.Lock()
	published := p.adv == advertiser(probe)
	p.lifeMu.Unlock()
	if !published {
		t.Fatal("the advertisement was not retained after a successful start")
	}
}

// TestStartRefusesAfterStopAndLeavesNothingAdvertising is the closed-flag half:
// a Start that arrives after Stop must not raise advertising at all, because
// the key that backs the advertised service has already been released.
func TestStartRefusesAfterStopAndLeavesNothingAdvertising(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop on an unstarted peripheral: %v", err)
	}

	probe := &probeAdvertiser{p: p}
	if err := p.publishAdvertisement(probe); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("publishAdvertisement after Stop returned %v, want ErrBackendClosed", err)
	}

	if probe.startCalls != 0 {
		t.Fatalf("a Start arriving after Stop asked the controller to advertise "+
			"%d time(s); it must never advertise in the first place, and a "+
			"cleared handle cannot tell that apart from advertising briefly "+
			"and rolling back", probe.startCalls)
	}
	if probe.stopCalls != 0 {
		t.Fatal("a Start arriving after Stop raised advertising and then took it back down")
	}

	p.lifeMu.Lock()
	stale := p.adv
	p.lifeMu.Unlock()
	if stale != nil {
		t.Fatal("a refused Start left an advertisement handle on a stopped peripheral")
	}
}

// TestPublishAdvertisementKeepsTheHandleWhenTheControllerRefuses covers the
// half of a failed raise that a cleared pointer cannot express.
//
// A Start error says the raise did not COMPLETE, not that nothing was
// registered: on Linux the advertisement is registered with BlueZ first and
// later steps of the same call can still fail. Rolling the handle back on that
// error therefore drops a possibly-live advertisement, after which Stop has
// nothing to take down and reports success while the peripheral may still be
// discoverable. The handle stays, and Stop reports whether taking it down
// worked.
func TestPublishAdvertisementKeepsTheHandleWhenTheControllerRefuses(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())
	probe := &probeAdvertiser{p: p, startErr: errors.New("controller refused")}

	if err := p.publishAdvertisement(probe); !errors.Is(err, ErrPeripheralStartFailed) {
		t.Fatalf("publishAdvertisement returned %v, want ErrPeripheralStartFailed", err)
	}
	if probe.startCalls != 1 {
		t.Fatalf("the controller was asked to advertise %d time(s), want 1", probe.startCalls)
	}

	p.lifeMu.Lock()
	retained := p.adv == advertiser(probe)
	p.lifeMu.Unlock()
	if !retained {
		t.Fatal("a raise that failed part-way dropped its handle: Stop now has " +
			"nothing to take down and will report success over an " +
			"advertisement that may still be up")
	}

	// And Stop does take it down.
	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if probe.stopCalls != 1 {
		t.Fatalf("Stop called adv.Stop %d time(s) on a retained handle, want 1", probe.stopCalls)
	}
}

// TestASecondStartIsRefusedRatherThanOverwritingTheHandle covers the clobber.
//
// The adapter hands out a cached advertisement, so a second Start operates on
// the SAME object: it fails with an already-started error, and a publication
// step that rolled the handle back on failure would drop the first call's live
// advertisement. Stop would then find nothing and report success while the
// peripheral was still discoverable.
func TestASecondStartIsRefusedRatherThanOverwritingTheHandle(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	first := &probeAdvertiser{p: p}
	if err := p.publishAdvertisement(first); err != nil {
		t.Fatalf("first publishAdvertisement: %v", err)
	}

	second := &probeAdvertiser{p: p, startErr: errors.New("advertisement already started")}
	if err := p.publishAdvertisement(second); !errors.Is(err, ErrPeripheralAlreadyRunning) {
		t.Fatalf("second publishAdvertisement returned %v, want ErrPeripheralAlreadyRunning", err)
	}
	if second.startCalls != 0 {
		t.Fatal("a refused second Start still asked the controller to advertise")
	}

	p.lifeMu.Lock()
	held := p.adv == advertiser(first)
	p.lifeMu.Unlock()
	if !held {
		t.Fatal("a second Start replaced the first call's live advertisement handle")
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if first.stopCalls != 1 {
		t.Fatalf("Stop took down the advertisement %d time(s), want 1", first.stopCalls)
	}
}

// TestStopReportsIncompleteWhenAdvertisingCannotBeStopped covers the swallowed
// failure — and the line between the two decisions Stop makes.
//
// Stop logged adv.Stop's error and carried on to report success, with the
// peripheral still, as far as anything knew, advertising. That is a fail-open:
// a peripheral that is still discoverable has not finished stopping.
//
// The KEY is a separate question, and coupling it to this one was wrong.
// Nothing but AcceptConnection and the session it builds reads those pages —
// an advertisement carries a service UUID and a device name — and `closed` is
// set under lifeMu before the drain, so a central arriving at a still-
// advertising peripheral cannot register. A confirmed join is therefore enough
// to free the key, and tying it to the advertisement instead retained
// protected pages for the life of the process every time an advertisement
// failed to come down.
func TestStopReportsIncompleteWhenAdvertisingCannotBeStopped(t *testing.T) {
	shrinkPeripheralTimeout(t, 5*time.Second)

	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	probe := &probeAdvertiser{p: p, stopErr: errors.New("controller refused")}
	p.lifeMu.Lock()
	p.generatedStaticKey = key
	p.adv = probe
	p.lifeMu.Unlock()

	if err := p.Stop(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("Stop returned %v when advertising could not be taken down, "+
			"want ErrShutdownIncomplete", err)
	}
	if probe.stopCalls != 1 {
		t.Fatalf("adv.Stop was called %d times, want 1", probe.stopCalls)
	}
	if len(key.Private) != 0 {
		t.Fatal("Stop retained the static key over an advertisement failure, " +
			"which no reader of those pages can be reached through")
	}
}

// TestStopRetainsTheKeyWhenAConnectionDidNotFinish is the other side of that
// line: the join, not the advertisement, is what licenses freeing the pages.
func TestStopRetainsTheKeyWhenAConnectionDidNotFinish(t *testing.T) {
	shrinkPeripheralTimeout(t, 100*time.Millisecond)

	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	probe := &probeAdvertiser{p: p}
	p.lifeMu.Lock()
	p.generatedStaticKey = key
	p.adv = probe
	p.lifeMu.Unlock()

	done := enterConnection(t, p)

	if err := p.Stop(); !errors.Is(err, ErrShutdownIncomplete) {
		t.Fatalf("Stop returned %v with a connection outstanding, want ErrShutdownIncomplete", err)
	}
	if probe.stopCalls != 1 {
		t.Fatalf("adv.Stop was called %d times, want 1", probe.stopCalls)
	}
	if len(key.Private) == 0 {
		t.Fatal("Stop destroyed the static key while a connection was still running")
	}

	done()
	key.Destroy()
}

// TestStopReleasesTheKeyWhenAdvertisingStops is what stops the retention above
// from being unconditional, and it pins the ordering: advertising comes down
// BEFORE the key is freed, never after.
func TestStopReleasesTheKeyWhenAdvertisingStops(t *testing.T) {
	shrinkPeripheralTimeout(t, 5*time.Second)

	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	key, err := pairing.GenerateStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	probe := &probeAdvertiser{p: p}
	p.lifeMu.Lock()
	p.generatedStaticKey = key
	p.adv = probe
	p.lifeMu.Unlock()

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop returned %v on a clean shutdown, want nil", err)
	}
	if probe.stopCalls != 1 {
		t.Fatalf("adv.Stop was called %d times, want 1", probe.stopCalls)
	}
	if probe.keyDestroyedAtStop {
		t.Fatal("the static key was already destroyed when advertising was " +
			"taken down: the peripheral advertised a service backed by freed pages")
	}
	if len(key.Private) != 0 {
		t.Fatal("Stop left the static key resident after a confirmed shutdown")
	}

	p.lifeMu.Lock()
	stale := p.adv
	p.lifeMu.Unlock()
	if stale != nil {
		t.Fatal("Stop left an advertisement handle behind")
	}
}

// TestStartRefusesBeforeItTouchesARunningPeripheral covers the ordering inside
// public Start.
//
// The already-running check used to live only in the publication step, which
// Start reaches LAST — after re-enabling the adapter, replacing the GATT
// characteristic handles and re-registering the service. So a repeated Start
// had already reconfigured a live peripheral by the time it discovered it
// should not have run, and usually reported a start failure rather than
// "already running".
//
// Start itself needs a Bluetooth adapter and cannot run in CI, so this exercises
// the guard Start now calls first, in both states.
//
// WHAT THIS DOES NOT COVER, stated rather than implied: deleting the call to
// reserveStart from Start does not fail this test, because the test takes the
// reservation directly. Covering the CALL SITE needs Start to run, which needs
// an adapter — the same limitation that keeps Start out of CI at all, and it
// rides with the advertisement state machine filed for v0.7.7. What is verified
// here is that the reservation is exclusive, is released, and answers correctly
// in every state Start can be in when it takes it.
func TestStartRefusesBeforeItTouchesARunningPeripheral(t *testing.T) {
	p := newTestPeripheral(t, &echoHandler{}, newCaptureWriter())

	// A first caller takes the reservation, and a second is refused while it is
	// held — before either has touched the adapter. A plain check would let
	// both through here, and they would then race over the adapter assignment,
	// the characteristic handles and the GATT registration.
	if err := p.reserveStart(); err != nil {
		t.Fatalf("reserveStart on an unstarted peripheral: %v", err)
	}
	if err := p.reserveStart(); !errors.Is(err, ErrPeripheralAlreadyRunning) {
		t.Fatalf("a concurrent Start returned %v, want ErrPeripheralAlreadyRunning: "+
			"both callers would go on to reconfigure the same peripheral", err)
	}
	p.releaseStart()

	// Released, so a retry after a failed start is allowed.
	if err := p.reserveStart(); err != nil {
		t.Fatalf("reserveStart after a released reservation: %v", err)
	}
	p.releaseStart()

	// And once an advertisement is published, a later Start is refused without
	// needing the reservation to still be held.
	if err := p.publishAdvertisement(&probeAdvertiser{p: p}); err != nil {
		t.Fatalf("publishAdvertisement: %v", err)
	}
	if err := p.reserveStart(); !errors.Is(err, ErrPeripheralAlreadyRunning) {
		t.Fatalf("reserveStart on a running peripheral returned %v, want "+
			"ErrPeripheralAlreadyRunning — Start would re-enable the adapter "+
			"and re-register the GATT service underneath it", err)
	}

	if err := p.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := p.reserveStart(); !errors.Is(err, ErrBackendClosed) {
		t.Fatalf("reserveStart after Stop returned %v, want ErrBackendClosed", err)
	}
}
