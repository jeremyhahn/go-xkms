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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// newGeneration builds the transport, session and protected key a completed
// Connect would hand to publishConnection.
func newGeneration(t *testing.T) (*phone.BLETransport, *pairing.NoiseSession, *pairing.StaticKey) {
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
	return &phone.BLETransport{}, session, key
}

// publishGeneration drives Connect's own publication step and returns the
// protected key backing the connection it installed.
func publishGeneration(t *testing.T, svc *PhoneService, device string) *pairing.StaticKey {
	t.Helper()

	transport, session, key := newGeneration(t)
	if err := svc.publishConnection(device, transport, session, key); err != nil {
		t.Fatalf("publishConnection(%q): %v", device, err)
	}
	svc.awaitNoticesDelivered()
	return key
}

// publishFromInsideTheDrain publishes a generation the way a Connect that is
// already inside the teardown's drain does.
//
// It calls publishConnectionLocked rather than publishConnection for one
// reason: publishConnection drains the previous generation first, and the lease
// this test holds open is the very thing that drain is waiting for — so the
// racing Connect would park behind the teardown instead of landing in its
// window. The publication step itself is the same code either way.
func publishFromInsideTheDrain(t *testing.T, svc *PhoneService, device string) *pairing.StaticKey {
	t.Helper()

	transport, session, key := newGeneration(t)

	svc.connMu.Lock()
	svc.publishConnectionLocked(device, transport, session, key)
	svc.connMu.Unlock()

	svc.awaitNoticesDelivered()
	return key
}

// awaitDrain blocks until teardown has detached its generation and parked in
// the lease drain, and fails the test if that never happens.
//
// It is a condition probe, not a sleep. closeActiveConnectionLocked clears the
// slot with connMu held and only releases the lock inside Drain.Wait, so an
// observer that takes connMu and finds the slot empty has proved teardown is
// in the drain — the exact window a Connect can publish into. Nothing here
// depends on how long any step takes.
func awaitDrain(t *testing.T, svc *PhoneService) {
	t.Helper()

	deadline := time.Now().Add(10 * time.Second)
	for {
		svc.connMu.Lock()
		empty := svc.activeTransport == nil && svc.activeSession == nil
		svc.connMu.Unlock()
		if empty {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("teardown never reached the lease drain")
		}
		time.Sleep(time.Millisecond)
	}
}

// TestTeardownLeavesAConnectionPublishedDuringItsDrainReportedConnected covers
// the status half of the publish-versus-teardown race.
//
// The lease drain releases connMu — that is what lets leaseholders reach their
// release — and a Connect can publish a whole new generation in that window.
// Teardown checked for that replacement and then wrote the disconnected status
// AFTER releasing the lock, so the write landed on top of a connection that was
// live: a running session, holding protected pages, that every status reader in
// the UI saw as down. Publication and status are one transition under connMu
// now, so there is no window to land in.
func TestTeardownLeavesAConnectionPublishedDuringItsDrainReportedConnected(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 5 * time.Second
	t.Cleanup(func() { connShutdownTimeout = original })

	svc := NewPhoneService()
	oldKey := publishGeneration(t, svc, "Pixel 9")

	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}

	torn := make(chan error, 1)
	go func() { torn <- svc.teardownActiveConnection("Pixel 9", "user_requested") }()

	// Publish the replacement from inside the drain window, then let the old
	// lease go so the drain completes.
	awaitDrain(t, svc)
	newKey := publishFromInsideTheDrain(t, svc, "Galaxy S25")
	release()

	select {
	case err := <-torn:
		if err != nil {
			t.Fatalf("teardown returned %v after a clean drain, want nil", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("teardown never returned")
	}

	if !svc.IsConnected() {
		t.Fatal("teardown reported the service disconnected while the connection " +
			"published during its drain is still live")
	}
	if name := svc.ConnectedDeviceName(); name != "Galaxy S25" {
		t.Fatalf("the service reports %q connected, want the device that replaced it", name)
	}

	svc.connMu.Lock()
	stillPublished := svc.activeStaticKey == newKey
	svc.connMu.Unlock()
	if !stillPublished {
		t.Fatal("teardown cleared the connection that replaced it")
	}
	if len(oldKey.Private) != 0 {
		t.Fatal("teardown left its own generation's key resident after a clean drain")
	}

	newKey.Destroy()
}

// teardownPublishRounds is how many times the test below races a teardown
// against a publication.
//
// It is a measured number, not a guessed one. Against the pre-fix shape — the
// status write moved back out of the critical section that decides it — a
// disagreement appears in 4.3% of rounds (857 of 20000), so five thousand
// rounds put the chance of the mutation surviving below any number worth
// writing down, and 20000 clean rounds were run five times over to establish
// that the fixed shape never produces one. The rounds are cheap because they
// need no key material: what is under test is the lock discipline around the
// slot and the status, and a nil key exercises it exactly as a real one does.
const teardownPublishRounds = 5000

// TestTeardownAndPublicationNeverDisagreeAboutTheConnection is the assertion
// the test above cannot make.
//
// The replacement check was always inside the lock; what was outside it was
// the status write that followed. The reachable window is therefore not the
// drain — it is the few instructions between teardown releasing connMu having
// decided "nothing replaced me" and teardown actually writing the status,
// during which a Connect blocked on that very lock publishes. Nothing can park
// a goroutine in a window that narrow, so this races the two operations with
// four more goroutines contending for the same lock — otherwise the unlocking
// goroutine simply barges back in and the window never opens — and asserts the
// invariant it violates: what the service reports and what the slot holds must
// agree.
func TestTeardownAndPublicationNeverDisagreeAboutTheConnection(t *testing.T) {
	for i := 0; i < teardownPublishRounds; i++ {
		svc := NewPhoneService()
		svc.connMu.Lock()
		svc.publishConnectionLocked("Pixel 9", &phone.BLETransport{}, nil, nil)
		svc.connMu.Unlock()

		start := make(chan struct{})
		stop := make(chan struct{})
		var operations, contenders sync.WaitGroup

		operations.Add(2)
		go func() {
			defer operations.Done()
			<-start
			svc.teardownActiveConnection("Pixel 9", "user_requested")
		}()
		go func() {
			defer operations.Done()
			<-start
			_ = svc.publishConnection("Galaxy S25", &phone.BLETransport{}, nil, nil)
		}()

		for c := 0; c < 4; c++ {
			contenders.Add(1)
			go func() {
				defer contenders.Done()
				<-start
				for {
					select {
					case <-stop:
						return
					default:
					}
					// Empty critical section on purpose: this goroutine exists to
					// contend for connMu, not to do work under it.
					svc.connMu.Lock()
					svc.connMu.Unlock() //nolint:staticcheck // SA2001: see above
				}
			}()
		}

		close(start)
		operations.Wait()
		close(stop)
		contenders.Wait()

		svc.connMu.Lock()
		live := svc.activeTransport != nil || svc.activeSession != nil
		reported := svc.connState.connected.Load()
		device := svc.activeDevice
		svc.connMu.Unlock()

		if live != reported {
			t.Fatalf("round %d: the slot holds a connection to %q (live=%v) but "+
				"the service reports connected=%v — a live session, holding "+
				"protected pages, that every status reader sees as down",
				i, device, live, reported)
		}
	}
}

// TestTeardownReportsDisconnectedWhenNothingReplacedIt is what stops the
// clause above from being unconditional: with an empty slot, teardown must
// still take the service down.
func TestTeardownReportsDisconnectedWhenNothingReplacedIt(t *testing.T) {
	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	var mu sync.Mutex
	var connected []bool
	svc.SetStatusChangeFunc(func(isConnected bool, _ string) {
		mu.Lock()
		defer mu.Unlock()
		connected = append(connected, isConnected)
	})

	if err := svc.teardownActiveConnection("Pixel 9", "user_requested"); err != nil {
		t.Fatalf("teardown returned %v on a clean drain, want nil", err)
	}
	if svc.IsConnected() || svc.ConnectedDeviceName() != "" {
		t.Fatal("teardown left the service reporting a connection it closed")
	}
	svc.awaitNoticesDelivered()
	mu.Lock()
	seen := append([]bool(nil), connected...)
	mu.Unlock()
	if len(seen) != 1 || seen[0] {
		t.Fatalf("status callback saw %v, want exactly one disconnected transition", seen)
	}
	if len(key.Private) != 0 {
		t.Fatal("teardown left the static key resident after a clean drain")
	}
}

// TestUnpairReportsTheRecordRemovalAndSurfacesRetentionInServiceState pins the
// contract Unpair was given.
//
// Unpair is asked to remove a pairing record. It either did that or it did
// not, and that is what its error reports. An incomplete drain is a different
// fact about a different thing — the protected key of the connection it tore
// down is still resident — and it belongs to the service's own state, where
// the UI reads status, not to the return value of the record removal. Reported
// through the return value it also lied by omission in the other direction: a
// caller retrying on error would find the record already gone.
func TestUnpairReportsTheRecordRemovalAndSurfacesRetentionInServiceState(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 100 * time.Millisecond
	t.Cleanup(func() { connShutdownTimeout = original })

	covSetupHomeWithDevicesConfig(t, &phoneConfig{
		Devices: []phoneConfigDevice{
			{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"},
			{Name: "Galaxy S25", Address: "AA:BB:CC:DD:EE:02"},
		},
		DefaultDevice: "Pixel 9",
	})

	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	// A lease nobody releases: the drain times out and the key is retained.
	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}
	t.Cleanup(func() {
		release()
		key.Destroy()
	})

	if err := svc.Unpair("Pixel 9"); err != nil {
		t.Fatalf("Unpair returned %v over a pairing record it removed successfully, "+
			"want nil: the incomplete drain belongs in service state, not here", err)
	}

	// The record is gone — the thing Unpair was asked to do.
	cfg, err := svc.loadConfig()
	if err != nil {
		t.Fatalf("loadConfig: %v", err)
	}
	for _, d := range cfg.Devices {
		if d.Name == "Pixel 9" {
			t.Fatal("Unpair returned success without removing the pairing record")
		}
	}

	// And the retention is visible where the UI reads status.
	if n := svc.RetainedKeyCount(); n != 1 {
		t.Fatalf("RetainedKeyCount is %d, want 1: an incomplete drain left no "+
			"observable record that the protected key is still resident", n)
	}
	if len(key.Private) == 0 {
		t.Fatal("the connection's static key was destroyed while an operation still held it")
	}
	if svc.IsConnected() {
		t.Fatal("the service still reports the unpaired device connected")
	}
}

// TestUnpairSucceedsAndRetainsNothingOnACleanDrain is the other half: with
// nothing in flight the key is destroyed and no retention is reported, so the
// count above cannot pass by being unconditional.
func TestUnpairSucceedsAndRetainsNothingOnACleanDrain(t *testing.T) {
	covSetupHomeWithDevicesConfig(t, &phoneConfig{
		Devices:       []phoneConfigDevice{{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"}},
		DefaultDevice: "Pixel 9",
	})

	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	if err := svc.Unpair("Pixel 9"); err != nil {
		t.Fatalf("Unpair: %v", err)
	}
	if n := svc.RetainedKeyCount(); n != 0 {
		t.Fatalf("RetainedKeyCount is %d after a clean drain, want 0", n)
	}
	if len(key.Private) != 0 {
		t.Fatal("Unpair left the connection's static key resident after a clean drain")
	}
}

// TestUnpairMarksTheDeviceForTheWholeOfItsTeardown covers the replacement
// Unpair used to leave standing.
//
// Tearing the connection down is not enough on its own, because the drain
// releases connMu: a Connect already past its own config load could publish
// into the slot while it was released, and Unpair — seeing a replacement —
// deliberately left it alone. The result was a live connection, with live
// protected pages, to a device whose pairing record had just been deleted.
//
// This is one half of the fix: the mark covers the entire window, checked from
// inside the drain, which is the only place the old code could be raced.
// TestPublishConnectionRefusesWhileTheDeviceIsBeingUnpaired is the other half —
// that the mark refuses a publication — and it uses the same predicate the
// publication step consults, so the two compose without either having to
// reproduce an interleaving that the fix itself makes unschedulable.
func TestUnpairMarksTheDeviceForTheWholeOfItsTeardown(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 5 * time.Second
	t.Cleanup(func() { connShutdownTimeout = original })

	covSetupHomeWithDevicesConfig(t, &phoneConfig{
		Devices:       []phoneConfigDevice{{Name: "Pixel 9", Address: "AA:BB:CC:DD:EE:01"}},
		DefaultDevice: "Pixel 9",
	})

	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}

	unpaired := make(chan error, 1)
	go func() { unpaired <- svc.Unpair("Pixel 9") }()

	// From inside the drain window — the exact point a racing Connect reaches
	// its publication step — ask the question the publication step asks.
	awaitDrain(t, svc)

	svc.connMu.Lock()
	markedDuringTheDrain := svc.unpairingLocked("Pixel 9")
	svc.connMu.Unlock()
	release()

	select {
	case err := <-unpaired:
		if err != nil {
			t.Fatalf("Unpair: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Unpair never returned")
	}

	if !markedDuringTheDrain {
		t.Fatal("the device was not marked unpairing while the teardown had " +
			"connMu released: a Connect publishing in that window installs a " +
			"connection that outlives the pairing record authorising it")
	}

	// The mark is released once Unpair is done, and nothing is left published.
	svc.connMu.Lock()
	stillMarked := svc.unpairing["Pixel 9"] > 0
	stillPublished := svc.activeTransport != nil || svc.activeSession != nil
	svc.connMu.Unlock()
	if stillMarked {
		t.Fatal("the unpairing mark outlived the Unpair that took it")
	}
	if stillPublished {
		t.Fatal("Unpair returned with a connection to the unpaired device still published")
	}
	if svc.IsConnected() {
		t.Fatal("the service reports a connection to the unpaired device")
	}

	key.Destroy()
}

// TestPublishConnectionRefusesWhileTheDeviceIsBeingUnpaired is the publication
// step's half of that contract on its own, without the concurrency: the mark
// alone is enough to refuse.
func TestPublishConnectionRefusesWhileTheDeviceIsBeingUnpaired(t *testing.T) {
	svc := NewPhoneService()
	svc.beginUnpair("Pixel 9")

	transport, session, key := newGeneration(t)
	t.Cleanup(key.Destroy)

	if err := svc.publishConnection("Pixel 9", transport, session, key); !errors.Is(err, ErrPhoneDeviceNotFound) {
		t.Fatalf("publishConnection returned %v while the device was being "+
			"unpaired, want ErrPhoneDeviceNotFound", err)
	}

	svc.connMu.Lock()
	published := svc.activeTransport != nil || svc.activeSession != nil || svc.activeStaticKey != nil
	svc.connMu.Unlock()
	if published {
		t.Fatal("a connection to a device being unpaired was published")
	}
	if svc.IsConnected() {
		t.Fatal("the service reports a connection to a device being unpaired")
	}

	// A different device is unaffected WHILE THE MARK IS STILL HELD, which is
	// what makes the refusal per-device rather than blanket. Releasing the mark
	// first would let `len(unpairing) > 0` pass this.
	other := publishGeneration(t, svc, "Galaxy S25")
	t.Cleanup(other.Destroy)
	if !svc.IsConnected() || svc.ConnectedDeviceName() != "Galaxy S25" {
		t.Fatal("the unpairing mark refused a device it does not name")
	}
}

// TestPublishConnectionRefusesAnUnpairThatBeganDuringItsDrain covers the SECOND
// refusal, and the state it has to settle.
//
// publishConnection drains the previous generation before installing the new
// one, and that drain releases connMu — so an Unpair for the device being
// connected can begin inside the window, after the first check passed. The
// second check is what catches it, and unlike the first it cannot simply
// return: the previous generation is already gone by then, so leaving the
// status alone would have the service reporting a connection that no longer
// exists. That is the exact divergence this contract exists to prevent, so the
// refusal settles the status and emits the transition.
func TestPublishConnectionRefusesAnUnpairThatBeganDuringItsDrain(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 5 * time.Second
	t.Cleanup(func() { connShutdownTimeout = original })

	svc := NewPhoneService()

	var mu sync.Mutex
	var transitions []bool
	svc.SetStatusChangeFunc(func(connected bool, _ string) {
		mu.Lock()
		defer mu.Unlock()
		transitions = append(transitions, connected)
	})

	previous := publishGeneration(t, svc, "Pixel 9")

	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}

	transport, session, arriving := newGeneration(t)
	t.Cleanup(arriving.Destroy)

	refused := make(chan error, 1)
	go func() { refused <- svc.publishConnection("Pixel 9", transport, session, arriving) }()

	// Inside the drain — the window the first check cannot see into — an Unpair
	// for this device begins.
	awaitDrain(t, svc)
	svc.beginUnpair("Pixel 9")
	t.Cleanup(func() { svc.endUnpair("Pixel 9") })
	release()

	select {
	case err := <-refused:
		if !errors.Is(err, ErrPhoneDeviceNotFound) {
			t.Fatalf("publishConnection returned %v after an unpair began during "+
				"its drain, want ErrPhoneDeviceNotFound", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("publishConnection never returned")
	}

	svc.connMu.Lock()
	published := svc.activeTransport != nil || svc.activeSession != nil || svc.activeStaticKey != nil
	svc.connMu.Unlock()
	if published {
		t.Fatal("a refused publication installed its connection anyway")
	}
	if svc.IsConnected() || svc.ConnectedDeviceName() != "" {
		t.Fatal("the refusal left the service reporting the connection its drain " +
			"had already torn down")
	}
	svc.awaitNoticesDelivered()
	mu.Lock()
	seen := append([]bool(nil), transitions...)
	mu.Unlock()
	if len(seen) != 2 || !seen[0] || seen[1] {
		t.Fatalf("status transitions were %v, want one connected then one "+
			"disconnected: the refusal must emit the transition it decided", seen)
	}
	if len(previous.Private) != 0 {
		t.Fatal("the previous generation's key was not released by a clean drain")
	}
}

// TestAStatusCallbackMayReEnterTheService covers the deadlock an earlier
// version of the delivery path had.
//
// Notifications are delivered outside connMu because the emitter and the
// status callback reach into the GUI, and a lock held across a frontend
// callback makes any re-entrant call a deadlock. Serializing delivery under a
// dedicated mutex to keep transitions ordered reintroduced exactly that: the
// callback re-entered, called the delivery path again, and blocked on a
// non-reentrant lock one layer over.
//
// The callback here does what a systray handler realistically does — reads
// status, then disconnects — from inside the notification itself. A hang is
// the failure this is looking for, so it runs on its own goroutine with a
// deadline rather than wedging the whole suite.
func TestAStatusCallbackMayReEnterTheService(t *testing.T) {
	svc := NewPhoneService()

	var reentered atomic.Bool
	svc.SetStatusChangeFunc(func(connected bool, deviceName string) {
		if !connected || !reentered.CompareAndSwap(false, true) {
			return
		}
		// Re-entrant, synchronous, on the delivering goroutine.
		_ = svc.IsConnected()
		_ = svc.Disconnect(deviceName)
	})

	key := make(chan *pairing.StaticKey, 1)
	go func() { key <- publishGeneration(t, svc, "Pixel 9") }()

	select {
	case k := <-key:
		t.Cleanup(k.Destroy)
	case <-time.After(10 * time.Second):
		t.Fatal("publishing deadlocked: a status callback that re-enters the " +
			"service blocked on a lock held across the callback")
	}

	if !reentered.Load() {
		t.Fatal("the status callback never ran, so nothing was re-entered")
	}
	if svc.IsConnected() {
		t.Fatal("the re-entrant Disconnect did not take effect")
	}
}

// TestAnOlderTransitionCannotOvertakeANewerOneAtEitherSink covers the hole a
// single delivery guard leaves.
//
// One guard claimed ahead of both callbacks orders the CLAIMS, not the calls.
// Notice N wins the claim, blocks inside the event emitter, N+1 claims and
// drives BOTH sinks to the final state, and then N resumes and hands the status
// callback its stale state — the newest transition delivered first and then
// overwritten by an older one, leaving the systray connected while connState
// says disconnected.
//
// The interleaving is forced rather than raced: the emitter for the first
// transition blocks until the second has been delivered in full.
func TestAnOlderTransitionCannotOvertakeANewerOneAtEitherSink(t *testing.T) {
	svc := NewPhoneService()

	var mu sync.Mutex
	var delivered []string

	olderParked := make(chan struct{})
	release := make(chan struct{})

	svc.SetEventEmitter(func(evt events.Event) {
		mu.Lock()
		delivered = append(delivered, "event:"+string(evt.Type))
		mu.Unlock()

		if evt.Type != events.EventPhoneConnected {
			return
		}
		close(olderParked)
		select {
		case <-release:
		case <-time.After(30 * time.Second):
			// Never silently: a regression that strands the older transition
			// here must show up as a wrong delivery order below, not as a
			// package timeout.
			mu.Lock()
			delivered = append(delivered, "event:STRANDED")
			mu.Unlock()
		}
	})
	svc.SetStatusChangeFunc(func(connected bool, _ string) {
		mu.Lock()
		delivered = append(delivered, fmt.Sprintf("status:%v", connected))
		mu.Unlock()
	})

	// The older transition. It parks inside the event sink, before the status
	// sink has seen anything.
	svc.connMu.Lock()
	svc.setConnectedLocked("Pixel 9")
	svc.connMu.Unlock()

	select {
	case <-olderParked:
	case <-time.After(10 * time.Second):
		t.Fatal("the first transition never reached the event sink")
	}

	// The newer transition, decided while the older is still inside its
	// callback.
	svc.connMu.Lock()
	svc.setDisconnectedLocked("Pixel 9", "user_requested")
	svc.connMu.Unlock()

	// THE NEGATIVE OBSERVATION, and the whole point. With one deliverer,
	// nothing can reach any sink while the older transition is still inside
	// its callback. A second deliverer — or delivery on the deciding goroutine
	// — would run the newer transition right here. The window is bounded
	// because "nothing happens" cannot be waited for positively; it is long
	// enough that a runnable goroutine would have been scheduled many times
	// over, and the mutation that reintroduces overtaking fails inside it.
	time.Sleep(overtakeObservationWindow)

	mu.Lock()
	duringPark := strings.Join(delivered, ",")
	mu.Unlock()
	if duringPark != "event:"+string(events.EventPhoneConnected) {
		t.Fatalf("while the older transition was still inside its callback the "+
			"sinks saw [%s] — something overtook it, so delivery is not ordered "+
			"and a stale status can land after a newer one", duringPark)
	}

	close(release)
	if !svc.awaitNoticesDelivered() {
		t.Fatal("delivery never finished")
	}

	mu.Lock()
	got := strings.Join(delivered, ",")
	mu.Unlock()

	want := strings.Join([]string{
		"event:" + string(events.EventPhoneConnected),
		"status:true",
		"event:" + string(events.EventPhoneDisconnected),
		"status:false",
	}, ",")
	if got != want {
		t.Fatalf("sinks saw [%s], want [%s]: both sinks must see every "+
			"transition, in the order they were decided", got, want)
	}
	if svc.IsConnected() {
		t.Fatal("connState disagrees with the transition that was delivered last")
	}
}

// overtakeObservationWindow is how long the test above watches for a delivery
// that must not happen. A negative property needs a bound; this one is set so
// the mutation it guards against (delivering on the deciding goroutine) fails
// well inside it.
var overtakeObservationWindow = 250 * time.Millisecond

// TestARefusedPublicationLeavesAnotherDevicesConnectionAlone covers the
// collateral damage the refusal order caused.
//
// publishConnection tore down whatever was connected FIRST and only then
// checked whether the requested device was being unpaired. So a Connect(A)
// that went stale during Unpair(A), arriving while B was connected, destroyed
// or retained B's protected key and cleared B's transport and session on its
// way to being refused — and left the service reporting B connected with
// nothing behind it. The refusal comes first now, because the teardown is
// destructive.
func TestARefusedPublicationLeavesAnotherDevicesConnectionAlone(t *testing.T) {
	svc := NewPhoneService()
	live := publishGeneration(t, svc, "Galaxy S25")
	t.Cleanup(live.Destroy)

	// A is being unpaired; the stale Connect(A) below is the one that must be
	// refused without touching B.
	svc.beginUnpair("Pixel 9")
	t.Cleanup(func() { svc.endUnpair("Pixel 9") })

	transport, session, stale := newGeneration(t)
	t.Cleanup(stale.Destroy)

	if err := svc.publishConnection("Pixel 9", transport, session, stale); !errors.Is(err, ErrPhoneDeviceNotFound) {
		t.Fatalf("publishConnection returned %v, want ErrPhoneDeviceNotFound", err)
	}

	svc.connMu.Lock()
	device := svc.activeDevice
	stillLive := svc.activeTransport != nil && svc.activeSession != nil && svc.activeStaticKey == live
	svc.connMu.Unlock()

	if !stillLive || device != "Galaxy S25" {
		t.Fatalf("a refused publication tore down the connection to %q: "+
			"activeDevice=%q still_published=%v", "Galaxy S25", device, stillLive)
	}
	if len(live.Private) == 0 {
		t.Fatal("a refused publication destroyed another device's protected key")
	}
	if !svc.IsConnected() || svc.ConnectedDeviceName() != "Galaxy S25" {
		t.Fatal("a refused publication left the service reporting a connection it had torn down")
	}
	if n := svc.RetainedKeyCount(); n != 0 {
		t.Fatalf("RetainedKeyCount is %d after a refusal that should not have "+
			"touched the published connection, want 0", n)
	}
}

// TestATimedOutDrainOverAnEmptySlotRecordsNoRetainedKey keeps the count the UI
// reads honest.
//
// The drain counts leases across generations, so it can time out on a slot
// that was already empty — a Connect landing behind a Disconnect that is still
// waiting for someone else's lease. There is no key in that case, and
// recording the nil as retained made RetainedKeyCount report key material that
// never existed. The drain is still incomplete and still says so; what it must
// not do is invent a protected page.
func TestATimedOutDrainOverAnEmptySlotRecordsNoRetainedKey(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 50 * time.Millisecond
	t.Cleanup(func() { connShutdownTimeout = original })

	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}
	t.Cleanup(func() {
		release()
		key.Destroy()
	})

	// First teardown: a real key, retained because the lease is outstanding.
	if err := svc.teardownActiveConnection("Pixel 9", "user_requested"); !errors.Is(err, ErrPhoneShutdownIncomplete) {
		t.Fatalf("teardown returned %v with a lease outstanding, want ErrPhoneShutdownIncomplete", err)
	}
	if n := svc.RetainedKeyCount(); n != 1 {
		t.Fatalf("RetainedKeyCount is %d after retaining a key, want 1", n)
	}

	// Second: the slot is empty, the lease is still out, so the drain times out
	// again — with no key to retain.
	transport, session, unpublished := newGeneration(t)
	t.Cleanup(unpublished.Destroy)
	if err := svc.publishConnection("Galaxy S25", transport, session, unpublished); err != nil {
		t.Fatalf("publishConnection over an empty slot: %v", err)
	}
	if n := svc.RetainedKeyCount(); n != 1 {
		t.Fatalf("RetainedKeyCount is %d, want 1: a drain that timed out over an "+
			"empty slot recorded key material that never existed", n)
	}
}

// TestAutoAttestPropagatesTheTeardownItForces covers the fourth caller of
// closeActiveConnectionLocked, and the last one that discarded its result.
//
// A policy violation tears down the connection the attestation was running
// over. Whether that teardown drained is exactly as consequential here as on
// the disconnect path — an incomplete one means the connection's protected key
// is still resident — and autoAttest dropped it on the floor, so Connect
// returned success over it.
func TestAutoAttestPropagatesTheTeardownItForces(t *testing.T) {
	original := connShutdownTimeout
	connShutdownTimeout = 100 * time.Millisecond
	t.Cleanup(func() { connShutdownTimeout = original })

	svc := NewPhoneService()
	key := publishGeneration(t, svc, "Pixel 9")

	// A lease nobody releases, so the teardown the violation forces cannot
	// confirm its drain.
	_, _, release, ok := svc.acquireActiveConnection()
	if !ok {
		t.Fatal("acquireActiveConnection refused a service with a live connection")
	}
	t.Cleanup(func() {
		release()
		key.Destroy()
	})

	device := &phoneConfigDevice{
		Name:              "Pixel 9",
		Address:           "AA:BB:CC:DD:EE:01",
		AttestationPolicy: &pairing.PairedDeviceAttestationPolicy{Enabled: true, DeviceLocked: true},
	}

	err := svc.autoAttest(&phoneConfig{Devices: []phoneConfigDevice{*device}}, device, "Pixel 9")
	if !errors.Is(err, ErrPhoneShutdownIncomplete) {
		t.Fatalf("autoAttest returned %v over a teardown it could not confirm "+
			"drained, want ErrPhoneShutdownIncomplete", err)
	}
	if n := svc.RetainedKeyCount(); n != 1 {
		t.Fatalf("RetainedKeyCount is %d, want 1", n)
	}
}
