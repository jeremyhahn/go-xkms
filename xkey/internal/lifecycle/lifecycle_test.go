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

package lifecycle

import (
	"runtime"
	"sync"
	"testing"
	"time"
)

// short is the window these tests give a bounded wait. Long enough that a
// drain which is going to complete has completed, short enough that a test
// asserting the timeout branch does not dominate the suite.
const short = 100 * time.Millisecond

func TestJoiner_ReturnsTrueWhenTheGroupDrains(t *testing.T) {
	var wg sync.WaitGroup
	var j Joiner
	wg.Add(1)

	// No wait needed before Done: Join blocks on the WaitGroup itself (up to
	// its own minute-long bound below), so the exact moment this goroutine
	// runs does not affect the assertion.
	go func() {
		wg.Done()
	}()

	if !j.Join(&wg, time.Minute) {
		t.Fatal("Join reported a timeout on a group that drained")
	}
}

// TestJoiner_ReturnsFalseAndDoesNotHang is the whole reason this package
// exists. A goroutine that never finishes must not make the join never
// return — the caller retains protected memory instead.
func TestJoiner_ReturnsFalseAndDoesNotHang(t *testing.T) {
	var wg sync.WaitGroup
	var j Joiner
	wg.Add(1)

	stuck := make(chan struct{})
	go func() {
		<-stuck
		wg.Done()
	}()
	defer close(stuck)

	start := time.Now()
	if j.Join(&wg, short) {
		t.Fatal("Join reported success while a goroutine was still running")
	}
	if elapsed := time.Since(start); elapsed < short {
		t.Fatalf("returned after %v, before the %v window elapsed", elapsed, short)
	}
}

// TestJoiner_RepeatedTimeoutsStartOneWaiter pins why Joiner is a type rather
// than a function. Joins are public and callers retry; a waiter spawned per
// call would add a permanently blocked goroutine on every retry against a
// goroutine that is itself stuck forever, turning a bounded wait into an
// unbounded leak.
func TestJoiner_RepeatedTimeoutsStartOneWaiter(t *testing.T) {
	var wg sync.WaitGroup
	var j Joiner
	wg.Add(1)

	stuck := make(chan struct{})
	go func() {
		<-stuck
		wg.Done()
	}()

	before := runtime.NumGoroutine()
	for i := 0; i < 20; i++ {
		if j.Join(&wg, time.Millisecond) {
			t.Fatalf("round %d: Join reported success while the group was held", i)
		}
	}
	growth := runtime.NumGoroutine() - before

	// One waiter for the Joiner, and nothing per call. Allow a little slack
	// for scheduler noise, but 20 calls must not mean 20 goroutines.
	if growth > 3 {
		t.Fatalf("20 timed-out joins added %d goroutines; expected one waiter", growth)
	}

	close(stuck)
	if !j.Join(&wg, time.Minute) {
		t.Fatal("the single waiter did not observe the group draining")
	}
}

func TestDrain_WaitReturnsImmediatelyWhenEmpty(t *testing.T) {
	var mu sync.Mutex
	var d Drain

	mu.Lock()
	defer mu.Unlock()

	if !d.Wait(&mu, time.Nanosecond) {
		t.Fatal("an empty Drain reported a timeout")
	}
}

func TestDrain_WaitReturnsWhenTheLastOperationRetires(t *testing.T) {
	var mu sync.Mutex
	var d Drain

	mu.Lock()
	d.Add()
	d.Add()

	// No wait needed before Done: Wait blocks on the Drain itself (up to
	// its own minute-long bound below), so the exact moment this goroutine
	// runs does not affect the assertion.
	go func() {
		mu.Lock()
		d.Done()
		d.Done()
		mu.Unlock()
	}()

	drained := d.Wait(&mu, time.Minute)
	inFlight := d.InFlight()
	mu.Unlock()

	if !drained {
		t.Fatal("Wait reported a timeout on a Drain that emptied")
	}
	if inFlight != 0 {
		t.Fatalf("InFlight = %d after a successful drain, want 0", inFlight)
	}
}

// TestDrain_WaitTimesOutAndReportsWhatIsLeft covers the branch every caller
// keys its retain-or-destroy decision off. Getting false here is what stops a
// destroyer freeing pages an operation is still reading.
func TestDrain_WaitTimesOutAndReportsWhatIsLeft(t *testing.T) {
	var mu sync.Mutex
	var d Drain

	mu.Lock()
	d.Add()

	start := time.Now()
	drained := d.Wait(&mu, short)
	inFlight := d.InFlight()
	mu.Unlock()

	if drained {
		t.Fatal("Wait reported a drain while an operation was still counted")
	}
	if elapsed := time.Since(start); elapsed < short {
		t.Fatalf("returned after %v, before the %v window elapsed", elapsed, short)
	}
	if inFlight != 1 {
		t.Fatalf("InFlight = %d after the timeout, want the 1 that never retired", inFlight)
	}
}

// TestDrain_WaitReleasesTheMutex pins the property the whole design rests on:
// the operations that have to call Done need the caller's mutex, so a Wait
// that held it would deadlock rather than time out. Failing this test looks
// like the timeout test above passing, which is why it is asserted directly.
func TestDrain_WaitReleasesTheMutex(t *testing.T) {
	var mu sync.Mutex
	var d Drain

	mu.Lock()
	d.Add()

	acquired := make(chan struct{})
	go func() {
		mu.Lock()
		close(acquired)
		d.Done()
		mu.Unlock()
	}()

	drained := d.Wait(&mu, time.Minute)
	mu.Unlock()

	if !drained {
		t.Fatal("Wait timed out; the mutex was never released to the operation")
	}
	select {
	case <-acquired:
	default:
		t.Fatal("the operation never acquired the mutex during Wait")
	}
}

// TestDrain_WaitIsUsableTwice covers a component that drains, takes new work,
// and drains again — the idle channel has to be recreated rather than reused
// after it is closed.
func TestDrain_WaitIsUsableTwice(t *testing.T) {
	var mu sync.Mutex
	var d Drain

	for i := 0; i < 2; i++ {
		mu.Lock()
		d.Add()

		go func() {
			mu.Lock()
			d.Done()
			mu.Unlock()
		}()

		drained := d.Wait(&mu, time.Minute)
		mu.Unlock()

		if !drained {
			t.Fatalf("round %d: Wait timed out on a Drain that emptied", i)
		}
	}
}

// TestDrain_DoneWithoutAddPanics prefers a panic at the mistake over a
// counter that wraps negative and hangs every future Wait forever — a
// shutdown bug that would surface far from its cause.
func TestDrain_DoneWithoutAddPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("Done on an empty Drain did not panic")
		}
	}()

	var d Drain
	d.Done()
}
