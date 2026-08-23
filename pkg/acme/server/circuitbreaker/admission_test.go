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

package circuitbreaker

import (
	"errors"
	"sync"
	"testing"
	"time"
)

// errProbeFailed trips the breaker in these tests.
var errProbeFailed = errors.New("probe failed")

// admissionTestBreaker returns a breaker whose transitions this file can drive
// deterministically:
//
//   - MaxFailures 1, so a single failure opens it;
//   - ResetTimeout 0, so the next call after opening moves it to half-open
//     without waiting on a clock;
//   - HalfOpenMaxRequests 1, so the admission limit is observable -- the
//     second concurrent probe must be refused;
//   - SuccessThreshold high, so successes never close it and the state stays
//     put while the test drives other things.
func admissionTestBreaker(name string) *CircuitBreaker {
	return New(&Config{
		Name:                name,
		MaxFailures:         1,
		ResetTimeout:        0,
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    1000,
	})
}

// startBlockedCall begins an Execute whose function blocks, and returns once
// that function is running -- i.e. once beforeRequest has admitted it. The
// returned func releases it and waits for Execute to return.
func startBlockedCall(cb *CircuitBreaker, result error) (release func()) {
	admitted := make(chan struct{})
	unblock := make(chan struct{})
	done := make(chan struct{})

	go func() {
		defer close(done)
		_ = cb.Execute(func() error {
			close(admitted)
			<-unblock
			return result
		})
	}()

	<-admitted
	return func() {
		close(unblock)
		<-done
	}
}

// TestAdmission_ClosedCallDoesNotReleaseAHalfOpenSlot is the regression test
// for the half-open admission limit being released by a call that never took a
// slot.
//
// The slot used to be released inside recordSuccess/recordFailure, on their
// StateHalfOpen branch, keyed on the state at COMPLETION. A call admitted while
// the breaker was closed, finishing after it had reached half-open, therefore
// decremented halfOpenRequests without ever having incremented it -- freeing
// the slot belonging to a probe that was still in flight.
//
// The limit exists to stop a herd of probes hitting a dependency the breaker
// has just judged to be failing, so this let exactly the wrong thing through at
// exactly the wrong moment.
func TestAdmission_ClosedCallDoesNotReleaseAHalfOpenSlot(t *testing.T) {
	cb := admissionTestBreaker("admission-slot")

	// A is admitted while the breaker is CLOSED, and stays in flight.
	releaseA := startBlockedCall(cb, nil)

	// Trip the breaker with a separate failing call.
	if err := cb.Execute(func() error { return errProbeFailed }); !errors.Is(err, errProbeFailed) {
		t.Fatalf("the tripping call returned %v, want errProbeFailed", err)
	}
	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %v after a failure at MaxFailures=1, want open", state)
	}

	// The next call moves the breaker to half-open and takes its only slot.
	// It stays in flight, so the slot stays held.
	releaseProbe := startBlockedCall(cb, nil)
	defer releaseProbe()

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %v after a call with ResetTimeout=0, want half-open", state)
	}

	// Now let A finish. It was admitted under closed and holds no slot.
	releaseA()

	// The probe still holds the only slot, so a second probe must be refused.
	ran := false
	err := cb.Execute(func() error { ran = true; return nil })

	if !errors.Is(err, ErrTooManyRequests) {
		t.Errorf("a second half-open probe returned %v, want ErrTooManyRequests: "+
			"the in-flight probe still holds the only slot", err)
	}
	if ran {
		t.Error("a second half-open probe ran while the only slot was held; the " +
			"closed-state call released a slot it never took")
	}
}

// TestAdmission_ClosedCallDoesNotUnderflowHalfOpenCount pins the same defect at
// its sharpest.
//
// halfOpenRequests is an atomic.Uint32. Decrementing it at zero does not clamp,
// it wraps to 4294967295 -- after which beforeRequest's `current >
// halfOpenMaxRequests` is false for the next 4 billion calls and the half-open
// limit admits everything until a transition resets the counter.
func TestAdmission_ClosedCallDoesNotUnderflowHalfOpenCount(t *testing.T) {
	cb := admissionTestBreaker("admission-underflow")

	// A is admitted while CLOSED and stays in flight.
	releaseA := startBlockedCall(cb, nil)

	if err := cb.Execute(func() error { return errProbeFailed }); !errors.Is(err, errProbeFailed) {
		t.Fatalf("the tripping call returned %v, want errProbeFailed", err)
	}

	// One completed probe moves the breaker to half-open and leaves the slot
	// count back at zero.
	if err := cb.Execute(func() error { return nil }); err != nil {
		t.Fatalf("the half-open probe returned %v, want nil", err)
	}
	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %v, want half-open", state)
	}
	if held := cb.halfOpenRequests.Load(); held != 0 {
		t.Fatalf("halfOpenRequests is %d after the probe completed, want 0", held)
	}

	// A now completes with the breaker half-open and the count already zero.
	releaseA()

	if held := cb.halfOpenRequests.Load(); held != 0 {
		t.Errorf("halfOpenRequests is %d after a closed-state call completed, want 0; "+
			"an atomic.Uint32 decremented at zero wraps to %d and disables the "+
			"half-open limit entirely", held, ^uint32(0))
	}
}

// TestAdmission_StaleCompletionChangesNothing pins the other half of the
// pairing, and it is the half I first got wrong.
//
// An earlier version of this test asserted that a call admitted while closed
// ALWAYS records against closed, even if the breaker had tripped meanwhile.
// That is attribution without a generation, and it is worse than the bug it
// replaced: see TestAdmission_StaleProbeSuccessCannotCloseAnOpenCircuit, where
// the same rule lets a late probe close a breaker moments after recovery
// failed.
//
// The correct rule is narrower. A completion is evidence about the window it
// was admitted into. If that window has closed -- any transition since -- the
// result is stale and changes nothing but the metrics.
func TestAdmission_StaleCompletionChangesNothing(t *testing.T) {
	cb := New(&Config{
		Name:                "admission-stale",
		MaxFailures:         1,
		ResetTimeout:        1 << 30, // Long: stay open rather than drifting.
		HalfOpenMaxRequests: 1,
		SuccessThreshold:    1000,
	})

	// A is admitted while CLOSED and stays in flight.
	releaseA := startBlockedCall(cb, nil)

	// Trip the breaker while A is still running. That is a transition, so A's
	// generation has ended.
	if err := cb.Execute(func() error { return errProbeFailed }); !errors.Is(err, errProbeFailed) {
		t.Fatalf("the tripping call returned %v, want errProbeFailed", err)
	}
	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %v, want open", state)
	}

	releaseA()

	if state := cb.State(); state != StateOpen {
		t.Errorf("breaker is %v after a stale success completed, want open: a call "+
			"admitted before the trip must not move a breaker it knows nothing about", state)
	}
	if _, successes := cb.Counts(); successes != 0 {
		t.Errorf("successCount is %d after a stale completion, want 0", successes)
	}
}

// TestAdmission_StaleProbeSuccessCannotCloseAnOpenCircuit is the fail-open
// regression test.
//
// With room for two half-open probes and a success threshold of one, admit A
// and B. A fails, which reopens the breaker. B then succeeds. Attributing B's
// result to its admitting state WITHOUT checking the generation transitions
// the open breaker straight back to closed -- declaring the dependency healthy
// on the strength of one probe, moments after another probe proved it was not,
// and skipping ResetTimeout entirely.
//
// The breaker must stay open: B's success belongs to a half-open window that A
// already ended.
func TestAdmission_StaleProbeSuccessCannotCloseAnOpenCircuit(t *testing.T) {
	cb := New(&Config{
		Name:                "admission-failopen",
		MaxFailures:         1,
		ResetTimeout:        0, // Reach half-open on the next call.
		HalfOpenMaxRequests: 2, // Room for two probes at once.
		SuccessThreshold:    1, // One success would close it.
	})

	// Trip it, then reach half-open with two concurrent probes.
	if err := cb.Execute(func() error { return errProbeFailed }); !errors.Is(err, errProbeFailed) {
		t.Fatalf("the tripping call returned %v, want errProbeFailed", err)
	}

	releaseA := startBlockedCall(cb, errProbeFailed) // probe A: will fail
	releaseB := startBlockedCall(cb, nil)            // probe B: will succeed

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %v with two probes admitted, want half-open", state)
	}

	// A fails first and reopens the breaker.
	releaseA()
	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %v after a probe failed, want open", state)
	}

	// B's success arrives late, against a generation that has ended.
	releaseB()

	if state := cb.State(); state != StateOpen {
		t.Errorf("breaker is %v after a stale probe success, want open: recovery had "+
			"just failed, and closing here skips ResetTimeout entirely", state)
	}
}

// TestAdmission_OldProbeCannotReleaseANewGenerationsSlot covers the other
// cross-generation hazard.
//
// transitionTo resets halfOpenRequests while probes may still be running. If
// release were keyed on ownership alone, a probe from an earlier half-open
// window would decrement the counter belonging to a later one -- freeing a
// slot held by a probe that is still in flight, exactly the failure the limit
// exists to prevent, one generation removed.
func TestAdmission_OldProbeCannotReleaseANewGenerationsSlot(t *testing.T) {
	cb := New(&Config{
		Name:                "admission-generation",
		MaxFailures:         1,
		ResetTimeout:        0,
		HalfOpenMaxRequests: 2,
		SuccessThreshold:    1000, // Never close; keep the window open.
	})

	if err := cb.Execute(func() error { return errProbeFailed }); !errors.Is(err, errProbeFailed) {
		t.Fatalf("the tripping call returned %v, want errProbeFailed", err)
	}

	// Half-open window 1: two probes, A will fail and end the window.
	releaseA := startBlockedCall(cb, errProbeFailed)
	releaseOld := startBlockedCall(cb, nil)

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %v, want half-open", state)
	}

	// A fails: back to open, counters reset. `releaseOld` is still in flight
	// and still believes it holds a slot.
	releaseA()
	if state := cb.State(); state != StateOpen {
		t.Fatalf("breaker is %v after the probe failed, want open", state)
	}

	// Half-open window 2 begins, and C takes one of its slots.
	releaseC := startBlockedCall(cb, nil)
	defer releaseC()

	if state := cb.State(); state != StateHalfOpen {
		t.Fatalf("breaker is %v, want a second half-open window", state)
	}
	held := cb.halfOpenRequests.Load()
	if held != 1 {
		t.Fatalf("halfOpenRequests is %d with one probe in the new window, want 1", held)
	}

	// The stale probe from window 1 now completes.
	releaseOld()

	if got := cb.halfOpenRequests.Load(); got != 1 {
		t.Errorf("halfOpenRequests is %d after a probe from the PREVIOUS half-open "+
			"window completed, want 1; it released a slot belonging to the current "+
			"window (or underflowed, in which case %d)", got, ^uint32(0))
	}
}

// snapshotStateAndGeneration reads the pair the way beforeRequest must: under
// cb.mu, so the two cannot come from different instants. Test-only; it exists
// to give the coherence test an oracle that is itself atomic.
func snapshotStateAndGeneration(cb *CircuitBreaker) (State, uint64) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	return State(cb.state.Load()), cb.generation.Load()
}

// TestAdmission_StateAndGenerationAreCoherent pins that beforeRequest cannot
// hand out an admission whose state belongs to one generation and whose
// generation number belongs to another.
//
// Reading the two independently is the trap, and both loads are individually
// correct: observe StateClosed, let a Closed->Open->HalfOpen sequence run in
// another goroutine, then read the generation, and the call carries
// {state: closed, generation: half-open}. That pair PASSES the staleness check
// at completion and is then settled with closed semantics inside a half-open
// window -- a probe failure increments the closed counter instead of
// reopening the circuit.
//
// The oracle is a concurrent poller taking the same pair under cb.mu. It will
// not observe every generation, and does not need to: any admission whose
// generation the poller DID see must agree with it. An incoherent pair cannot
// agree, because the poller never produces one.
//
// (An earlier version recorded the mapping from OnStateChange, which worked
// only while that callback ran under cb.mu. It no longer does -- user code
// must not run under the lock -- so the oracle moved here rather than
// silently becoming racy.)
func TestAdmission_StateAndGenerationAreCoherent(t *testing.T) {
	cb := New(&Config{
		Name:                "admission-coherence",
		MaxFailures:         1000, // never trip on its own
		ResetTimeout:        0,    // reach half-open on the next call
		HalfOpenMaxRequests: 4,
		SuccessThreshold:    1000, // never close on its own
	})

	var (
		recMu      sync.Mutex
		stateOfGen = map[uint64]State{}

		admMu sync.Mutex
		seen  []admission

		workers sync.WaitGroup
		helpers sync.WaitGroup
		stop    = make(chan struct{})
	)

	record := func() {
		st, gen := snapshotStateAndGeneration(cb)
		recMu.Lock()
		stateOfGen[gen] = st
		recMu.Unlock()
	}
	record() // generation 0

	// Churn the state so admissions race transitions, and poll the true pair.
	// Both run until the admitting workers are done -- no timer decides that.
	for i := 0; i < 2; i++ {
		helpers.Add(1)
		go func() {
			defer helpers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				cb.Trip()
				record()
				cb.Reset()
				record()
			}
		}()
	}

	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 500; j++ {
				adm, err := cb.beforeRequest()
				if err != nil {
					continue
				}
				admMu.Lock()
				seen = append(seen, adm)
				admMu.Unlock()
				cb.afterRequest(adm, nil) // release any half-open slot
			}
		}()
	}

	workers.Wait()
	close(stop)
	helpers.Wait()

	if len(seen) == 0 {
		t.Fatal("no admissions were granted; the test exercised nothing")
	}

	recMu.Lock()
	defer recMu.Unlock()
	checked := 0
	for _, adm := range seen {
		want, known := stateOfGen[adm.generation]
		if !known {
			continue // the poller never saw this generation
		}
		checked++
		if want != adm.state {
			t.Fatalf("incoherent admission: state=%v carried with generation %d, "+
				"but generation %d was %v -- the state and the generation were "+
				"read at different instants", adm.state, adm.generation, adm.generation, want)
		}
	}
	if checked == 0 {
		t.Fatal("no admission shared a generation with the poller; the oracle " +
			"observed nothing and this test proved nothing")
	}
	t.Logf("checked %d of %d admissions against %d observed generations",
		checked, len(seen), len(stateOfGen))
}

// TestAdmission_CallbackMayCallBackIntoTheBreaker is the deadlock regression
// test.
//
// transitionToLocked used to invoke OnStateChange while cb.mu was held. That
// was survivable while admission was lock-free, but this package's admission
// now takes cb.mu -- so a callback calling cb.Execute blocked on a mutex the
// transition could not release until the callback returned. sync.Mutex is not
// reentrant: that is a deadlock, not a slow path, and it is reachable from an
// ordinary closed-to-open transition.
//
// The callback here does the most natural reentrant thing: ask the breaker it
// was notified about to run something. It must not hang.
//
// The whole test runs behind a timeout, because the failure mode is a hang and
// a hung test takes the suite with it instead of reporting.
func TestAdmission_CallbackMayCallBackIntoTheBreaker(t *testing.T) {
	var cb *CircuitBreaker

	callbackRan := make(chan struct{}, 4)
	cb = New(&Config{
		Name:         "callback-reentrancy",
		MaxFailures:  1,
		ResetTimeout: 1 << 30,
		OnStateChange: func(_ string, _, _ State) {
			// Reentrant call into the breaker being transitioned.
			_ = cb.Execute(func() error { return nil })
			callbackRan <- struct{}{}
		},
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		// Fails once, hits MaxFailures, transitions closed->open, which fires
		// the callback.
		_ = cb.Execute(func() error { return errProbeFailed })
	}()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Execute did not return: the state-change callback called back " +
			"into the breaker and deadlocked on cb.mu")
	}

	select {
	case <-callbackRan:
	case <-time.After(5 * time.Second):
		t.Fatal("the state-change callback never completed")
	}

	if state := cb.State(); state != StateOpen {
		t.Errorf("breaker is %v, want open", state)
	}
}
