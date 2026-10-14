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

// Package lifecycle provides bounded shutdown joins for components that hold
// protected key material.
//
// Every such wait exists for one reason: to stop a destroyer from freeing
// pages a reader is still using. That makes an unbounded wait look like the
// safe choice, and it is not. The work being waited for is routinely outside
// the waiting package's control — a caller-supplied request handler, or a
// Transport whose Close is not contractually required to unblock a read
// already in progress — so a wait with no bound is a shutdown that can hang
// forever, usually while holding the very mutex the reader needs to finish.
// One unbounded wait per component was enough to make Close, Stop and
// teardown all indefinitely blocking in the same release.
//
// The bound does not trade safety for liveness. A join that times out reports
// false, and the caller's correct response is to RETAIN the protected memory
// rather than free it. Leaking locked pages is the safe failure mode; freeing
// pages a live goroutine is decrypting through is not. Retention is permanent
// for the life of the process — go-enclave reclaims only through a process-wide
// enclave.WipeAll — so a timeout is a real cost and the timeouts are set accordingly.
package lifecycle

import (
	"sync"
	"time"
)

// Joiner bounds waits on a WaitGroup, reporting whether it drained before the
// timeout elapsed. A false return means at least one counted goroutine is
// still running and anything it may be reading must stay resident.
//
// A waiter goroutine outlives a timed-out join, because there is no way to
// abandon a WaitGroup.Wait. ONE such goroutine is the price of having a bound
// at all, and it costs a stack where the alternative costs a use-after-free.
// Many of them is a leak, and that is what a Joiner prevents: joins are
// public and callers retry, so spawning a waiter per call means every retry
// against a goroutine that is stuck forever adds another goroutine that is
// stuck forever. A Joiner starts exactly one, whatever happens.
//
// The zero value is ready to use. Every call must pass the same WaitGroup;
// a Joiner belongs to the component whose shutdown it bounds.
type Joiner struct {
	once sync.Once
	done chan struct{}
}

// Join waits for wg to reach zero, reporting whether it did so before timeout
// elapsed.
func (j *Joiner) Join(wg *sync.WaitGroup, timeout time.Duration) bool {
	j.once.Do(func() {
		j.done = make(chan struct{})
		go func() {
			wg.Wait()
			close(j.done)
		}()
	})

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case <-j.done:
		return true
	case <-timer.C:
		return false
	}
}

// Drain counts in-flight operations that hold a reference to something a
// shutdown wants to free, and lets that shutdown wait for them with a bound.
//
// It is the counter half of sync.Cond, which cannot be waited on with a
// timeout at all. Like a Cond it is driven under a mutex the CALLER owns,
// because the check that admits a new operation and the increment that counts
// it have to be one step: a component that tests "am I closed?" and then
// increments in a second step can admit an operation the shutdown has already
// stopped waiting for.
//
// The zero value is ready to use.
type Drain struct {
	n int

	// idle is closed when n reaches zero, and is created lazily by Wait so
	// that a Drain nobody waits on allocates nothing. It is nil whenever
	// there is no wait outstanding.
	idle chan struct{}
}

// Add counts one operation as in flight. The caller must hold the mutex that
// guards this Drain, and must have already checked, under that same mutex,
// that the component will admit the operation.
func (d *Drain) Add() { d.n++ }

// Done retires one operation. The caller must hold the mutex that guards this
// Drain. Calling Done more times than Add panics rather than wrapping the
// counter negative and hanging every future Wait.
func (d *Drain) Done() {
	if d.n == 0 {
		panic("lifecycle: Drain.Done without a matching Add")
	}

	d.n--
	if d.n == 0 && d.idle != nil {
		close(d.idle)
		d.idle = nil
	}
}

// InFlight reports the number of operations currently counted. The caller
// must hold the mutex that guards this Drain.
func (d *Drain) InFlight() int { return d.n }

// Wait blocks until every counted operation has retired or timeout elapses,
// and reports whether the drain completed. It releases mu while waiting and
// re-acquires it before returning, exactly as sync.Cond.Wait does, which is
// what lets the in-flight operations reach their Done.
//
// The caller must hold mu, and must already have made the component refuse
// new operations — otherwise a fresh Add can land in the window between the
// drain completing and mu being re-acquired, and a true return would be a
// lie by the time the caller acts on it.
func (d *Drain) Wait(mu sync.Locker, timeout time.Duration) bool {
	if d.n == 0 {
		return true
	}

	if d.idle == nil {
		d.idle = make(chan struct{})
	}
	idle := d.idle

	timer := time.NewTimer(timeout)
	defer timer.Stop()

	mu.Unlock()
	var drained bool
	select {
	case <-idle:
		drained = true
	case <-timer.C:
	}
	mu.Lock()

	return drained
}
