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

package module

import (
	"fmt"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests in this file cover the admission control around Argon2id PIN hashing.
// Each derivation allocates pinArgonMemory KiB — 64 MiB — of scratch space, so
// before the gate existed N simultaneous C_Login calls cost N times that, and
// an unauthenticated caller could exhaust host memory by opening sessions and
// guessing PINs. The parameter itself is the security property and must not be
// weakened; only the number of derivations in flight is bounded.

// TestPinHashConcurrencyFor covers the sizing rule, including the floor. A zero
// or negative limit would produce a zero-capacity channel that blocks every
// login forever, converting the memory-exhaustion defect into a total denial of
// service, so the floor is the branch that matters most here.
func TestPinHashConcurrencyFor(t *testing.T) {
	tests := []struct {
		name   string
		numCPU int
		want   int
	}{
		{"a machine reporting no CPUs still admits one", 0, 1},
		{"a negative report still admits one", -8, 1},
		{"a single core admits one", 1, 1},
		{"fewer cores than lanes admits one", pinArgonLanes - 1, 1},
		{"exactly one lane group admits one", pinArgonLanes, 1},
		{"two lane groups admit two", pinArgonLanes * 2, 2},
		{"six lane groups admit six", pinArgonLanes * 6, 6},
		{"a partial lane group is not counted", pinArgonLanes*3 + 1, 3},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, pinHashConcurrencyFor(tc.numCPU))
		})
	}
}

// TestMaxPinHashConcurrencyIsBounded checks the live limit used to size the
// gate: at least one derivation may always proceed, and the limit never exceeds
// the machine's core count, so the token's worst-case PIN-hashing footprint is
// bounded by a number the operator can predict.
func TestMaxPinHashConcurrencyIsBounded(t *testing.T) {
	limit := maxPinHashConcurrency()

	assert.GreaterOrEqual(t, limit, 1, "the gate must always admit at least one derivation")
	assert.LessOrEqual(t, limit, runtime.NumCPU()+1, "the gate must not admit more derivations than the machine can run")
	assert.Equal(t, limit, cap(pinHashSlots), "the gate's capacity must be the computed limit")
}

// requireGateIdle waits until no derivation holds a slot. Every test here
// starts from and returns to that state.
//
// It waits rather than asserting instantaneously because pinHashSlots is a
// package-level semaphore shared with every other test in this package that
// logs in. Those tests hold a slot for the duration of one Argon2id
// derivation, so an instantaneous check ran green in isolation and failed
// intermittently under the full package — measuring another test's in-flight
// login rather than a leak. A bounded wait still fails on a genuine leak,
// because a leaked slot is never returned.
func requireGateIdle(t *testing.T) {
	t.Helper()

	const (
		limit = 30 * time.Second
		poll  = 2 * time.Millisecond
	)

	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if len(pinHashSlots) == 0 {
			return
		}
		time.Sleep(poll)
	}

	require.Zero(t, len(pinHashSlots),
		"the PIN-hash gate must drain; a slot still held after %s is a leak", limit)
}

// TestPinHashGateBlocksWhenFull is the direct proof of admission control and
// the regression test for the DoS: it catches a build in which argon2.IDKey is
// reachable without passing through the gate, because such a build lets a
// derivation start while every slot is taken and therefore lets N concurrent
// logins allocate N scratch buffers.
func TestPinHashGateBlocksWhenFull(t *testing.T) {
	requireGateIdle(t)

	stored := mustHashPin("gate-test-pin")

	// Time one ungated derivation so the "did not finish" window below is
	// known to be longer than the work itself, rather than an arbitrary
	// constant that a fast machine could satisfy by accident.
	start := time.Now()
	require.True(t, verifyPin(stored, "gate-test-pin"))
	baseline := time.Since(start)

	window := 4 * baseline
	if window < 250*time.Millisecond {
		window = 250 * time.Millisecond
	}

	// Occupy every slot, as a burst of concurrent C_Login calls would.
	for i := 0; i < cap(pinHashSlots); i++ {
		pinHashSlots <- struct{}{}
	}

	done := make(chan bool, 1)
	go func() { done <- verifyPin(stored, "gate-test-pin") }()

	select {
	case <-done:
		t.Fatal("a derivation ran while the gate was full: argon2.IDKey is reachable without admission control")
	case <-time.After(window):
	}

	// Freeing one slot must let exactly that queued derivation through.
	<-pinHashSlots
	select {
	case ok := <-done:
		assert.True(t, ok, "the queued derivation must still verify correctly once admitted")
	case <-time.After(30 * time.Second):
		t.Fatal("the queued derivation never ran after a slot was freed: the gate deadlocked")
	}

	// Drain the slots this test occupied.
	for i := 0; i < cap(pinHashSlots)-1; i++ {
		<-pinHashSlots
	}
	requireGateIdle(t)
}

// TestPinHashGateReleasesOnFailure checks that a login which fails still
// returns its slot. A gate leaked on the failure path would shrink the token's
// login capacity with every wrong PIN until no login could ever proceed —
// a worse denial of service than the one being fixed.
func TestPinHashGateReleasesOnFailure(t *testing.T) {
	requireGateIdle(t)

	stored := mustHashPin("correct-pin")

	for i := 0; i < cap(pinHashSlots)*3; i++ {
		assert.False(t, verifyPin(stored, "wrong-pin"), "a wrong PIN must not verify")
	}

	requireGateIdle(t)
	assert.True(t, verifyPin(stored, "correct-pin"), "the correct PIN must still verify after repeated failures")
	requireGateIdle(t)
}

// TestVerifyPinRejectsMalformedStoredValue covers the bad-input paths that
// return before any derivation is attempted. They must fail closed and must not
// touch the gate, since a slot acquired on a path that returns early would
// never be released.
func TestVerifyPinRejectsMalformedStoredValue(t *testing.T) {
	requireGateIdle(t)

	valid := mustHashPin("some-pin")

	tests := []struct {
		name   string
		stored []byte
	}{
		{"nil stored value", nil},
		{"empty stored value", []byte{}},
		{"one byte is too short to hold a header", []byte{pinHashVersion}},
		{"unknown version", append([]byte{pinHashVersion + 1}, valid[1:]...)},
		{"zero salt length", append([]byte{pinHashVersion, 0}, valid[2:]...)},
		{"truncated derived key", valid[:len(valid)-1]},
		{"trailing garbage", append(append([]byte{}, valid...), 0xFF)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.False(t, verifyPin(tc.stored, "some-pin"), "a malformed verifier must never authenticate")
			requireGateIdle(t)
		})
	}
}

// TestConcurrentPinVerificationIsBounded is the scaled-down form of the
// original crash: many simultaneous PIN verifications. Ungated, each of these
// goroutines holds its own 64 MiB scratch buffer at once; gated, at most
// cap(pinHashSlots) of them do. The test also proves the gate does not corrupt
// results or deadlock under contention — every correct PIN must verify and
// every wrong one must not.
func TestConcurrentPinVerificationIsBounded(t *testing.T) {
	requireGateIdle(t)

	const workers = 64

	stored := make([][]byte, workers)
	for i := range stored {
		stored[i] = mustHashPin(fmt.Sprintf("pin-%d", i))
	}

	results := make([]bool, workers)
	negatives := make([]bool, workers)

	begin := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-begin

			results[idx] = verifyPin(stored[idx], fmt.Sprintf("pin-%d", idx))
			negatives[idx] = verifyPin(stored[idx], fmt.Sprintf("pin-%d-wrong", idx))
		}(i)
	}

	close(begin)
	wg.Wait()

	for i := 0; i < workers; i++ {
		assert.True(t, results[i], "worker %d: the correct PIN must verify under contention", i)
		assert.False(t, negatives[i], "worker %d: a wrong PIN must not verify under contention", i)
	}

	requireGateIdle(t)
}

// TestHashPinProducesDistinctSaltedVerifiers guards the property the gate must
// not disturb: two hashes of the same PIN differ because the salt is random, so
// stored verifiers can only ever be compared through verifyPin.
func TestHashPinProducesDistinctSaltedVerifiers(t *testing.T) {
	first := mustHashPin("same-pin")
	second := mustHashPin("same-pin")

	require.Equal(t, byte(pinHashVersion), first[0])
	require.Equal(t, 2+pinSaltLen+pinKeyLen, len(first))
	assert.NotEqual(t, first, second, "a fresh salt must make every stored verifier unique")

	assert.True(t, verifyPin(first, "same-pin"))
	assert.True(t, verifyPin(second, "same-pin"))
	assert.False(t, verifyPin(first, "other-pin"))
}
