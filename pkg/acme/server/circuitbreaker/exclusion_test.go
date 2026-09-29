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
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// errNotEvidence is an error the exclusion predicate in these tests excludes.
var errNotEvidence = errors.New("refused before reaching the dependency")

func excludeNotEvidence(err error) bool {
	return errors.Is(err, errNotEvidence)
}

func TestExecute_ExcludedFailureIsReturnedButNotRecorded(t *testing.T) {
	cb := New(&Config{Name: "exclude-closed", MaxFailures: 1, ResetTimeout: time.Hour})

	for i := 0; i < 100; i++ {
		err := cb.execute(context.Background(), func() error { return errNotEvidence }, excludeNotEvidence)
		require.ErrorIs(t, err, errNotEvidence, "an excluded error must still reach the caller")
	}

	assert.Equal(t, StateClosed, cb.State(), "excluded failures must not open the breaker")
	failures, successes := cb.Counts()
	assert.Zero(t, failures)
	assert.Zero(t, successes, "an excluded failure must not be recorded as a success either")
}

// TestExecute_ExcludedFailureDoesNotResetFailureCount pins that an excluded
// outcome is neutral, not a success: were it recorded as a success it would
// reset the failure count, and interleaving excluded calls would keep a
// genuinely failing dependency's breaker closed forever.
func TestExecute_ExcludedFailureDoesNotResetFailureCount(t *testing.T) {
	cb := New(&Config{Name: "exclude-neutral", MaxFailures: 2, ResetTimeout: time.Hour})

	require.ErrorIs(t, cb.execute(context.Background(), func() error { return errDependencyFailed }, excludeNotEvidence), errDependencyFailed)
	require.ErrorIs(t, cb.execute(context.Background(), func() error { return errNotEvidence }, excludeNotEvidence), errNotEvidence)
	require.ErrorIs(t, cb.execute(context.Background(), func() error { return errDependencyFailed }, excludeNotEvidence), errDependencyFailed)

	assert.Equal(t, StateOpen, cb.State(), "two genuine failures must open the breaker despite the excluded call between them")
}

func TestExecute_FailureThePredicateDoesNotExcludeIsRecorded(t *testing.T) {
	cb := New(&Config{Name: "exclude-miss", MaxFailures: 1, ResetTimeout: time.Hour})

	err := cb.execute(context.Background(), func() error { return errDependencyFailed }, excludeNotEvidence)

	require.ErrorIs(t, err, errDependencyFailed)
	assert.Equal(t, StateOpen, cb.State())
}

func TestExecute_PredicateIsNotConsultedOnSuccess(t *testing.T) {
	cb := New(&Config{Name: "exclude-success", MaxFailures: 1, ResetTimeout: time.Hour})
	consulted := false

	err := cb.execute(context.Background(), func() error { return nil }, func(error) bool {
		consulted = true
		return true
	})

	require.NoError(t, err)
	assert.False(t, consulted)
	_, successes := cb.Counts()
	assert.Equal(t, uint32(1), successes)
}

// TestExecute_TimeoutIsRecordedEvenWithAPredicate verifies that a call the
// breaker abandons on its own timeout is a failure: the predicate sees
// context.DeadlineExceeded, not an excluded error.
func TestExecute_TimeoutIsRecordedEvenWithAPredicate(t *testing.T) {
	cb := New(&Config{Name: "exclude-timeout", MaxFailures: 1, ResetTimeout: time.Hour, Timeout: time.Millisecond})
	unblock := make(chan struct{})
	defer close(unblock)

	err := cb.execute(context.Background(), func() error {
		<-unblock
		return errNotEvidence
	}, excludeNotEvidence)

	require.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Equal(t, StateOpen, cb.State())
}

// TestExecute_ExcludedHalfOpenProbeReleasesItsSlot verifies that an excluded
// probe neither closes nor reopens a half-open breaker, and gives its slot
// back so the next probe can run.
func TestExecute_ExcludedHalfOpenProbeReleasesItsSlot(t *testing.T) {
	cb := admissionTestBreaker("exclude-half-open")
	cb.Trip()

	// ResetTimeout 0: this call moves the breaker to half-open and is its probe.
	err := cb.execute(context.Background(), func() error { return errNotEvidence }, excludeNotEvidence)
	require.ErrorIs(t, err, errNotEvidence)
	assert.Equal(t, StateHalfOpen, cb.State(), "an excluded probe must not change the half-open state")
	assert.Zero(t, cb.halfOpenRequests.Load(), "an excluded probe must release its half-open slot")

	// The slot is free, so a genuine probe runs, fails and reopens the breaker.
	ran := false
	err = cb.Execute(func() error { ran = true; return errProbeFailed })
	require.ErrorIs(t, err, errProbeFailed)
	assert.True(t, ran)
	assert.Equal(t, StateOpen, cb.State())
}

// TestReleaseAdmission_StaleSlotIsNotReleased verifies releaseAdmission
// follows afterRequest's ownership rule: a half-open slot taken in an earlier
// generation no longer exists, so releasing it must not free the slot a
// later generation's probe holds.
func TestReleaseAdmission_StaleSlotIsNotReleased(t *testing.T) {
	cb := admissionTestBreaker("release-stale")
	cb.Trip()

	stale, err := cb.Allow()
	require.NoError(t, err)
	require.True(t, stale.adm.heldHalfOpenSlot)

	// A new half-open generation, whose only slot is then taken.
	cb.Trip()
	current, err := cb.Allow()
	require.NoError(t, err)
	require.Equal(t, uint32(1), cb.halfOpenRequests.Load())

	cb.releaseAdmission(stale.adm)
	assert.Equal(t, uint32(1), cb.halfOpenRequests.Load(), "a stale admission must not release the current generation's slot")

	cb.releaseAdmission(current.adm)
	assert.Zero(t, cb.halfOpenRequests.Load(), "the current admission releases its own slot")
	assert.Equal(t, StateHalfOpen, cb.State(), "releasing an admission records no outcome")
}
