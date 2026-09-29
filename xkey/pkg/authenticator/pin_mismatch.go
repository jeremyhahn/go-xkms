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

package authenticator

import "sync/atomic"

// PINMaxConsecutiveFailures is the number of consecutive failed PIN attempts
// allowed within a single power cycle, for both the user PIN and the Security
// Officer PIN. CTAP 2.1 §6.5.5.5 / §6.5.5.7 require the authenticator to
// refuse further attempts with CTAP2_ERR_PIN_AUTH_BLOCKED after three
// consecutive mismatches until it is power-cycled, which bounds an online brute
// force far below the total retry budget.
const PINMaxConsecutiveFailures = 3

// pinRefusals names the three errors a PIN credential reports for a failed
// attempt, so the user PIN and the Security Officer PIN share one
// classification while keeping their own error identities.
type pinRefusals struct {
	// blocked reports an exhausted retry budget. Terminal until
	// authenticatorReset.
	blocked error

	// authBlocked reports PINMaxConsecutiveFailures consecutive mismatches.
	// Cleared by a power cycle or a correct PIN.
	authBlocked error

	// invalid reports an ordinary mismatch with attempts remaining.
	invalid error
}

// pinMismatchGuard counts consecutive PIN mismatches since the last correct
// PIN or power-up. It is deliberately never persisted: "power cycle to
// continue" is only meaningful if a power cycle clears it, and for this
// authenticator a power cycle is a process restart.
//
// The zero value is ready to use.
type pinMismatchGuard struct {
	failures atomic.Int32
}

// authBlocked reports whether PINMaxConsecutiveFailures consecutive attempts
// have failed since the last power cycle.
func (g *pinMismatchGuard) authBlocked() bool {
	return g.failures.Load() >= int32(PINMaxConsecutiveFailures)
}

// count returns the number of consecutive failed attempts.
func (g *pinMismatchGuard) count() int {
	return int(g.failures.Load())
}

// reset clears the counter after a correct PIN.
func (g *pinMismatchGuard) reset() {
	g.failures.Store(0)
}

// recordMismatch counts one failed attempt and returns the refusal CTAP 2.1
// requires, in the specification's order: the exhausted retry budget first
// (retriesExhausted), then the consecutive-mismatch block, otherwise an
// ordinary invalid PIN.
func (g *pinMismatchGuard) recordMismatch(retriesExhausted bool, refusals pinRefusals) error {
	g.failures.Add(1)

	switch {
	case retriesExhausted:
		return refusals.blocked
	case g.authBlocked():
		return refusals.authBlocked
	default:
		return refusals.invalid
	}
}
