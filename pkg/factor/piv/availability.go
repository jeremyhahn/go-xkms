// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package piv

import "context"

// This file implements the ceremony's OPTIONAL availability probe, so a PIV
// factor selected for admin enrollment at init fails the preflight when no
// card is reachable — before the barrier is initialized — rather than partway
// through, which would leave a half-enrolled administrator.

// GeneratorAvailability is an optional capability a PIVKeyGenerator may
// implement to report whether its card is reachable.
//
// Optional because the Factor is deliberately hardware-agnostic: it talks to
// a PIVKeyGenerator, and the software generator used in tests and in
// software-only deployments cannot fail for environmental reasons. Only a
// generator that actually reaches a reader needs to answer.
type GeneratorAvailability interface {
	// Available reports whether the card is reachable, with operator-facing
	// text when it is not.
	Available(ctx context.Context) (ok bool, reason string)
}

// Available reports whether PIV enrollment can proceed right now.
//
// It answers about the generator the deployment actually configured, in three
// cases:
//
//   - No generator, and Config.RequireGenerator set: unavailable. The
//     deployment asked for a card and none is attached, so refusing here is
//     the whole point — the alternative is a software credential recorded as
//     if it were the smartcard the operator presented.
//   - A generator that implements GeneratorAvailability: its answer, which is
//     how an attached-but-empty reader is caught before any state changes.
//   - Anything else: available. A software generator has no card to be
//     missing, and reporting it unavailable would block software-only
//     deployments from enrolling a PIV factor they can legitimately use.
func (f *Factor) Available(ctx context.Context) (bool, string) {
	if f == nil {
		return false, "PIV factor is not configured"
	}
	if f.cfg.Generator == nil {
		return false, NoGeneratorReason
	}
	probe, ok := f.cfg.Generator.(GeneratorAvailability)
	if !ok {
		return true, ""
	}
	return probe.Available(ctx)
}
