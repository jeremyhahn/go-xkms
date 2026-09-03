// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// NoGeneratorReason is the operator-facing text reported by a Factor that was
// configured to require a PIV key generator and has none attached. It is
// exported because it is what the ceremony's preflight surfaces to the person
// standing at the console, and a caller may want to match on it.
const NoGeneratorReason = "no PIV generator attached — enroll from a console with a card reader, or opt in to a software credential"

// GeneratorUnattachedError reports that a PIV Factor configured with
// Config.RequireGenerator was asked to produce or use key material with no
// generator attached.
//
// It is deliberately a refusal rather than a fallback: substituting a software
// key for the smartcard an operator asked for produces a credential that is
// recorded, reported, and usable exactly like a hardware one, which no relying
// party can afterwards tell apart.
type GeneratorUnattachedError struct{}

// Error implements error.
func (e *GeneratorUnattachedError) Error() string {
	return "piv: " + NoGeneratorReason
}
