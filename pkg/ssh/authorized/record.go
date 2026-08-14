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

package authorized

import (
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// Record is the read-side result of a Store lookup: the store metadata
// that identifies an entry — its (Scope, Owner, Name) coordinates and
// the time it was filed — paired with the parsed Entry.
//
// The split is deliberate. Entry models exactly one authorized_keys
// line (key, options, comment) and nothing else, so it stays usable for
// parsing and emitting free-standing files. Name, Scope and Owner are
// store metadata — they name the slot the line was filed in, not
// anything present on the line — so they live here instead of being
// bolted onto Entry.
//
// Because Record carries Name, a caller that lists entries holds the
// identifier it needs to feed straight back into Store.Get or
// Store.Remove. The values are the ones read back from storage, so they
// are authoritative rather than an echo of whatever the caller asked
// for.
type Record struct {
	// Scope is the scope the entry was filed under.
	Scope scope.Scope

	// Owner is the scope-relative owner the entry was filed under.
	Owner string

	// Name is the caller-assigned identifier for the entry, unique
	// within (Scope, Owner). It is the lookup key for Get and Remove.
	Name string

	// AddedAt is the UTC timestamp recorded when the entry was added.
	AddedAt time.Time

	// Entry is the parsed authorized_keys line. Never nil for Records
	// produced by this package.
	Entry *Entry
}
