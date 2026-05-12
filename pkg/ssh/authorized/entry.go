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
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
)

// Entry is a single authorized_keys record: a public-key-bearing
// *keys.Key (the key's private Material may be nil for public-only
// Entries produced by ParseLine) plus the OpenSSH restriction Options
// and an optional Comment.
//
// Options are whitespace/comma-safe restriction directives exactly as
// they appear on disk (e.g., "no-port-forwarding",
// `command="/usr/local/bin/backup"`, `from="10.0.0.0/8"`, "restrict").
// This package does not validate option semantics — the OpenSSH sshd
// does. We preserve whatever the caller emits so operator-specific
// directives round-trip unchanged.
//
// Comment is free text concatenated to the line after the key. It is
// not used for lookup; Verify matches by fingerprint only.
type Entry struct {
	// Key carries the public key to authorize. For ParseLine results
	// Key.Material is nil (no private half on disk). For Entries the
	// caller constructs around a locally-generated keys.Key the
	// Material field is left alone (authorized never opens the
	// enclave).
	Key *keys.Key

	// Options are the OpenSSH authorized_keys option tokens, preserved
	// exactly as they appear on the wire. May be nil.
	Options []string

	// Comment is the trailing free-text comment. Empty string is
	// acceptable.
	Comment string
}
