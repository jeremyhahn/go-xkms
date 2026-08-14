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

// Package authorized handles authorized_keys emission, parsing, and
// storage-backed verification for xkms.
//
// An Entry composes a *keys.Key (for public-key material) with the
// OpenSSH restriction Options and a free-text Comment. Emit produces an
// OpenSSH authorized_keys-format line; ParseLine / ParseAll read the
// same format back. Emit only touches the public half of a Key — no
// secure.Secret is opened during emission.
//
// The Store sub-surface persists Entries by (scope, owner, name) using
// the same storage.Backend contract that pkg/ssh/keys and
// pkg/ssh/known_hosts use. Reads return a Record — the stored (scope,
// owner, name) coordinates and add timestamp paired with the parsed
// Entry — so a listed entry can be fed straight back into Get or
// Remove. Verify looks up pinned Records and matches an incoming
// ssh.PublicKey against them by SHA256 fingerprint, returning the
// Record that granted access.
//
// # Layering
//
// authorized depends on pkg/ssh/keys (for *Key and Fingerprint),
// pkg/ssh/scope, and pkg/storage. It is independent of
// pkg/ssh/known_hosts and pkg/ssh/session.
package authorized
