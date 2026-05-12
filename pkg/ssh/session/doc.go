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

// Package session provides a MITM-safe SSH client that composes
// pkg/ssh/keys (enclave-backed signers) and pkg/ssh/known_hosts (pinned
// host verification) behind a minimal Session interface.
//
// This package replaces the legacy pkg/ssh.Client. Every Session owns
// its underlying *keys.Key — Close() deterministically destroys the
// memguard enclave in LIFO order, matching the secure-memory discipline
// documented in pkg/secure.
//
// # MITM safety
//
// Dial refuses to proceed without an explicit known_hosts.Store. There
// is no trust-on-first-use path — pins are added by an operator action,
// and a dial against an unpinned host returns *known_hosts.NotFoundError.
//
// # Layering
//
// session depends on pkg/ssh/keys, pkg/ssh/known_hosts, and
// pkg/ssh/scope. It does NOT depend on pkg/ssh/authorized (that
// package serves the opposite direction — authorizing inbound keys on
// a server — and has no place in an outbound client).
package session
