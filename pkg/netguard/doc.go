// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package netguard is the reserved-address classification and guarded HTTP
// dialer every attacker-directed fetch in go-xkms builds on: a URL taken
// from a certificate's AIA or CRL distribution point extension (pkg/ca), or
// a target an ACME client named for challenge validation
// (pkg/acme/challenges/validation). Both fetches dial a destination neither
// caller chose, so both need the same three guarantees:
//
//   - a resolved address is checked against ReservedAddr, not the
//     hostname the caller was given, so a name that resolves -- or
//     re-resolves, DNS rebinding -- to a reserved address is refused;
//   - the check runs in the dialer's Control hook, after DNS resolution and
//     on every connection a client makes, redirect hops included, so it
//     cannot be bypassed by a second lookup;
//   - no proxy is consulted, because a proxy would dial on the caller's
//     behalf and make the address checked meaningless.
//
// netguard supplies the address classification (ReservedAddr), the dialer
// guard (DialControl, GuardedTransport) and a size-capped body read
// (ReadLimited). It does not decide what a caller is willing to fetch --
// redirect policy, per-call size limits, URL scheme and userinfo checks,
// and opting a specific caller into reserved targets all stay with the
// caller, because those decisions differ between an AIA/CRL fetch and an
// ACME challenge fetch.
package netguard
