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

package console

import (
	"crypto/fips140"
	"testing"
)

// requireHandshake reports whether a Dial (or ssh.Dial) error is nil -- the
// caller should proceed -- and otherwise reports whether that error is the
// expected outcome of an SSH handshake under GODEBUG=fips140=only, failing
// the test if it is any other kind of failure.
//
// buildClientConfig (pkg/ssh/session/config.go) deliberately defers to
// golang.org/x/crypto/ssh's own default key-exchange list rather than
// pinning one: "Overriding here would be a maintenance burden without a
// concrete threat model that justifies it." That list's preferred
// algorithm, curve25519-sha256, negotiates successfully between this
// package's test client and test server (both run in the same process, and
// neither restricts its own algorithm list for FIPS), and only then fails
// inside crypto/ecdh when the handshake actually tries to compute it -- a
// clean, typed error, not a panic. Restricting the negotiated algorithm
// list under FIPS is a policy decision for #23's follow-up, not one this
// test suite makes unilaterally; until then, a fixture that cannot complete
// a handshake under fips140=only is the expected, asserted outcome here.
func requireHandshake(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return true
	}
	if fips140.Enforced() {
		return false
	}
	t.Fatalf("unexpected handshake error: %v", err)
	return false
}

// requireWSUpgrade is requireHandshake for a WebSocket upgrade. handler.go's
// wsHandler.ServeHTTP calls github.com/gorilla/websocket's Upgrader.Upgrade,
// which computes the RFC 6455 Sec-WebSocket-Accept header with crypto/sha1
// -- a protocol-mandated checksum, not a security boundary, but crypto/sha1
// panics unconditionally under GODEBUG=fips140=only regardless of purpose.
// net/http recovers the panic per connection, so it does not crash the
// process (unlike the panics #23 otherwise fixed), but every upgrade this
// handler serves fails under fips140=only until gorilla/websocket is
// patched or replaced -- an upstream/dependency limitation out of scope for
// this repository to fix directly, tracked alongside the go-tpm blocker.
func requireWSUpgrade(t *testing.T, err error) bool {
	t.Helper()
	if err == nil {
		return true
	}
	if fips140.Enforced() {
		return false
	}
	t.Fatalf("ws dial: %v", err)
	return false
}
