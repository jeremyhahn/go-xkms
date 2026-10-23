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

package session_test

import (
	"crypto/fips140"
	"errors"
	"net"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/session"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// requireHandshake reports whether a session.Dial or session.DialClient
// error is nil, so the caller should carry on. Under GODEBUG=fips140=only it
// instead asserts that the error is a *session.HandshakeError carrying the
// Go Cryptographic Module's own refusal and nothing else -- in particular
// not the net.ErrClosed of closing a connection golang.org/x/crypto/ssh has
// already closed -- re-runs the test with fips140=off, and returns false.
//
// buildClientConfig (config.go) deliberately defers to golang.org/x/crypto/ssh's
// own default key-exchange list rather than pinning one: "Overriding here
// would be a maintenance burden without a concrete threat model that
// justifies it." That list's preferred algorithm, curve25519-sha256,
// negotiates successfully between this package's test client and test
// server (both run in the same process, and neither restricts its own
// algorithm list for FIPS), and only then fails inside crypto/ecdh when the
// handshake actually tries to compute it -- a clean, typed error, not a
// panic. Restricting the negotiated algorithm list under FIPS is a policy
// decision for #23's follow-up, not one this test suite makes unilaterally;
// until then, a fixture that cannot complete a handshake under
// fips140=only is the expected, asserted outcome here.
func requireHandshake(t *testing.T, err error) bool {
	t.Helper()
	if fips140.Enforced() {
		var hsErr *session.HandshakeError
		if !errors.As(err, &hsErr) {
			t.Fatalf("%s under GODEBUG=fips140=only: got error %T (%v), want *session.HandshakeError", t.Name(), err, err)
		}
		if errors.Is(err, net.ErrClosed) {
			t.Fatalf("%s under GODEBUG=fips140=only: the handshake refusal carries a stray closed-connection error: %v", t.Name(), err)
		}
	}
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		return false
	}
	if err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	return true
}
