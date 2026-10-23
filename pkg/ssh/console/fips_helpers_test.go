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
	"crypto/sha1"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
)

// requireHandshake reports whether a Dial succeeded, so the caller should
// carry on. Under GODEBUG=fips140=only it instead asserts that Dial returned
// a *DialError carrying the Go Cryptographic Module's own refusal (see
// outsideFIPSAfterDialRefusal), re-runs the test with fips140=off, and
// returns false.
func requireHandshake(t *testing.T, err error) bool {
	t.Helper()
	if !outsideFIPSAfterDialRefusal(t, err) {
		return false
	}
	if err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	return true
}

// requireSSHHandshake is requireHandshake for a fixture that calls ssh.Dial
// directly, so its error is the x/crypto/ssh handshake error with no
// *DialError around it.
func requireSSHHandshake(t *testing.T, err error) bool {
	t.Helper()
	if !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
		return false
	}
	if err != nil {
		t.Fatalf("unexpected handshake error: %v", err)
	}
	return true
}

// outsideFIPSAfterDialRefusal is fipstest.OutsideFIPSAfterRefusal for a Dial
// error: under GODEBUG=fips140=only it also asserts the refusal arrives
// wrapped in a *DialError.
//
// buildClientConfig (pkg/ssh/session/config.go) deliberately defers to
// golang.org/x/crypto/ssh's own default key-exchange list rather than
// pinning one. That list's preferred algorithm, curve25519-sha256,
// negotiates between this package's test client and test server (both run
// in the same process, and neither restricts its algorithm list for FIPS).
// Under fips140=only the handshake then fails when x/crypto/ssh computes the
// shared secret: crypto/ecdh returns "use of X25519 is not allowed in FIPS
// 140-only mode", which x/crypto/ssh wraps as "ssh: handshake failed:
// curve25519: ...", pkg/ssh/session as *session.HandshakeError, and Dial as
// *DialError -- an error, not a panic. Restricting the negotiated algorithm
// list under FIPS is a policy decision for #23's follow-up, not one this test
// suite makes; until then the module's refusal is the expected, asserted
// outcome, and any other handshake failure fails the test.
func outsideFIPSAfterDialRefusal(t *testing.T, err error) bool {
	t.Helper()
	var dialErr *DialError
	if fips140.Enforced() && !errors.As(err, &dialErr) {
		t.Fatalf("%s under GODEBUG=fips140=only: got error %T (%v), want *DialError", t.Name(), err, err)
	}
	return fipstest.OutsideFIPSAfterRefusal(t, err, nil)
}

// requireWSUpgrade reports whether a WebSocket dial succeeded, so the caller
// should carry on with its round trip. Under GODEBUG=fips140=only it instead
// asserts that the handler refused the upgrade (upgradeWS: the standard
// library refuses the SHA-1 RFC 6455 §4.2.2 requires), re-runs the test with
// fips140=off, and returns false.
func requireWSUpgrade(t *testing.T, resp *http.Response, err error) bool {
	t.Helper()
	if !fipstest.OutsideFIPSAfterRefusal(t, upgradeRefusal(t, resp, err), &UpgradeRefusedError{}) {
		return false
	}
	if err != nil {
		t.Fatalf("ws dial: %v", err)
	}
	return true
}

// upgradeRefusal is the dial error as the handler meant it: when the
// response is upgradeWS's 501 carrying the refusal this process's standard
// library makes, that typed refusal; otherwise err itself.
func upgradeRefusal(t *testing.T, resp *http.Response, err error) error {
	t.Helper()
	if err == nil || resp == nil || resp.StatusCode != http.StatusNotImplemented {
		return err
	}
	body, rerr := io.ReadAll(resp.Body)
	if rerr != nil {
		t.Fatalf("read the refused upgrade's body: %v", rerr)
	}
	_, hashErr := sha1.New().Write(nil)
	if hashErr == nil {
		return err
	}
	refused := &UpgradeRefusedError{Err: hashErr}
	if strings.TrimSpace(string(body)) != refused.Error() {
		return err
	}
	return refused
}
