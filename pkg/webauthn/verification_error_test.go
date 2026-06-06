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

package webauthn

import (
	"errors"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
)

// TestVerificationError_ProtocolErrorClassifiedAsVerificationFailure ensures a
// go-webauthn protocol verification failure (a forged or invalid
// attestation/assertion) is classified as ErrVerificationFailed so the HTTP
// transport returns 401 Unauthorized rather than 500 Internal Server Error.
//
// Regression guard for the bug surfaced by the Chrome virtual-authenticator
// ceremony test: a tampered assertion signature was reaching the handler's
// default branch (500) because go-webauthn's *protocol.Error was wrapped
// verbatim without translation.
func TestVerificationError_ProtocolErrorClassifiedAsVerificationFailure(t *testing.T) {
	cases := []*protocol.Error{
		protocol.ErrAssertionSignature, // bad signature (the tampered-assertion case)
		protocol.ErrVerification,       // generic verification failure
		protocol.ErrInvalidAttestation, // bad attestation (forged registration)
	}
	for _, pe := range cases {
		got := verificationError("validate login", pe)
		if !IsVerificationFailed(got) {
			t.Fatalf("protocol error %q must classify as ErrVerificationFailed", pe.Error())
		}
		if !errors.Is(got, ErrVerificationFailed) {
			t.Fatalf("errors.Is(err, ErrVerificationFailed) must hold for %q", pe.Error())
		}
	}
}

// TestVerificationError_InternalErrorNotMisclassified ensures a non-protocol
// error (for example a storage fault surfaced through a validation callback) is
// NOT misclassified as a verification failure and therefore remains a 500.
func TestVerificationError_InternalErrorNotMisclassified(t *testing.T) {
	internal := errors.New("credential store unavailable")
	got := verificationError("validate discoverable login", internal)

	if IsVerificationFailed(got) {
		t.Fatal("a non-protocol internal error must not classify as ErrVerificationFailed")
	}
	if !errors.Is(got, internal) {
		t.Fatal("the underlying internal error must remain unwrappable")
	}
}
