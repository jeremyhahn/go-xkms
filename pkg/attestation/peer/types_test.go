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

package peer

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ca"
)

func TestFailureClass_String(t *testing.T) {
	for class, want := range map[FailureClass]string{
		FailureNone:          "none",
		FailureAbsence:       "absence",
		FailureCryptographic: "cryptographic",
		FailureClass(200):    "unknown",
	} {
		if got := class.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", class, got, want)
		}
	}
}

func TestFailureClass_TextRoundTrip(t *testing.T) {
	for _, class := range []FailureClass{FailureNone, FailureAbsence, FailureCryptographic} {
		text, err := class.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		var back FailureClass
		if err := back.UnmarshalText(text); err != nil {
			t.Fatal(err)
		}
		if back != class {
			t.Fatalf("%s round-tripped to %s", class, back)
		}
	}
}

func TestFailureClass_RejectsUnknownText(t *testing.T) {
	var class FailureClass
	err := class.UnmarshalText([]byte("quarantine"))
	var fce *FailureClassError
	if !errors.As(err, &fce) || fce.Text != "quarantine" || !strings.Contains(err.Error(), `"quarantine"`) {
		t.Fatalf("err = %v", err)
	}
	if _, err := FailureClass(7).MarshalText(); err == nil {
		t.Fatal("unknown class marshaled")
	}
}

func TestVerdict_JSONCarriesClassByName(t *testing.T) {
	v := Verdict{Failure: FailureCryptographic, Checks: Checks{Signature: true}, Reason: "bad"}
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"failure":"cryptographic"`) {
		t.Fatalf("json = %s", raw)
	}
	var back Verdict
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if back.Failure != FailureCryptographic || !back.Checks.Signature || back.Reason != "bad" {
		t.Fatalf("back = %+v", back)
	}
}

func TestErrors_Messages(t *testing.T) {
	pe := &PolicyError{Field: "MaxEvidenceAge", Reason: "must not be negative"}
	if pe.Error() != "peer: invalid policy: MaxEvidenceAge: must not be negative" {
		t.Fatal(pe.Error())
	}
	ce := &ContextError{Cause: context.DeadlineExceeded}
	if !strings.Contains(ce.Error(), "deadline") || !errors.Is(ce, context.DeadlineExceeded) {
		t.Fatal(ce.Error())
	}
	cbe := &ChannelBindingError{Reason: "no TLS connection state"}
	if cbe.Error() != "peer: channel binding unavailable: no TLS connection state" || cbe.Unwrap() != nil {
		t.Fatal(cbe.Error())
	}
	cause := errors.New("boom")
	cbe = &ChannelBindingError{Reason: "TLS exporter refused", Cause: cause}
	if !strings.HasSuffix(cbe.Error(), ": boom") || !errors.Is(cbe, cause) {
		t.Fatal(cbe.Error())
	}
}

// TestRestrictedOIDMatchesCA pins the locally declared policy OID to the one
// pkg/ca stamps on IAK certificates, so the verifier and the issuer cannot
// drift apart without this test noticing.
func TestRestrictedOIDMatchesCA(t *testing.T) {
	if !oidTCGVerifiedTPMRestricted.Equal(ca.OIDTCGVerifiedTPMRestricted) {
		t.Fatalf("asn1 form %v != pkg/ca %v", oidTCGVerifiedTPMRestricted, ca.OIDTCGVerifiedTPMRestricted)
	}
	if !oidTCGVerifiedTPMRestrictedX509.Equal(ca.TCGVerifiedTPMRestrictedPolicy) {
		t.Fatalf("x509 form %v != pkg/ca %v", oidTCGVerifiedTPMRestrictedX509, ca.TCGVerifiedTPMRestrictedPolicy)
	}
}

func TestMustOID_PanicsOnInvalidArc(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("no panic for an invalid OID")
		}
	}()
	mustOID(5)
}
