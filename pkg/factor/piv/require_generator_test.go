// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package piv

import (
	"context"
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// This file covers RequireGenerator: the fail-closed configuration that stops
// a deployment which asked for a smartcard credential from silently receiving
// a software one (issue #199).

// TestNew_RequireGeneratorLeavesNoSubstitutedGenerator verifies the substitution
// itself is suppressed, not merely reported around. If the software generator
// were still installed, a caller reaching past Available() straight to Enroll
// would produce exactly the software key this setting exists to prevent.
func TestNew_RequireGeneratorLeavesNoSubstitutedGenerator(t *testing.T) {
	f := New(Config{RequireGenerator: true})
	if f.cfg.Generator != nil {
		t.Fatal("RequireGenerator with no generator attached must not substitute a software generator")
	}
}

// TestFactor_AvailableRefusesWhenAGeneratorIsRequiredButAbsent verifies the
// preflight probe answers about the hardware the operator asked for, not about
// the software generator that used to be substituted underneath it.
func TestFactor_AvailableRefusesWhenAGeneratorIsRequiredButAbsent(t *testing.T) {
	f := New(Config{RequireGenerator: true})
	ok, reason := f.Available(context.Background())
	if ok {
		t.Fatal("Available() = true, want false when a generator is required and none is attached")
	}
	if reason != NoGeneratorReason {
		t.Errorf("reason = %q, want %q", reason, NoGeneratorReason)
	}
}

// TestFactor_AvailableWithARequiredGeneratorAttached verifies RequireGenerator
// is inert once a generator is actually attached: the seam exists to reach
// hardware, not to block it.
func TestFactor_AvailableWithARequiredGeneratorAttached(t *testing.T) {
	f := New(Config{RequireGenerator: true, Generator: &plainGenerator{}})
	ok, reason := f.Available(context.Background())
	if !ok {
		t.Fatalf("Available() = false (%q), want true with a generator attached", reason)
	}
}

// TestFactor_AvailableWithoutRequireGeneratorStaysSoftware pins the deliberate
// default: a software-only deployment that never asked for hardware still gets
// a usable PIV factor. Flipping this would break every such deployment.
func TestFactor_AvailableWithoutRequireGeneratorStaysSoftware(t *testing.T) {
	f := New(Config{})
	if f.cfg.Generator == nil {
		t.Fatal("the zero-value Config must still substitute the software generator")
	}
	if ok, reason := f.Available(context.Background()); !ok {
		t.Fatalf("Available() = false (%q), want true for the software default", reason)
	}
}

// TestFactor_EnrollRefusesWhenAGeneratorIsRequiredButAbsent is the defence in
// depth behind the availability probe. Preflight is an OPTIONAL step in the
// ceremony contract, so a caller that skips it must still be refused rather
// than handed a software credential.
func TestFactor_EnrollRefusesWhenAGeneratorIsRequiredButAbsent(t *testing.T) {
	f := New(Config{RequireGenerator: true})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID:   "administrator",
		TenantID: "system",
	})
	if err == nil {
		t.Fatal("Enroll must refuse when a generator is required and none is attached")
	}
	if enrollment != nil {
		t.Error("a refused enrollment must return no enrollment")
	}
	var unattached *GeneratorUnattachedError
	if !errors.As(err, &unattached) {
		t.Fatalf("err = %T (%v), want *GeneratorUnattachedError", err, err)
	}
}

// TestFactor_SignNonceRefusesWhenAGeneratorIsRequiredButAbsent verifies the
// custodian-side signing helper refuses too, so no code path in the package
// dereferences a deliberately absent generator.
func TestFactor_SignNonceRefusesWhenAGeneratorIsRequiredButAbsent(t *testing.T) {
	f := New(Config{RequireGenerator: true})
	sig, err := f.SignNonce(context.Background(), pivcert.PIVSlotAuthentication, []byte("nonce"))
	if err == nil {
		t.Fatal("SignNonce must refuse when a generator is required and none is attached")
	}
	if sig != nil {
		t.Error("a refused signature must return no bytes")
	}
	var unattached *GeneratorUnattachedError
	if !errors.As(err, &unattached) {
		t.Fatalf("err = %T (%v), want *GeneratorUnattachedError", err, err)
	}
}

// TestGeneratorUnattachedError_Message verifies the error names its origin and
// carries the operator-facing remedy, per the Go error-string convention.
func TestGeneratorUnattachedError_Message(t *testing.T) {
	msg := (&GeneratorUnattachedError{}).Error()
	if msg == "" {
		t.Fatal("GeneratorUnattachedError must carry a message")
	}
	if want := "piv: " + NoGeneratorReason; msg != want {
		t.Errorf("Error() = %q, want %q", msg, want)
	}
}
