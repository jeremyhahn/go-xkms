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

package fido2

import (
	"context"
	"errors"
	"testing"

	pkgfido2 "github.com/jeremyhahn/go-xkms/pkg/fido2"
)

// TestLocalCeremony_Available_UnwiredSubsystem pins the nil-wiring guard: a
// LocalCeremony missing either collaborator (not just an empty device list)
// must report unavailable with a build-time explanation, not panic.
func TestLocalCeremony_Available_UnwiredSubsystem(t *testing.T) {
	t.Run("nil devices", func(t *testing.T) {
		c := newLocalCeremony(nil, &fakeCeremony{}, 0)
		ok, reason := c.Available(context.Background())
		if ok || reason == "" {
			t.Fatalf("Available() = (%v, %q), want (false, non-empty)", ok, reason)
		}
	})
	t.Run("nil ceremony", func(t *testing.T) {
		c := newLocalCeremony(&fakeDevices{}, nil, 0)
		ok, reason := c.Available(context.Background())
		if ok || reason == "" {
			t.Fatalf("Available() = (%v, %q), want (false, non-empty)", ok, reason)
		}
	})
	t.Run("nil receiver", func(t *testing.T) {
		var c *LocalCeremony
		ok, reason := c.Available(context.Background())
		if ok || reason == "" {
			t.Fatalf("Available() = (%v, %q), want (false, non-empty)", ok, reason)
		}
	})
}

// TestLocalCeremony_Available_EnumerationError pins the ListDevices
// failure path: an enumeration error must surface as unavailable with the
// underlying reason, not be swallowed as "no authenticator".
func TestLocalCeremony_Available_EnumerationError(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{err: errors.New("hidraw permission denied")}, &fakeCeremony{}, 0)
	ok, reason := c.Available(context.Background())
	if ok {
		t.Fatal("Available() = true despite an enumeration error")
	}
	if reason == "" {
		t.Error("Available() must explain the enumeration failure")
	}
}

// TestLocalCeremony_Enroll_UnwiredSubsystem pins Enroll's own nil-wiring
// guard, distinct from Available's.
func TestLocalCeremony_Enroll_UnwiredSubsystem(t *testing.T) {
	c := newLocalCeremony(nil, nil, 0)
	_, err := c.Enroll(context.Background(), localRequest())
	if !errors.Is(err, ErrLocalCeremonyUnavailable) {
		t.Fatalf("Enroll = %v, want ErrLocalCeremonyUnavailable", err)
	}
}

// TestLocalCeremony_Enroll_EnumerationErrorDuringSelection pins that a
// ListDevices failure inside selectDevice surfaces as a wrapped
// *LocalCeremonyError at the "enumerate" stage, and the authenticator is
// never touched.
func TestLocalCeremony_Enroll_EnumerationErrorDuringSelection(t *testing.T) {
	ceremony := &fakeCeremony{}
	c := newLocalCeremony(&fakeDevices{err: errors.New("hidraw permission denied")}, ceremony, 0)

	_, err := c.Enroll(context.Background(), localRequest())
	var ceremonyErr *LocalCeremonyError
	if !errors.As(err, &ceremonyErr) || ceremonyErr.Stage != "enumerate" {
		t.Fatalf("Enroll = %v, want *LocalCeremonyError{Stage: enumerate}", err)
	}
	if ceremony.called {
		t.Error("the authenticator must not be touched when enumeration fails")
	}
}

// TestLocalCeremony_Enroll_NoAuthenticatorAttached pins selectDevice's
// zero-device branch, distinct from Available's own check: Enroll must
// refuse rather than proceed to drive a nonexistent authenticator.
func TestLocalCeremony_Enroll_NoAuthenticatorAttached(t *testing.T) {
	c := newLocalCeremony(&fakeDevices{}, &fakeCeremony{}, 0)
	_, err := c.Enroll(context.Background(), localRequest())
	if !errors.Is(err, ErrNoAuthenticator) {
		t.Fatalf("Enroll = %v, want ErrNoAuthenticator", err)
	}
}

// TestMatchesHint_MatchesManufacturerAndSerial pins the substring-match
// fields matchesHint consults beyond Product, so an operator can select a
// device by manufacturer name or serial number alone.
func TestMatchesHint_MatchesManufacturerAndSerial(t *testing.T) {
	d := pkgfido2.Device{Path: "/dev/hidraw0", Manufacturer: "Yubico", Product: "YubiKey 5 NFC", SerialNumber: "ABC123"}

	if !matchesHint(d, "yubico") {
		t.Error("expected a case-insensitive manufacturer match")
	}
	if !matchesHint(d, "abc123") {
		t.Error("expected a case-insensitive serial number match")
	}
	if matchesHint(d, "nonexistent") {
		t.Error("expected no match for an unrelated hint")
	}
}

// TestDescribeDevice_FallsBackToPath pins the empty-manufacturer/product
// fallback: a device with neither reported falls back to its device path so
// the operator-facing message is never a bare empty string.
func TestDescribeDevice_FallsBackToPath(t *testing.T) {
	d := pkgfido2.Device{Path: "/dev/hidraw3"}
	if got := describeDevice(d); got != "/dev/hidraw3" {
		t.Fatalf("describeDevice = %q, want the device path", got)
	}
}

// TestCredentialFromAttestation_MalformedDocument pins the parse-error
// path: an attestation whose PublicKeyCredentialJSON is not a valid
// WebAuthn document surfaces the parser's error rather than a zero-value
// success.
func TestCredentialFromAttestation_MalformedDocument(t *testing.T) {
	_, _, err := credentialFromAttestation(&pkgfido2.WebAuthnAttestation{
		PublicKeyCredentialJSON: []byte(`{not valid json`),
	})
	if err == nil {
		t.Fatal("expected a parse error for a malformed attestation document")
	}
}
