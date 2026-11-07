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
	"strings"
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
	if !strings.Contains(err.Error(), "enumerate: hidraw permission denied") {
		t.Errorf("error %q does not name the failed stage and its cause", err)
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

// TestLocalCeremony_Enroll_SelectionRefusalsGuideTheOperator pins each
// device-selection refusal: its typed error, an untouched authenticator, and
// a message naming what the operator must act on — the selector flag, the
// unmatched hint — and every candidate device.
func TestLocalCeremony_Enroll_SelectionRefusalsGuideTheOperator(t *testing.T) {
	isAmbiguous := func(err error) bool {
		var target *AmbiguousAuthenticatorError
		return errors.As(err, &target)
	}
	cases := []struct {
		name    string
		devices *fakeDevices
		hint    string
		isType  func(error) bool
		want    []string
	}{
		{
			name:    "several authenticators and no selector",
			devices: &fakeDevices{devices: []pkgfido2.Device{yubi("1"), yubi("2")}},
			isType:  isAmbiguous,
			want:    []string{"--passkey-device", describeDevice(yubi("1")), describeDevice(yubi("2"))},
		},
		{
			name:    "selector matching several authenticators",
			devices: &fakeDevices{devices: []pkgfido2.Device{yubi("1"), yubi("2")}},
			hint:    "yubikey",
			isType:  isAmbiguous,
			want:    []string{"--passkey-device", describeDevice(yubi("1")), describeDevice(yubi("2"))},
		},
		{
			name:    "selector matching nothing",
			devices: &fakeDevices{devices: []pkgfido2.Device{yubi("111")}},
			hint:    "nonexistent",
			isType: func(err error) bool {
				var target *AuthenticatorNotFoundError
				return errors.As(err, &target)
			},
			want: []string{`"nonexistent"`, "attached: " + describeDevice(yubi("111"))},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ceremony := &fakeCeremony{}
			req := localRequest()
			req.DeviceHint = tc.hint

			_, err := newLocalCeremony(tc.devices, ceremony, 0).Enroll(context.Background(), req)
			if !tc.isType(err) {
				t.Fatalf("Enroll = %v (%T), not the refusal's typed error", err, err)
			}
			for _, w := range tc.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q does not name %q", err, w)
				}
			}
			if ceremony.called {
				t.Error("the authenticator must not be touched when selection is refused")
			}
		})
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
	if !matchesHint(d, "/dev/hidraw0") {
		t.Error("expected an exact device path match")
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
