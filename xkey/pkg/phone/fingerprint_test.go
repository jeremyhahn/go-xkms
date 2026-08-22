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

package phone

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
)

func TestDecodeDeviceFingerprint_ValidHexDecodes(t *testing.T) {
	want := bytes.Repeat([]byte{0xab}, DeviceFingerprintSize)

	got, err := DecodeDeviceFingerprint(hex.EncodeToString(want))
	if err != nil {
		t.Fatalf("DecodeDeviceFingerprint() error = %v, want nil", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("DecodeDeviceFingerprint() = %x, want %x", got, want)
	}
}

// The empty string is the legitimate "no fingerprint policy configured" state
// and must stay distinguishable from a present-but-invalid one.
func TestDecodeDeviceFingerprint_EmptyIsNoPolicy(t *testing.T) {
	got, err := DecodeDeviceFingerprint("")
	if err != nil {
		t.Fatalf("DecodeDeviceFingerprint(\"\") error = %v, want nil", err)
	}
	if got != nil {
		t.Fatalf("DecodeDeviceFingerprint(\"\") = %x, want nil", got)
	}
}

// The security property: a non-empty value that does not decode is an error,
// never an absent policy. Returning (nil, nil) here would hand the handshake
// the same signal an unconfigured device gives it.
func TestDecodeDeviceFingerprint_MalformedFailsClosed(t *testing.T) {
	// Every one of these is refused; which check catches them is not the
	// point of this test (length vs hex is covered separately below).
	malformed := []string{
		"not-valid-hex-!!!",
		"aabbccddz",  // non-hex digit
		"aabbccdde",  // odd length
		"  aabbccdd", // leading whitespace is not hex
		strings.Repeat("zz", DeviceFingerprintSize), // right length, not hex
	}

	for _, encoded := range malformed {
		t.Run(encoded, func(t *testing.T) {
			got, err := DecodeDeviceFingerprint(encoded)
			if err == nil {
				t.Fatalf("DecodeDeviceFingerprint(%q) error = nil, want an error", encoded)
			}
			if got != nil {
				t.Fatalf("DecodeDeviceFingerprint(%q) = %x, want no bytes alongside the error", encoded, got)
			}
			if !errors.Is(err, ErrInvalidDeviceFingerprint) {
				t.Fatalf("DecodeDeviceFingerprint(%q) error = %v, want ErrInvalidDeviceFingerprint", encoded, err)
			}
		})
	}
}

func TestDecodeDeviceFingerprint_ErrorCarriesValueAndCause(t *testing.T) {
	// Correct LENGTH, invalid hex -- the length check now runs first, so a
	// short bad value reports its length rather than reaching the decoder.
	// This one has to get past that check to exercise the hex path at all.
	encoded := strings.Repeat("zz", DeviceFingerprintSize)

	_, err := DecodeDeviceFingerprint(encoded)

	var fpErr *InvalidDeviceFingerprintError
	if !errors.As(err, &fpErr) {
		t.Fatalf("error type = %T, want *InvalidDeviceFingerprintError", err)
	}
	// Value is a bounded PREFIX of the offending input, not the whole of it,
	// and ValueLen carries the length truncation removes.
	if !strings.HasPrefix(encoded, fpErr.Value) {
		t.Fatalf("InvalidDeviceFingerprintError.Value = %q, want a prefix of %q", fpErr.Value, encoded)
	}
	if len(fpErr.Value) > maxReportedFingerprint {
		t.Fatalf("retained value is %d chars, want at most %d", len(fpErr.Value), maxReportedFingerprint)
	}
	if fpErr.ValueLen != len(encoded) {
		t.Fatalf("ValueLen = %d, want %d", fpErr.ValueLen, len(encoded))
	}

	var hexErr hex.InvalidByteError
	if !errors.As(err, &hexErr) {
		t.Fatalf("error should unwrap to the hex decoding cause, got %v", err)
	}
}

// The device always presents exactly DeviceFingerprintSize bytes, so a stored
// value of any other length can never match. Left to the handshake it surfaces
// as "device fingerprint mismatch" -- accusing the device of being the wrong
// one when the stored record is simply unusable.
func TestDecodeDeviceFingerprint_WrongLengthFailsClosed(t *testing.T) {
	tests := []struct {
		name    string
		encoded string
	}{
		{"truncated to one byte", "aa"},
		{"one byte short", strings.Repeat("aa", DeviceFingerprintSize-1)},
		{"one byte long", strings.Repeat("aa", DeviceFingerprintSize+1)},
		{"double length", strings.Repeat("aa", DeviceFingerprintSize*2)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecodeDeviceFingerprint(tt.encoded)
			if err == nil {
				t.Fatalf("DecodeDeviceFingerprint(%q) error = nil, want an error", tt.encoded)
			}
			if got != nil {
				t.Fatalf("DecodeDeviceFingerprint(%q) = %x, want no bytes alongside the error", tt.encoded, got)
			}
			if !errors.Is(err, ErrInvalidDeviceFingerprint) {
				t.Fatalf("DecodeDeviceFingerprint(%q) error = %v, want ErrInvalidDeviceFingerprint", tt.encoded, err)
			}
		})
	}
}

// The exact length the wire contract fixes is accepted.
func TestDecodeDeviceFingerprint_ExactLengthAccepted(t *testing.T) {
	encoded := strings.Repeat("5a", DeviceFingerprintSize)

	got, err := DecodeDeviceFingerprint(encoded)
	if err != nil {
		t.Fatalf("DecodeDeviceFingerprint() error = %v, want nil", err)
	}
	if len(got) != DeviceFingerprintSize {
		t.Fatalf("DecodeDeviceFingerprint() length = %d, want %d", len(got), DeviceFingerprintSize)
	}
}

// A corrupted or synchronised config can carry an arbitrarily long run of
// valid hex. The length check runs BEFORE hex.DecodeString, so such a value is
// refused without allocating half its size, and the error truncates it rather
// than carrying the whole thing into every caller's log.
func TestDecodeDeviceFingerprint_OversizedValidHexIsRefusedCheaply(t *testing.T) {
	huge := strings.Repeat("ab", 512*1024) // 1 MiB of perfectly valid hex

	got, err := DecodeDeviceFingerprint(huge)
	if err == nil {
		t.Fatal("a 1 MiB valid-hex fingerprint was accepted")
	}
	if got != nil {
		t.Fatalf("refused value still returned %d bytes", len(got))
	}
	if !errors.Is(err, ErrInvalidDeviceFingerprint) {
		t.Fatalf("error = %v, want ErrInvalidDeviceFingerprint", err)
	}

	// The whole value must not reach the error string, and through it the log.
	msg := err.Error()
	if len(msg) > 256 {
		t.Fatalf("error string is %d bytes; the offending value is not bounded", len(msg))
	}
	if strings.Contains(msg, huge) {
		t.Fatal("the full oversized value was carried into the error")
	}
}

// The type and its fields are EXPORTED, so any downstream package can build a
// zero value or set Value without Err. Formatting one must not panic: an error
// type that takes the process down while being reported converts a handled
// failure into an outage, which is strictly worse than what it was describing.
func TestInvalidDeviceFingerprintError_FormattingIsNilSafe(t *testing.T) {
	cases := []struct {
		name string
		err  *InvalidDeviceFingerprintError
	}{
		{"zero value", &InvalidDeviceFingerprintError{}},
		{"value without cause", &InvalidDeviceFingerprintError{Value: "abcd"}},
		{"cause without value", &InvalidDeviceFingerprintError{Err: errors.New("boom")}},
		{"nil receiver", nil},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// Both the direct call and the fmt path: fmt recovers a panic into
			// a %!v(PANIC=...) string rather than crashing, so asserting only
			// on fmt would hide exactly the bug this guards.
			msg := tc.err.Error()
			if msg == "" {
				t.Fatal("Error() returned an empty string")
			}
			if formatted := fmt.Sprintf("%v", tc.err); strings.Contains(formatted, "PANIC") {
				t.Fatalf("formatting panicked: %s", formatted)
			}

			// Unwrap must stay usable, and must not hand out a nil element for
			// a missing cause.
			for _, u := range tc.err.Unwrap() {
				if u == nil {
					t.Fatal("Unwrap returned a nil element")
				}
			}
			if !errors.Is(tc.err, ErrInvalidDeviceFingerprint) {
				t.Error("errors.Is no longer matches the sentinel")
			}
		})
	}
}

// Bounded RETENTION, not merely bounded display. An error that formats to
// something short while holding a megabyte of corrupted config keeps that
// megabyte alive for as long as any caller holds the error, which is what the
// oversized-input test's claim actually requires.
func TestInvalidDeviceFingerprintError_RetainsOnlyABoundedPrefix(t *testing.T) {
	huge := strings.Repeat("ab", 512*1024) // 1 MiB of valid hex

	_, err := DecodeDeviceFingerprint(huge)

	var fpErr *InvalidDeviceFingerprintError
	if !errors.As(err, &fpErr) {
		t.Fatalf("error type = %T, want *InvalidDeviceFingerprintError", err)
	}
	if len(fpErr.Value) > maxReportedFingerprint {
		t.Fatalf("the error retains %d characters of the offending value; "+
			"want at most %d -- truncating only in Error() bounds the log, not the heap",
			len(fpErr.Value), maxReportedFingerprint)
	}
	if fpErr.ValueLen != len(huge) {
		t.Fatalf("ValueLen = %d, want %d: the true length must survive truncation",
			fpErr.ValueLen, len(huge))
	}
	if !strings.Contains(fpErr.Error(), strconv.Itoa(len(huge))) {
		t.Error("the error string should report the original length")
	}
}
