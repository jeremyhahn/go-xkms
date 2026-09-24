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

package fido2

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// TestDecodeB64 pins the standard/raw-url dual decoding: a value that
// decodes under standard base64 is used as-is, one that only decodes under
// raw-url base64 falls back to it, and a value that decodes under neither
// (or is empty) is a typed decodeError.
func TestDecodeB64(t *testing.T) {
	want := []byte("fido2-needle")

	t.Run("standard encoding", func(t *testing.T) {
		got, err := decodeB64(base64.StdEncoding.EncodeToString(want))
		if err != nil {
			t.Fatalf("decodeB64: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("decodeB64 = %q, want %q", got, want)
		}
	})

	t.Run("raw url encoding falls back", func(t *testing.T) {
		// This 5-byte payload's raw-url encoding ("5ojOEEg", unpadded, 7
		// chars) is not valid input for StdEncoding.DecodeString (which
		// requires padding to a multiple of 4), so decodeB64 must fall
		// through to the RawURLEncoding branch to decode it at all.
		urlOnly := []byte{0xe6, 0x88, 0xce, 0x10, 0x48}
		encoded := base64.RawURLEncoding.EncodeToString(urlOnly)
		if _, err := base64.StdEncoding.DecodeString(encoded); err == nil {
			t.Fatalf("test payload %q decodes under StdEncoding too; pick one that doesn't", encoded)
		}

		got, err := decodeB64(encoded)
		if err != nil {
			t.Fatalf("decodeB64: %v", err)
		}
		if string(got) != string(urlOnly) {
			t.Fatalf("decodeB64 = %v, want %v", got, urlOnly)
		}
	})

	t.Run("empty value", func(t *testing.T) {
		_, err := decodeB64("")
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("decodeB64(\"\") err = %v, want *decodeError", err)
		}
	})

	t.Run("invalid in both encodings", func(t *testing.T) {
		_, err := decodeB64("not-valid-base64!!!")
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("decodeB64(invalid) err = %v, want *decodeError", err)
		}
	})
}

// TestExtractBytes pins every accepted shape (nil, []byte, string) and
// their failure modes, plus the default branch for an unsupported type.
func TestExtractBytes(t *testing.T) {
	t.Run("nil is required", func(t *testing.T) {
		_, err := extractBytes(nil)
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("extractBytes(nil) err = %v, want *decodeError", err)
		}
	})

	t.Run("empty []byte", func(t *testing.T) {
		_, err := extractBytes([]byte{})
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("extractBytes([]byte{}) err = %v, want *decodeError", err)
		}
	})

	t.Run("non-empty []byte passes through", func(t *testing.T) {
		want := []byte{1, 2, 3}
		got, err := extractBytes(want)
		if err != nil {
			t.Fatalf("extractBytes: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("extractBytes = %v, want %v", got, want)
		}
	})

	t.Run("empty string", func(t *testing.T) {
		_, err := extractBytes("")
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("extractBytes(\"\") err = %v, want *decodeError", err)
		}
	})

	t.Run("string decodes via decodeB64", func(t *testing.T) {
		want := []byte("fido2-needle")
		got, err := extractBytes(base64.StdEncoding.EncodeToString(want))
		if err != nil {
			t.Fatalf("extractBytes: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("extractBytes = %q, want %q", got, want)
		}
	})

	t.Run("unsupported type", func(t *testing.T) {
		_, err := extractBytes(42)
		var de *decodeError
		if !errors.As(err, &de) {
			t.Fatalf("extractBytes(42) err = %v, want *decodeError", err)
		}
	})
}

// TestFactor_Available_NoLocalCeremony pins the always-available default:
// the ordinary server-side factor (no local ceremony configured) reports
// available regardless of what hardware this host has attached.
func TestFactor_Available_NoLocalCeremony(t *testing.T) {
	f := New(Config{})
	ok, reason := f.Available(context.Background())
	if !ok {
		t.Fatalf("Available() = false (%s), want true with no local ceremony", reason)
	}
}

// TestNewWithLocalCeremony_DelegatesAvailability pins that
// NewWithLocalCeremony wires the local driver in, so Available() reflects
// its answer instead of the always-true default.
func TestNewWithLocalCeremony_DelegatesAvailability(t *testing.T) {
	local := newLocalCeremony(&fakeDevices{}, &fakeCeremony{}, 0)
	f := NewWithLocalCeremony(Config{RPID: "example.com"}, local)

	ok, reason := f.Available(context.Background())
	if ok {
		t.Fatal("Available() = true, want false: the local ceremony has no attached authenticator")
	}
	if reason == "" {
		t.Error("Available() must explain why it is unavailable")
	}
	if f.Name() != FactorName {
		t.Fatalf("Name() = %q, want %q", f.Name(), FactorName)
	}
}
