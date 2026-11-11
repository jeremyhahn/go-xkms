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
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
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

// TestFIDO2Factor_Enroll_RefusesMalformedOriginsAndUV pins each refusal of an
// "origins" or "require_user_verification" value Enroll cannot record: the
// enrollment is refused with a typed EnrollmentInvalidError naming the
// parameter and why, and no enrollment is returned. An origin list recorded
// wrongly would widen the origins Verify accepts.
func TestFIDO2Factor_Enroll_RefusesMalformedOriginsAndUV(t *testing.T) {
	cases := []struct {
		name   string
		param  string
		value  any
		reason string
	}{
		{"empty origin string", "origins", "", "origins must not be empty"},
		{"empty origin list of any", "origins", []any{}, "origins must not be empty"},
		{"origin list with a non-string", "origins", []any{"https://example.com", 7}, "origins must be non-empty strings"},
		{"origin list with an empty string", "origins", []any{"https://example.com", ""}, "origins must be non-empty strings"},
		{"origins of the wrong type", "origins", 42, "origins must be a string or []string"},
		{"unparseable require_user_verification", "require_user_verification", "maybe", "require_user_verification must be a bool"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := newAuthenticator(t, "example.com")
			enrollment, err := New(Config{RPID: "example.com"}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
				UserID: "custodian-1",
				MethodParams: map[string]any{
					"cose_public_key": base64.StdEncoding.EncodeToString(a.coseKey(t)),
					"credential_id":   base64.RawURLEncoding.EncodeToString([]byte("credential-id-1")),
					tc.param:          tc.value,
				},
			})
			var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
			if !errors.As(err, &inv) {
				t.Fatalf("Enroll err = %v, want EnrollmentInvalidError", err)
			}
			if !strings.Contains(inv.Reason, tc.reason) {
				t.Errorf("Reason = %q, want it to contain %q", inv.Reason, tc.reason)
			}
			if enrollment != nil {
				t.Errorf("Enroll returned enrollment %+v alongside its refusal", enrollment)
			}
		})
	}
}

// TestFIDO2Factor_Enroll_RecordsEachAcceptedParamShape pins the accepted
// shapes the refusals above border on: a single origin string, an origin
// list decoded from JSON as []any, and a require_user_verification string.
func TestFIDO2Factor_Enroll_RecordsEachAcceptedParamShape(t *testing.T) {
	cases := []struct {
		name  string
		param string
		value any
		key   string
		want  string
	}{
		{"single origin string", "origins", "https://login.example.com", "origins", "https://login.example.com"},
		{"origin list of any", "origins", []any{"https://example.com", "https://www.example.com"}, "origins", "https://example.com,https://www.example.com"},
		{"require_user_verification string", "require_user_verification", "false", "require_uv", "false"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := New(Config{RPID: "example.com"})
			enrollment := enrollWithParams(t, f, newAuthenticator(t, "example.com"), map[string]any{tc.param: tc.value})
			if got := enrollment.Metadata[tc.key]; got != tc.want {
				t.Errorf("Metadata[%q] = %q, want %q", tc.key, got, tc.want)
			}
		})
	}
}
