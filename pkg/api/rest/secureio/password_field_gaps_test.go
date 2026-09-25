// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package secureio

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestBadBodyError_Unwrap_NilReceiver covers the nil-receiver guard in
// Unwrap — calling Unwrap on a nil *BadBodyError must return nil
// rather than panicking on the nil pointer dereference.
func TestBadBodyError_Unwrap_NilReceiver(t *testing.T) {
	var e *BadBodyError
	if got := e.Unwrap(); got != nil {
		t.Fatalf("Unwrap() on nil receiver = %v, want nil", got)
	}
}

// TestPasswordField_Buffer_NilReceiver covers the nil-receiver guard
// in Buffer — calling Buffer on a nil *PasswordField must return nil
// rather than panicking.
func TestPasswordField_Buffer_NilReceiver(t *testing.T) {
	var f *PasswordField
	if got := f.Buffer(); got != nil {
		t.Fatalf("Buffer() on nil receiver = %v, want nil", got)
	}
}

// TestPasswordField_Size_NilReceiver covers the nil-receiver branch of
// Size (as distinct from the zero-value struct already covered
// elsewhere) — calling Size on a nil *PasswordField must return 0.
func TestPasswordField_Size_NilReceiver(t *testing.T) {
	var f *PasswordField
	if got := f.Size(); got != 0 {
		t.Fatalf("Size() on nil receiver = %d, want 0", got)
	}
}

// TestPasswordField_Destroy_NilReceiver covers the nil-receiver guard
// in Destroy — calling Destroy on a nil *PasswordField (as opposed to
// a zero-value PasswordField) must be a no-op, not a panic.
func TestPasswordField_Destroy_NilReceiver(t *testing.T) {
	var f *PasswordField
	f.Destroy() // must not panic
}

// TestPasswordField_UnmarshalJSON_EmptyData covers the len(data) == 0
// guard directly. json.Decoder never invokes UnmarshalJSON with a
// zero-length token, so this branch is only reachable via a direct
// call — as would happen if a caller invoked encoding.TextUnmarshaler
// style code paths with an empty buffer.
func TestPasswordField_UnmarshalJSON_EmptyData(t *testing.T) {
	var f PasswordField
	if err := f.UnmarshalJSON(nil); err != nil {
		t.Fatalf("UnmarshalJSON(nil) = %v, want nil", err)
	}
	if f.Buffer() != nil {
		t.Fatal("Buffer() should be nil after UnmarshalJSON(nil)")
	}

	var f2 PasswordField
	if err := f2.UnmarshalJSON([]byte{}); err != nil {
		t.Fatalf("UnmarshalJSON([]byte{}) = %v, want nil", err)
	}
	if f2.Buffer() != nil {
		t.Fatal("Buffer() should be nil after UnmarshalJSON([]byte{})")
	}
}

// TestPasswordField_UnmarshalJSON_ShortToken covers the len(data) < 2
// guard directly — a single-character token can never be a properly
// quoted JSON string, and json.Decoder itself would never dispatch
// such a malformed token, so it must be exercised via a direct call.
func TestPasswordField_UnmarshalJSON_ShortToken(t *testing.T) {
	var f PasswordField
	err := f.UnmarshalJSON([]byte(`"`))
	if err == nil {
		t.Fatal("expected error for single-quote token, got nil")
	}
	var bad *BadBodyError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadBodyError, got %T: %v", err, err)
	}
	if bad.Unwrap() == nil {
		t.Fatal("BadBodyError should wrap underlying cause")
	}
	if !errors.Is(err, ErrPasswordFieldNotString) {
		t.Fatalf("expected errors.Is to match ErrPasswordFieldNotString, got %v", err)
	}
}

// TestPasswordField_UnmarshalJSON_DecodedLenZero covers the
// maxLen <= 0 guard — a base64 payload shorter than 4 characters
// decodes to a maximum length of 0 bytes (base64.StdEncoding.DecodedLen
// rounds down), which must surface as *BadBodyError rather than
// attempting to allocate a zero-length secure.Buffer.
func TestPasswordField_UnmarshalJSON_DecodedLenZero(t *testing.T) {
	cases := []string{"A", "AB", "ABC"}
	for _, encoded := range cases {
		encoded := encoded
		t.Run(encoded, func(t *testing.T) {
			body := `{"password_b64":"` + encoded + `"}`
			var req struct {
				Password PasswordField `json:"password_b64"`
			}
			err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
			if err == nil {
				t.Fatalf("expected error decoding %q, got nil", encoded)
			}
			var bad *BadBodyError
			if !errors.As(err, &bad) {
				t.Fatalf("expected *BadBodyError, got %T: %v", err, err)
			}
			if bad.Unwrap() == nil {
				t.Fatal("BadBodyError should wrap underlying cause")
			}
			if !errors.Is(err, ErrPasswordFieldEmptyAfterDecode) {
				t.Fatalf("expected errors.Is to match ErrPasswordFieldEmptyAfterDecode, got %v", err)
			}
			if req.Password.Buffer() != nil {
				t.Fatal("Buffer() should remain nil on decode failure")
			}
		})
	}
}
