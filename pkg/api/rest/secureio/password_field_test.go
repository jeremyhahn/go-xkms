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
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// TestPasswordField_UnmarshalJSON_Happy covers the mainline path:
// base64 JSON string decodes into a right-sized Buffer and Bytes()
// matches the original plaintext.
func TestPasswordField_UnmarshalJSON_Happy(t *testing.T) {
	tests := []struct {
		name      string
		plaintext []byte
	}{
		{"ascii", []byte("correct horse battery staple")},
		{"single-byte", []byte{0x7f}},
		{"binary", []byte{0x00, 0xff, 0xde, 0xad, 0xbe, 0xef}},
		{"long", bytes.Repeat([]byte{0xa5}, 4096)},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			encoded := base64.StdEncoding.EncodeToString(tc.plaintext)
			body := `{"password_b64":"` + encoded + `"}`

			var req struct {
				Password PasswordField `json:"password_b64"`
			}
			if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
				t.Fatalf("decode: %v", err)
			}
			defer req.Password.Destroy()

			if got := req.Password.Size(); got != len(tc.plaintext) {
				t.Fatalf("size mismatch: got %d want %d", got, len(tc.plaintext))
			}
			buf := req.Password.Buffer()
			if buf == nil {
				t.Fatal("Buffer() returned nil")
			}
			if !bytes.Equal(buf.Bytes(), tc.plaintext) {
				t.Fatalf("plaintext mismatch")
			}
		})
	}
}

// TestPasswordField_UnmarshalJSON_Null verifies a JSON null leaves
// the field as a zero value (no Buffer allocated).
func TestPasswordField_UnmarshalJSON_Null(t *testing.T) {
	body := `{"password_b64":null}`
	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	defer req.Password.Destroy()

	if req.Password.Buffer() != nil {
		t.Fatal("Buffer() should be nil for JSON null")
	}
	if req.Password.Size() != 0 {
		t.Fatalf("Size() = %d, want 0", req.Password.Size())
	}
}

// TestPasswordField_UnmarshalJSON_Empty verifies an empty JSON string
// leaves the field unset (Size == 0).
func TestPasswordField_UnmarshalJSON_Empty(t *testing.T) {
	body := `{"password_b64":""}`
	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	defer req.Password.Destroy()

	if req.Password.Size() != 0 {
		t.Fatalf("Size() = %d, want 0", req.Password.Size())
	}
}

// TestPasswordField_UnmarshalJSON_InvalidBase64 exercises the error
// path — malformed base64 must return *BadBodyError with a non-nil
// wrapped cause.
func TestPasswordField_UnmarshalJSON_InvalidBase64(t *testing.T) {
	body := `{"password_b64":"!!!not-base64!!!"}`
	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	var bad *BadBodyError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadBodyError, got %T: %v", err, err)
	}
	if bad.Unwrap() == nil {
		t.Fatal("BadBodyError should wrap underlying cause")
	}
}

// TestPasswordField_UnmarshalJSON_NonString exercises the error path
// when the JSON value is not a string.
func TestPasswordField_UnmarshalJSON_NonString(t *testing.T) {
	cases := []string{
		`{"password_b64":12345}`,
		`{"password_b64":true}`,
		`{"password_b64":[]}`,
	}
	for _, body := range cases {
		body := body
		t.Run(body, func(t *testing.T) {
			var req struct {
				Password PasswordField `json:"password_b64"`
			}
			err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
			if err == nil {
				t.Fatalf("expected error, got nil body=%s", body)
			}
			if !errors.Is(err, ErrPasswordFieldNotString) {
				t.Fatalf("expected errors.Is to match ErrPasswordFieldNotString, got %v", err)
			}
		})
	}
}

// TestPasswordField_Destroy_Idempotent verifies Destroy is safe to
// call multiple times and on a zero value.
func TestPasswordField_Destroy_Idempotent(t *testing.T) {
	// Zero value
	var zero PasswordField
	zero.Destroy()
	zero.Destroy()

	// After populated decode + Destroy, calling again is a no-op.
	body := `{"password_b64":"` + base64.StdEncoding.EncodeToString([]byte("secret")) + `"}`
	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	req.Password.Destroy()
	if req.Password.Buffer() != nil {
		t.Fatal("Buffer() should be nil after Destroy")
	}
	req.Password.Destroy() // second call must not panic
}

// TestPasswordField_NoStringFields is a reflection-free compile-time
// witness: the PasswordField struct contains only the unexported
// *secure.Buffer, so no Go string carrying the plaintext can escape
// through struct inspection / JSON re-serialization.
func TestPasswordField_NoStringFields(t *testing.T) {
	// The type has a single unexported Buffer field. A direct
	// json.Marshal of a populated PasswordField must NOT include
	// the plaintext — only the empty object (because the field is
	// unexported).
	encoded := base64.StdEncoding.EncodeToString([]byte("needle-marker"))
	body := `{"password_b64":"` + encoded + `"}`
	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("decode: %v", err)
	}
	defer req.Password.Destroy()

	out, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if bytes.Contains(out, []byte("needle-marker")) {
		t.Fatalf("plaintext leaked through marshal: %s", out)
	}
	if bytes.Contains(out, []byte(encoded)) {
		t.Fatalf("encoded form leaked through marshal: %s", out)
	}
}

// TestBadBodyError_FormatAndUnwrap covers the error type accessors
// against nil and non-nil Err values.
func TestBadBodyError_FormatAndUnwrap(t *testing.T) {
	cases := []struct {
		name string
		err  *BadBodyError
		msg  string
	}{
		{"nil-receiver", nil, "secureio: bad body"},
		{"empty", &BadBodyError{}, "secureio: bad body"},
		{"wrapped", &BadBodyError{Err: errors.New("boom")}, "secureio: bad body: boom"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if tc.err.Error() != tc.msg {
				t.Fatalf("Error(): got %q want %q", tc.err.Error(), tc.msg)
			}
			if tc.err != nil && tc.err.Err != nil {
				if tc.err.Unwrap() == nil {
					t.Fatal("Unwrap() should expose underlying err")
				}
			}
		})
	}
}

// TestPasswordField_UnmarshalJSON_TooLarge verifies that a password_b64
// field whose decoded length would exceed MaxPasswordFieldBytes is
// rejected with *BadBodyError wrapping ErrPasswordTooLarge, and that NO
// protected buffer is allocated for it (go-xkms#121). Without the cap
// the field would allocate an mlocked buffer proportional to attacker
// input, the memlock-exhaustion vector this bound closes.
func TestPasswordField_UnmarshalJSON_TooLarge(t *testing.T) {
	oversized := bytes.Repeat([]byte{0x5a}, 2*MaxPasswordFieldBytes)
	encoded := base64.StdEncoding.EncodeToString(oversized)
	body := `{"password_b64":"` + encoded + `"}`

	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
	defer req.Password.Destroy()
	if err == nil {
		t.Fatal("expected error for oversized password_b64, got nil")
	}
	if !errors.Is(err, ErrPasswordTooLarge) {
		t.Fatalf("expected ErrPasswordTooLarge, got %T: %v", err, err)
	}
	var bad *BadBodyError
	if !errors.As(err, &bad) {
		t.Fatalf("expected *BadBodyError wrapper, got %T", err)
	}
	if req.Password.Buffer() != nil || req.Password.Size() != 0 {
		t.Fatal("no buffer must be allocated when the cap rejects the field")
	}
}

// TestPasswordField_UnmarshalJSON_CapBoundary drives both sides of the
// real default cap: a secret of exactly MaxPasswordFieldBytes is
// accepted and one byte over is rejected. The cap is compared against
// the EXACT decoded length (padding subtracted), so this must hold for
// lengths whose base64 DecodedLen upper bound overshoots the cap — the
// exact case a decoded-length-upper-bound check would get wrong.
func TestPasswordField_UnmarshalJSON_CapBoundary(t *testing.T) {
	decode := func(plaintextLen int) (int, error) {
		encoded := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x1}, plaintextLen))
		var req struct {
			Password PasswordField `json:"password_b64"`
		}
		err := json.NewDecoder(strings.NewReader(`{"password_b64":"` + encoded + `"}`)).Decode(&req)
		size := req.Password.Size()
		req.Password.Destroy()
		return size, err
	}

	// Exactly at the cap: accepted, with the full secret preserved.
	if size, err := decode(MaxPasswordFieldBytes); err != nil {
		t.Fatalf("%d bytes (== cap) must be accepted, got: %v", MaxPasswordFieldBytes, err)
	} else if size != MaxPasswordFieldBytes {
		t.Fatalf("accepted secret size = %d, want %d", size, MaxPasswordFieldBytes)
	}

	// One byte over: rejected, no buffer allocated.
	if size, err := decode(MaxPasswordFieldBytes + 1); !errors.Is(err, ErrPasswordTooLarge) {
		t.Fatalf("%d bytes (> cap) must be rejected with ErrPasswordTooLarge, got: %v", MaxPasswordFieldBytes+1, err)
	} else if size != 0 {
		t.Fatalf("rejected field must allocate no buffer, size = %d", size)
	}
}

// TestPasswordField_UnmarshalJSON_DuplicateOversizedDoesNotLeak is the #121
// duplicate-member regression (Codex review of #123). JSON permits repeating
// password_b64, so an accepted value followed by an oversized one must reject
// AND leave no stranded mlocked buffer; otherwise repeated {valid, oversized}
// bodies leak one buffer each and exhaust RLIMIT_MEMLOCK — the condition the
// cap exists to close.
func TestPasswordField_UnmarshalJSON_DuplicateOversizedDoesNotLeak(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("a-real-password"))
	oversized := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x5a}, 2*MaxPasswordFieldBytes))
	body := `{"password_b64":"` + valid + `","password_b64":"` + oversized + `"}`

	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
	defer req.Password.Destroy()
	if !errors.Is(err, ErrPasswordTooLarge) {
		t.Fatalf("oversized duplicate must be rejected with ErrPasswordTooLarge, got: %v", err)
	}
	if req.Password.Buffer() != nil || req.Password.Size() != 0 {
		t.Fatal("the earlier accepted buffer must be destroyed, not stranded, when a duplicate is rejected")
	}
}

// TestPasswordField_UnmarshalJSON_DuplicateSuccessKeepsLast verifies a
// duplicate SUCCESSFUL field leaves exactly the last value and does not strand
// the first's buffer.
func TestPasswordField_UnmarshalJSON_DuplicateSuccessKeepsLast(t *testing.T) {
	first := base64.StdEncoding.EncodeToString([]byte("first"))
	second := base64.StdEncoding.EncodeToString([]byte("second-value"))
	body := `{"password_b64":"` + first + `","password_b64":"` + second + `"}`

	var req struct {
		Password PasswordField `json:"password_b64"`
	}
	if err := json.NewDecoder(strings.NewReader(body)).Decode(&req); err != nil {
		t.Fatalf("duplicate successful fields must decode, got: %v", err)
	}
	defer req.Password.Destroy()
	if got := req.Password.Size(); got != len("second-value") {
		t.Fatalf("last value must win: size = %d, want %d", got, len("second-value"))
	}
}

// TestPasswordField_UnmarshalJSON_DuplicateEarlyReturnPaths covers the round-3
// finding (Codex #123): the prior mlocked buffer must be destroyed before EVERY
// duplicate-member early return — malformed, null, and empty — not only the
// oversized/replacement path. A valid value followed by any of these must leave
// no stranded buffer, and null/empty must clear the field (JSON last-wins).
func TestPasswordField_UnmarshalJSON_DuplicateEarlyReturnPaths(t *testing.T) {
	valid := base64.StdEncoding.EncodeToString([]byte("a-real-password"))

	cases := []struct {
		name    string
		second  string // raw JSON value for the duplicate member
		wantErr bool
	}{
		{"valid then malformed object", `{}`, true},
		{"valid then null", `null`, false},
		{"valid then empty string", `""`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			body := `{"password_b64":"` + valid + `","password_b64":` + tc.second + `}`
			var req struct {
				Password PasswordField `json:"password_b64"`
			}
			err := json.NewDecoder(strings.NewReader(body)).Decode(&req)
			defer req.Password.Destroy()
			if tc.wantErr && err == nil {
				t.Fatal("expected a decode error for the malformed duplicate")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if req.Password.Buffer() != nil || req.Password.Size() != 0 {
				t.Fatal("the earlier accepted buffer must be destroyed, not stranded, on any duplicate early return")
			}
		})
	}
}
