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
