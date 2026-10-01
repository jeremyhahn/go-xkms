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
//     Contact licensing@automatethethings.com for commercial licensing options.

// Package secureio provides JSON request helpers that land sensitive
// values directly into memguard-backed enclaves, bypassing the Go
// string heap that json.Decoder would otherwise use.
//
// The centerpiece is PasswordField — a JSON field type whose
// UnmarshalJSON base64-decodes the quoted JSON token directly into a
// *secure.Buffer. Handlers use it like any other DTO field and MUST
// call Destroy() (typically via defer) once the request completes.
package secureio

import (
	"encoding/base64"
	"errors"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// MaxPasswordFieldBytes bounds the decoded length of a password_b64
// value. A password, passphrase, or PIN is human- or tool-scale, so
// 8 KiB is far beyond any legitimate secret (a generated static
// password caps at 128 bytes) while keeping a single mlocked
// allocation small. The bound is enforced BEFORE any secure.Buffer is
// allocated, so an oversized field is rejected rather than driving
// protected-memory (RLIMIT_MEMLOCK) exhaustion — a purge-class
// no-recover wrapper turns that exhaustion into a process-wide key
// purge on the barrier endpoints (go-xkms#121).
//
// It is an immutable const on purpose: every request reads the same
// limit with no synchronization, and it can never be tuned to a
// fail-open (non-positive) value at runtime. A deployment that
// genuinely needs a different limit changes it here, not at runtime.
const MaxPasswordFieldBytes = 8192

// ErrPasswordTooLarge is wrapped by *BadBodyError when a password_b64
// field would decode to more than MaxPasswordFieldBytes bytes. It is
// exported so a transport layer can map the rejection to HTTP 413
// (errors.Is reaches it through the *BadBodyError wrapper).
var ErrPasswordTooLarge = errors.New("secureio: password exceeds maximum permitted length")

// ErrPasswordFieldNotString is wrapped by *BadBodyError when a
// password_b64 JSON token is present but is not a quoted JSON string
// (e.g. a number, bool, or array).
var ErrPasswordFieldNotString = errors.New("password_b64 must be a JSON string")

// ErrPasswordFieldEmptyAfterDecode is wrapped by *BadBodyError when a
// password_b64 JSON string is short enough that base64's DecodedLen
// reports zero decodable bytes (1-3 base64 characters with no
// trailing padding).
var ErrPasswordFieldEmptyAfterDecode = errors.New("password_b64 empty after decode")

// BadBodyError is returned by PasswordField.UnmarshalJSON when the
// JSON token is missing, not a string, or not valid base64.
type BadBodyError struct {
	// Err is the underlying cause (base64 decode error, quote check
	// failure, etc.). May be nil for pure structural errors; when
	// present it satisfies Unwrap so errors.Is / errors.As reach it.
	Err error
}

// Error returns a stable human-readable description.
func (e *BadBodyError) Error() string {
	if e == nil {
		return "secureio: bad body"
	}
	if e.Err == nil {
		return "secureio: bad body"
	}
	return "secureio: bad body: " + e.Err.Error()
}

// Unwrap exposes the inner cause for errors.Is/As chains.
func (e *BadBodyError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}

// PasswordField is a JSON field whose UnmarshalJSON decodes a base64
// string directly into a memguard-backed *secure.Buffer. The
// plaintext password bytes NEVER become a Go string at any point
// along the unmarshal path:
//
//  1. json.Unmarshal invokes UnmarshalJSON with the raw JSON token
//     (including the surrounding quotes).
//  2. The method validates the quotes against the []byte directly —
//     no string conversion.
//  3. base64.StdEncoding.Decode writes decoded bytes into the
//     mlocked Buffer's Bytes() slice in place.
//  4. A right-size pass allocates a fresh Buffer of the exact
//     decoded length when the padding-computed maximum overshoots,
//     and destroys the oversized Buffer.
//
// Callers MUST invoke Destroy when finished with the field. The
// canonical pattern is `defer req.Password.Destroy()` immediately
// after json.Decode returns; Destroy is idempotent and safe on a
// zero value.
type PasswordField struct {
	buf *secure.Buffer
}

// Buffer returns the underlying *secure.Buffer. The returned pointer
// is owned by the PasswordField; do not Destroy it directly — call
// PasswordField.Destroy so the field's internal state resets. May
// return nil when the field was absent or explicitly null in the
// JSON body.
func (f *PasswordField) Buffer() *secure.Buffer {
	if f == nil {
		return nil
	}
	return f.buf
}

// Size returns the length of the decoded password in bytes. Returns
// 0 for an absent, null, or destroyed field.
func (f *PasswordField) Size() int {
	if f == nil || f.buf == nil {
		return 0
	}
	return f.buf.Size()
}

// UnmarshalJSON decodes a JSON-quoted base64 string directly into an
// mlocked Buffer. A JSON null is a no-op (leaves f.buf == nil), an
// empty string yields an empty (zero-length) field, and any other
// malformed input returns *BadBodyError.
func (f *PasswordField) UnmarshalJSON(data []byte) error {
	// Duplicate JSON members first: JSON permits repeating "password_b64", and
	// an earlier occurrence may already have allocated an mlocked buffer into
	// f.buf. Destroy it before ANY early return, so a later duplicate that is
	// null, empty, malformed, oversized, or simply a replacement value cannot
	// strand the earlier allocation — repeated such bodies would otherwise leak
	// one mlocked buffer each and exhaust RLIMIT_MEMLOCK, the exact exhaustion
	// #121 closes (Codex review). This also gives JSON last-wins semantics: a
	// duplicate null/empty clears the field rather than retaining the prior
	// secret. Destroy is idempotent and a no-op on the common single-field case
	// where f.buf is still nil.
	f.Destroy()
	if len(data) == 0 {
		return nil
	}
	// An explicit JSON null is a no-op.
	if len(data) == 4 && data[0] == 'n' && data[1] == 'u' && data[2] == 'l' && data[3] == 'l' {
		return nil
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return &BadBodyError{Err: ErrPasswordFieldNotString}
	}
	encoded := data[1 : len(data)-1]
	if len(encoded) == 0 {
		return nil
	}
	maxLen := base64.StdEncoding.DecodedLen(len(encoded))
	if maxLen <= 0 {
		return &BadBodyError{Err: ErrPasswordFieldEmptyAfterDecode}
	}
	// Reject an oversized field BEFORE allocating any protected memory.
	// DecodedLen counts the bytes that trailing '=' padding will drop,
	// so subtract the padding to get the EXACT decoded length: a secret
	// at the cap is accepted while one past it is refused, and the
	// RLIMIT_MEMLOCK purge threshold stays unreachable from a single
	// request (go-xkms#121).
	decodedLen := maxLen
	if n := len(encoded); encoded[n-1] == '=' {
		decodedLen--
		if n > 1 && encoded[n-2] == '=' {
			decodedLen--
		}
	}
	if decodedLen > MaxPasswordFieldBytes {
		return &BadBodyError{Err: ErrPasswordTooLarge}
	}
	raw, err := secure.NewBuffer(maxLen)
	if err != nil {
		return err
	}
	// Decode straight into protected memory, holding the borrow across the
	// write. decodeErr is kept apart from WithBytes' own error so a bad
	// encoding stays a BadBodyError while a buffer failure does not.
	var n int
	var decodeErr error
	if err := raw.WithBytes(func(b []byte) error {
		n, decodeErr = base64.StdEncoding.Decode(b, encoded)
		return nil
	}); err != nil {
		raw.Destroy()
		return err
	}
	if decodeErr != nil {
		raw.Destroy()
		return &BadBodyError{Err: decodeErr}
	}
	if n == maxLen {
		f.buf = raw
		return nil
	}
	// Right-size: copy the n decoded bytes out under raw's borrow, destroy
	// the oversized Buffer, and move the copy into an exactly-sized one.
	// NewBufferFromBytes wipes the copy on every path, and no borrow is
	// ever nested inside another.
	var plain []byte
	err = raw.WithBytes(func(b []byte) error {
		plain = make([]byte, n)
		copy(plain, b[:n])
		return nil
	})
	raw.Destroy()
	if err != nil {
		return err
	}
	trimmed, err := secure.NewBufferFromBytes(plain)
	if err != nil {
		return err
	}
	f.buf = trimmed
	return nil
}

// Destroy wipes the underlying Buffer. Safe on a zero value and
// idempotent — memguard.Destroy is itself idempotent. Subsequent
// calls to Buffer return nil and Size returns 0.
func (f *PasswordField) Destroy() {
	if f == nil {
		return
	}
	if f.buf != nil {
		f.buf.Destroy()
		f.buf = nil
	}
}
