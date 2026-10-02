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

package types

import (
	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// SecretText is secret text held in mlocked, guard-paged protected memory
// that encodes to and from a JSON string. It is for a record that carries a
// secret across a function boundary -- a backup archive, a sync delta, a
// pairing message -- where a SecretBytes would leave a plaintext copy on the
// ordinary heap for as long as the record lives.
//
// On the wire it is indistinguishable from a string field: it decodes what a
// string field wrote and encodes to the same bytes a string field would
// (encoding/json applies its own HTML and U+2028 escaping to the output). The
// zero value is empty and encodes as "".
//
// A SecretText has pointer semantics: copies of the value share one protected
// buffer, so a record copied by value shares its secrets with the original,
// and exactly one owner calls Destroy. Because the buffer is guard-paged
// memory, a record holding a SecretText must not be compared with
// reflect.DeepEqual (or assert.Equal); compare the secrets through Copy.
type SecretText struct {
	buf *secure.Buffer
}

// NewSecretText returns a SecretText holding a copy of text. text stays the
// caller's, who wipes it. Empty text yields the zero SecretText. Returns
// *SecretTextError when the protected allocation fails.
func NewSecretText(text []byte) (SecretText, error) {
	var s SecretText
	if err := s.Set(text); err != nil {
		return SecretText{}, err
	}
	return s, nil
}

// Set copies text into protected memory, destroying whatever the receiver held
// before. Empty text clears the receiver. text stays the caller's, who wipes
// it. Returns *SecretTextError when the protected allocation fails, leaving the
// previous value in place.
func (s *SecretText) Set(text []byte) error {
	if len(text) == 0 {
		s.buf.Destroy()
		s.buf = nil
		return nil
	}
	// NewBufferFromBytes consumes its argument, so it consumes the clone.
	buf, err := secure.NewBufferFromBytes(append([]byte(nil), text...))
	if err != nil {
		return &SecretTextError{Op: "allocate", Err: err}
	}
	s.buf.Destroy()
	s.buf = buf
	return nil
}

// IsZero reports whether the SecretText is empty. It is what the omitzero JSON
// tag option consults.
func (s SecretText) IsZero() bool { return s.buf == nil }

// WithBytes lends the secret to fn for the duration of the call; an empty
// SecretText calls fn with a nil slice. fn must not retain the slice and must
// not allocate protected memory, because borrows do not nest. Returns
// *SecretTextError when the buffer can no longer be read, otherwise fn's error.
func (s SecretText) WithBytes(fn func([]byte) error) error {
	if s.buf == nil {
		return fn(nil)
	}
	return s.buf.WithBytes(fn)
}

// Copy returns a caller-owned copy of the secret, or nil when empty. The caller
// MUST wipe it (secure.Wipe) as soon as it has been used. Returns
// *SecretTextError when the buffer can no longer be read.
func (s SecretText) Copy() ([]byte, error) {
	if s.buf == nil {
		return nil, nil
	}
	out, err := secure.CopyOut(s.buf)
	if err != nil {
		return nil, &SecretTextError{Op: "read", Err: err}
	}
	return out, nil
}

// Destroy wipes and releases the protected buffer, and so empties every copy of
// the value. Safe on the zero value and more than once.
func (s *SecretText) Destroy() {
	if s == nil {
		return
	}
	s.buf.Destroy()
	s.buf = nil
}

// MarshalJSON encodes the secret as a JSON string, escaping exactly as
// SecretBytes does. The value receiver lets encoding/json reach it for a field
// of a non-addressable struct. The encoded bytes necessarily hold the secret;
// they belong to the serialization boundary, not to this type.
func (s SecretText) MarshalJSON() ([]byte, error) {
	plain, err := s.Copy()
	if err != nil {
		return nil, err
	}
	defer secure.Wipe(plain)
	return SecretBytes(plain).MarshalJSON()
}

// UnmarshalJSON decodes a JSON string (or null) into protected memory. The
// decoded text never outlives the call. Returns *SecretBytesError for input
// that is not a JSON string and *SecretTextError when allocation fails.
func (s *SecretText) UnmarshalJSON(data []byte) error {
	var plain SecretBytes
	defer plain.Wipe()
	if err := plain.UnmarshalJSON(data); err != nil {
		return err
	}
	return s.Set(plain)
}

// SecretTextError reports a failure to hold or read a SecretText in protected
// memory.
type SecretTextError struct {
	// Op names the step that failed: "allocate" or "read".
	Op string
	// Err is the underlying protected-memory error.
	Err error
}

// Error implements the error interface.
func (e *SecretTextError) Error() string {
	return "types: secret text " + e.Op + ": " + e.Err.Error()
}

// Unwrap returns the underlying error.
func (e *SecretTextError) Unwrap() error { return e.Err }
