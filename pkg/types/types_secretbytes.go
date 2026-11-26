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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"unicode/utf16"
	"unicode/utf8"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"
)

// SecretBytes carries secret text (a PIN, a password, a PEM private key)
// through encoding/json as a JSON string without ever materializing a Go
// string, which could not be wiped. On the wire it is indistinguishable from
// a string field, so peers and stored records written with a string still
// decode, and what it writes still decodes into a string. The owner of a
// SecretBytes must Wipe it on every path.
type SecretBytes []byte

// hexDigits is the digit set for \u00XX escapes.
const hexDigits = "0123456789abcdef"

// invalidUTF8JSON is what encoding/json writes in a string for one byte that is
// not valid UTF-8: the escape \ufffd up to Go 1.26, the replacement character
// itself from Go 1.27. It is asked of the encoder this process runs, once,
// rather than assumed, so SecretBytes writes what a string field would under
// the same toolchain and GODEBUG settings.
var invalidUTF8JSON = func() []byte {
	encoded, err := json.Marshal("\xff")
	if err != nil || len(encoded) < 2 {
		return []byte(`\ufffd`)
	}
	return encoded[1 : len(encoded)-1]
}()

// MarshalJSON encodes the field as a JSON string, escaping exactly as
// encoding/json escapes a string of the same text, so a record written with a
// SecretBytes is byte-identical to one written with a string: control
// characters, quotes and backslashes are escaped, U+2028 and U+2029 are
// written as \u2028 and \u2029, and a byte that is not valid UTF-8 is replaced
// as a string would have been (see invalidUTF8JSON). (encoding/json adds its own HTML
// escaping to a Marshaler's output when the encoder asks for it.) An empty
// field encodes as "" so that omitempty on the owning struct field keeps
// behaving.
func (p SecretBytes) MarshalJSON() ([]byte, error) {
	out := make([]byte, 0, len(p)+len(p)/32+2)
	out = append(out, '"')
	for i := 0; i < len(p); {
		c := p[i]
		if c >= utf8.RuneSelf {
			r, size := utf8.DecodeRune(p[i:])
			switch {
			case r == utf8.RuneError && size == 1:
				out = append(out, invalidUTF8JSON...)
			case r == '\u2028' || r == '\u2029':
				out = append(out, `\u202`...)
				out = append(out, hexDigits[r&0xf])
			default:
				out = append(out, p[i:i+size]...)
			}
			i += size
			continue
		}
		switch c {
		case '"', '\\':
			out = append(out, '\\', c)
		case '\b':
			out = append(out, '\\', 'b')
		case '\f':
			out = append(out, '\\', 'f')
		case '\n':
			out = append(out, '\\', 'n')
		case '\r':
			out = append(out, '\\', 'r')
		case '\t':
			out = append(out, '\\', 't')
		default:
			if c < 0x20 {
				out = append(out, '\\', 'u', '0', '0', hexDigits[c>>4], hexDigits[c&0xf])
			} else {
				out = append(out, c)
			}
		}
		i++
	}
	return append(out, '"'), nil
}

// UnmarshalJSON decodes a JSON string (or null) into the field. The
// decoded bytes are the field's own allocation, owned by the caller, who
// must wipe them. A secret the field held before is wiped, not just dropped,
// so a decoder that reuses a struct leaves no unreachable plaintext behind.
func (p *SecretBytes) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		p.Wipe()
		return nil
	}
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return &SecretBytesError{Reason: "not a JSON string"}
	}
	in := data[1 : len(data)-1]
	out := make([]byte, 0, len(in))
	for i := 0; i < len(in); i++ {
		if in[i] != '\\' {
			if in[i] >= utf8.RuneSelf {
				// A string field decodes bytes that are not valid UTF-8 as
				// U+FFFD, so this does too.
				r, size := utf8.DecodeRune(in[i:])
				out = utf8.AppendRune(out, r)
				i += size - 1
				continue
			}
			out = append(out, in[i])
			continue
		}
		i++
		if i >= len(in) {
			secure.Wipe(out)
			return &SecretBytesError{Reason: "truncated escape"}
		}
		var err error
		out, i, err = appendEscape(out, in, i)
		if err != nil {
			secure.Wipe(out)
			return err
		}
	}
	p.Wipe()
	*p = out
	return nil
}

// appendEscape decodes the escape whose selector byte is in[i], appends the
// result to out, and returns the index of the escape's last byte.
func appendEscape(out, in []byte, i int) ([]byte, int, error) {
	switch in[i] {
	case '"', '\\', '/':
		return append(out, in[i]), i, nil
	case 'b':
		return append(out, '\b'), i, nil
	case 'f':
		return append(out, '\f'), i, nil
	case 'n':
		return append(out, '\n'), i, nil
	case 'r':
		return append(out, '\r'), i, nil
	case 't':
		return append(out, '\t'), i, nil
	case 'u':
		r, err := hex4(in, i+1)
		if err != nil {
			return out, i, err
		}
		i += 4
		if utf16.IsSurrogate(r) {
			if i+6 < len(in) && in[i+1] == '\\' && in[i+2] == 'u' {
				if lo, lerr := hex4(in, i+3); lerr == nil {
					if dec := utf16.DecodeRune(r, lo); dec != utf8.RuneError {
						return utf8.AppendRune(out, dec), i + 6, nil
					}
				}
			}
			r = utf8.RuneError
		}
		return utf8.AppendRune(out, r), i, nil
	}
	return out, i, &SecretBytesError{Reason: "invalid escape"}
}

// hex4 parses the four hex digits at in[at:] as a UTF-16 code unit.
func hex4(in []byte, at int) (rune, error) {
	if at+4 > len(in) {
		return 0, &SecretBytesError{Reason: "truncated \\u escape"}
	}
	var r rune
	for _, c := range in[at : at+4] {
		switch {
		case c >= '0' && c <= '9':
			c -= '0'
		case c >= 'a' && c <= 'f':
			c = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			c = c - 'A' + 10
		default:
			return 0, &SecretBytesError{Reason: "invalid \\u escape"}
		}
		r = r<<4 | rune(c)
	}
	return r, nil
}

// MarshalText implements encoding.TextMarshaler, returning a copy of the
// secret text, so text-based encoders (YAML) write the same scalar a string
// field wrote. encoding/json keeps using MarshalJSON. The caller owns the
// copy.
func (p SecretBytes) MarshalText() ([]byte, error) {
	return append([]byte(nil), p...), nil
}

// UnmarshalText implements encoding.TextUnmarshaler, copying text into the
// field's own allocation, which the caller must wipe. A secret the field held
// before is wiped, including any tail a shorter replacement would leave
// behind.
func (p *SecretBytes) UnmarshalText(text []byte) error {
	out := append([]byte(nil), text...)
	p.Wipe()
	*p = out
	return nil
}

// Wipe zeroes the secret's backing array and drops the reference.
func (p *SecretBytes) Wipe() {
	if p == nil {
		return
	}
	secure.Wipe(*p)
	*p = nil
}

// String returns PasswordRedacted, the marker a Password prints, and never
// the secret (ruling 152).
func (p SecretBytes) String() string {
	return PasswordRedacted
}

// GoString returns PasswordRedacted, so %#v never prints the secret.
func (p SecretBytes) GoString() string {
	return PasswordRedacted
}

// Format implements fmt.Formatter, writing PasswordRedacted for every verb
// and flag: without it %x, %q and %v would print the bytes, since fmt
// consults String only for some verbs and formats a byte slice itself for
// the rest.
func (p SecretBytes) Format(f fmt.State, _ rune) {
	// Format cannot return an error; a failed write leaves the output short,
	// and the redaction marker is all there was to write.
	if _, err := io.WriteString(f, PasswordRedacted); err != nil {
		return
	}
}

// SecretBytesError reports a malformed JSON string for a SecretBytes.
type SecretBytesError struct {
	Reason string
}

// Error implements the error interface.
func (e *SecretBytesError) Error() string {
	return "types: malformed secret string: " + e.Reason
}
