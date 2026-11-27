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
	"errors"
	"fmt"
	"strings"
	"testing"
)

type secretHolder struct {
	PEM SecretBytes `json:"pem,omitempty"`
}

type stringHolder struct {
	PEM string `json:"pem,omitempty"`
}

// TestSecretBytes_WireCompatibleWithString proves a SecretBytes reads what a string
// field wrote and writes what a string field reads, so envelopes stored before
// the field type changed still load.
func TestSecretBytes_WireCompatibleWithString(t *testing.T) {
	inputs := []string{
		"-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaA==\r\n-----END OPENSSH PRIVATE KEY-----\n",
		"quote\" backslash\\ tab\t ctrl\x01 <>&",
		"unicode é \U0001F600",
	}
	for _, in := range inputs {
		legacy, err := json.Marshal(stringHolder{PEM: in})
		if err != nil {
			t.Fatalf("marshal string: %v", err)
		}
		var got secretHolder
		if err := json.Unmarshal(legacy, &got); err != nil {
			t.Fatalf("unmarshal legacy %q: %v", legacy, err)
		}
		if string(got.PEM) != in {
			t.Errorf("legacy decode = %q, want %q", got.PEM, in)
		}

		written, err := json.Marshal(secretHolder{PEM: SecretBytes(in)})
		if err != nil {
			t.Fatalf("marshal SecretBytes: %v", err)
		}
		var back stringHolder
		if err := json.Unmarshal(written, &back); err != nil {
			t.Fatalf("stdlib decode of %q: %v", written, err)
		}
		if back.PEM != in {
			t.Errorf("stdlib decode = %q, want %q", back.PEM, in)
		}
	}
}

// TestSecretBytes_EmptyOmitted proves omitempty still drops an empty field.
func TestSecretBytes_EmptyOmitted(t *testing.T) {
	out, err := json.Marshal(secretHolder{})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte("{}")) {
		t.Errorf("empty field encoded as %s, want {}", out)
	}
}

// TestSecretBytes_Null proves JSON null decodes to an empty field.
func TestSecretBytes_Null(t *testing.T) {
	got := secretHolder{PEM: SecretBytes("stale")}
	if err := json.Unmarshal([]byte(`{"pem":null}`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.PEM) != 0 {
		t.Errorf("null decoded to %q", got.PEM)
	}
}

// TestSecretBytes_SurrogatePair proves an escaped surrogate pair decodes to one
// rune and a lone surrogate to the replacement character.
func TestSecretBytes_SurrogatePair(t *testing.T) {
	var pair SecretBytes
	if err := pair.UnmarshalJSON([]byte(`"😀"`)); err != nil {
		t.Fatal(err)
	}
	if string(pair) != "\U0001F600" {
		t.Errorf("pair = %q", pair)
	}
	var lone SecretBytes
	if err := lone.UnmarshalJSON([]byte(`"\ud83d!"`)); err != nil {
		t.Fatal(err)
	}
	if string(lone) != "�!" {
		t.Errorf("lone = %q", lone)
	}
}

// TestSecretBytes_Malformed proves malformed JSON strings are refused with
// *SecretBytesError and leave the field unset.
func TestSecretBytes_Malformed(t *testing.T) {
	for name, in := range map[string]string{
		"not a string":    `123`,
		"unterminated":    `"abc`,
		"trailing escape": `"abc\"`,
		"bad escape":      `"\q"`,
		"short unicode":   `"\u12"`,
		"non-hex unicode": `"\u12zz"`,
		"empty input":     ``,
		"lone quote":      `"`,
	} {
		t.Run(name, func(t *testing.T) {
			p := SecretBytes("keep")
			err := p.UnmarshalJSON([]byte(in))
			var pe *SecretBytesError
			if !errors.As(err, &pe) {
				t.Fatalf("err = %v, want *SecretBytesError", err)
			}
			if string(p) != "keep" {
				t.Errorf("field modified on error: %q", p)
			}
		})
	}
}

// TestSecretBytes_Wipe proves Wipe zeroes the backing array and drops the
// reference, and tolerates nil receivers and empty values.
func TestSecretBytes_Wipe(t *testing.T) {
	backing := []byte("123456")
	s := SecretBytes(backing)
	s.Wipe()
	if s != nil {
		t.Errorf("after Wipe = %q, want nil", s)
	}
	if !bytes.Equal(backing, make([]byte, len(backing))) {
		t.Errorf("backing array not zeroed: %q", backing)
	}
	var empty SecretBytes
	empty.Wipe()
	var nilPtr *SecretBytes
	nilPtr.Wipe()
}

// TestSecretBytes_ByteIdenticalToString proves the encoded bytes, not just the
// decoded text, match what a string field writes, for every ASCII byte and a
// spread of multi-byte text, so archives and stored records stay byte-stable.
func TestSecretBytes_ByteIdenticalToString(t *testing.T) {
	var inputs []string
	for c := 0; c < 0x80; c++ {
		inputs = append(inputs, "a"+string(rune(c))+"z")
	}
	inputs = append(inputs, "", "é", "\u2028 \u2029", "\U0001F600 emoji", "<script>&amp;</script>",
		// Not valid UTF-8: a string field writes U+FFFD for each, so must we.
		"\xff", "a\xc3z", "\xe2\x80", "\xed\xa0\x80", "\xf4\x90\x80\x80", "ok\xfe\xffok")

	for _, in := range inputs {
		want, err := json.Marshal(stringHolder{PEM: in})
		if err != nil {
			t.Fatalf("marshal string %q: %v", in, err)
		}
		got, err := json.Marshal(secretHolder{PEM: SecretBytes(in)})
		if err != nil {
			t.Fatalf("marshal SecretBytes %q: %v", in, err)
		}
		if string(got) != string(want) {
			t.Errorf("%q: SecretBytes wrote %s, string wrote %s", in, got, want)
		}
	}
}

func TestSecretBytes_TextRoundTrip(t *testing.T) {
	in := SecretBytes("hunter2")
	text, err := in.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText: %v", err)
	}
	text[0] = 'X'
	if string(in) != "hunter2" {
		t.Fatalf("MarshalText aliased the secret: %q", in)
	}

	var out SecretBytes
	if err := out.UnmarshalText([]byte("hunter2")); err != nil {
		t.Fatalf("UnmarshalText: %v", err)
	}
	if string(out) != "hunter2" {
		t.Errorf("UnmarshalText = %q", out)
	}
	out.Wipe()
	if out != nil {
		t.Errorf("Wipe left %q", out)
	}
}

// TestSecretBytes_DecodeWipesWhatItReplaces proves a decoder that reuses a
// struct leaves no unreachable plaintext: the previous value's backing array is
// zeroed by a replacement, by null and by UnmarshalText.
func TestSecretBytes_DecodeWipesWhatItReplaces(t *testing.T) {
	for name, decode := range map[string]func(*SecretBytes) error{
		"json replace": func(p *SecretBytes) error { return p.UnmarshalJSON([]byte(`"new"`)) },
		"json null":    func(p *SecretBytes) error { return p.UnmarshalJSON([]byte(`null`)) },
		"text shorter": func(p *SecretBytes) error { return p.UnmarshalText([]byte("n")) },
	} {
		t.Run(name, func(t *testing.T) {
			old := SecretBytes("previous-secret")
			backing := []byte(old)
			p := old
			if err := decode(&p); err != nil {
				t.Fatalf("decode: %v", err)
			}
			if string(backing) == "previous-secret" || string(old) == "previous-secret" {
				t.Errorf("the previous secret survived the decode: %q", old)
			}
		})
	}
}

func TestSecretBytes_DecodeErrorKeepsPreviousValue(t *testing.T) {
	p := SecretBytes("kept")
	if err := p.UnmarshalJSON([]byte(`42`)); err == nil {
		t.Fatal("a non-string must be rejected")
	}
	if string(p) != "kept" {
		t.Errorf("a failed decode must not touch the field, got %q", p)
	}
}

// TestSecretBytes_ByteIdenticalWithHTMLEscapingOff proves the equivalence holds
// for an encoder that turns HTML escaping off, where encoding/json writes the
// Marshaler's output as it finds it.
func TestSecretBytes_ByteIdenticalWithHTMLEscapingOff(t *testing.T) {
	for _, in := range []string{"<a&b>", "\u2028x\u2029", "q\"b\\", "bad\xffbyte", "\U0001F600"} {
		encode := func(v any) string {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if err := enc.Encode(v); err != nil {
				t.Fatalf("encode %q: %v", in, err)
			}
			return buf.String()
		}
		want := encode(stringHolder{PEM: in})
		got := encode(secretHolder{PEM: SecretBytes(in)})
		if got != want {
			t.Errorf("%q: SecretBytes wrote %s, string wrote %s", in, got, want)
		}
	}
}

// TestSecretBytes_DecodesInvalidUTF8LikeAString proves a document carrying a
// byte that is not valid UTF-8 decodes to the same text a string field gets.
func TestSecretBytes_DecodesInvalidUTF8LikeAString(t *testing.T) {
	for _, doc := range []string{"{\"pem\":\"a\xffb\"}", "{\"pem\":\"\xe2\x80\"}", "{\"pem\":\"ok\xf4\x90\x80\x80ok\"}"} {
		var legacy stringHolder
		if err := json.Unmarshal([]byte(doc), &legacy); err != nil {
			t.Fatalf("string decode of %q: %v", doc, err)
		}
		var got secretHolder
		if err := json.Unmarshal([]byte(doc), &got); err != nil {
			t.Fatalf("SecretBytes decode of %q: %v", doc, err)
		}
		if string(got.PEM) != legacy.PEM {
			t.Errorf("%q: SecretBytes decoded %q, string decoded %q", doc, got.PEM, legacy.PEM)
		}
	}
}

func TestSecretBytes_FormatRedactsEveryVerb(t *testing.T) {
	secret := SecretBytes("hunter2")
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d", "%10s"} {
		got := fmt.Sprintf(verb, secret)
		if got != PasswordRedacted {
			t.Errorf("%s printed %q, want %q", verb, got, PasswordRedacted)
		}
	}
	holder := struct{ Password SecretBytes }{Password: secret}
	if got := fmt.Sprintf("%+v", holder); strings.Contains(got, "hunter2") || !strings.Contains(got, PasswordRedacted) {
		t.Errorf("a struct field printed %q", got)
	}
	if secret.String() != PasswordRedacted || secret.GoString() != PasswordRedacted {
		t.Errorf("String/GoString leak the secret")
	}
}

func TestSecretBytes_FormatRedactsEmptyAndNil(t *testing.T) {
	var nilSecret SecretBytes
	for _, secret := range []SecretBytes{nilSecret, {}} {
		if got := fmt.Sprintf("%v", secret); got != PasswordRedacted {
			t.Errorf("%%v printed %q, want %q", got, PasswordRedacted)
		}
	}
	if string(SecretBytes("x")) != "x" {
		t.Errorf("a string conversion must still yield the secret for its owner")
	}
}
