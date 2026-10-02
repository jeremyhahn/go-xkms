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
	"encoding/json"
	"errors"
	"testing"
)

type textHolder struct {
	Secret SecretText `json:"secret"`
	Opt    SecretText `json:"opt,omitzero"`
}

type stringTextHolder struct {
	Secret string `json:"secret"`
	Opt    string `json:"opt,omitempty"`
}

func TestSecretText_SetCopyAndDestroy(t *testing.T) {
	in := []byte("hunter2")
	var s SecretText
	if err := s.Set(in); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if string(in) != "hunter2" {
		t.Errorf("Set must leave the caller's slice intact, got %q", in)
	}
	if s.IsZero() {
		t.Fatal("IsZero after Set")
	}

	got, err := s.Copy()
	if err != nil {
		t.Fatalf("Copy: %v", err)
	}
	got[0] = 'X'
	again, err := s.Copy()
	if err != nil || string(again) != "hunter2" {
		t.Errorf("a returned copy must not alias the protected original: %q, %v", again, err)
	}

	var seen string
	if err := s.WithBytes(func(b []byte) error { seen = string(b); return nil }); err != nil || seen != "hunter2" {
		t.Errorf("WithBytes lent %q, %v", seen, err)
	}

	s.Destroy()
	if !s.IsZero() {
		t.Error("Destroy must empty the value")
	}
	s.Destroy()
}

func TestSecretText_EmptyValue(t *testing.T) {
	var s SecretText
	if !s.IsZero() {
		t.Error("zero value must be empty")
	}
	if got, err := s.Copy(); got != nil || err != nil {
		t.Errorf("Copy of empty = %v, %v", got, err)
	}
	called := false
	if err := s.WithBytes(func(b []byte) error { called = true; return nil }); err != nil || !called {
		t.Errorf("WithBytes of empty: called=%v err=%v", called, err)
	}
	if err := s.Set(nil); err != nil || !s.IsZero() {
		t.Errorf("Set(nil) = %v", err)
	}
	var nilSecret *SecretText
	nilSecret.Destroy()
}

func TestSecretText_CopiesShareOneBuffer(t *testing.T) {
	a, err := NewSecretText([]byte("shared"))
	if err != nil {
		t.Fatalf("NewSecretText: %v", err)
	}
	b := a
	a.Destroy()
	if got, err := b.Copy(); err == nil {
		t.Errorf("a copy of a destroyed SecretText must not read back %q", got)
	}
	var terr *SecretTextError
	if _, err := b.Copy(); !errors.As(err, &terr) || terr.Op != "read" {
		t.Errorf("want a read *SecretTextError, got %v", err)
	}
}

// TestSecretText_ByteIdenticalToString proves the encoded bytes match a string
// field's, for every ASCII byte and a spread of multi-byte text.
func TestSecretText_ByteIdenticalToString(t *testing.T) {
	var inputs []string
	for c := 0; c < 0x80; c++ {
		inputs = append(inputs, "a"+string(rune(c))+"z")
	}
	inputs = append(inputs, "", "é", "   ", "\U0001F600 emoji", "<script>&amp;</script>", "bad\xffbyte", "\xe2\x80")

	for _, in := range inputs {
		want, err := json.Marshal(stringTextHolder{Secret: in, Opt: in})
		if err != nil {
			t.Fatalf("marshal string %q: %v", in, err)
		}
		holder := textHolder{}
		if err := holder.Secret.Set([]byte(in)); err != nil {
			t.Fatalf("Set: %v", err)
		}
		if err := holder.Opt.Set([]byte(in)); err != nil {
			t.Fatalf("Set: %v", err)
		}
		got, err := json.Marshal(holder)
		if err != nil {
			t.Fatalf("marshal SecretText %q: %v", in, err)
		}
		if string(got) != string(want) {
			t.Errorf("%q: SecretText wrote %s, string wrote %s", in, got, want)
		}
		holder.Secret.Destroy()
		holder.Opt.Destroy()
	}
}

func TestSecretText_DecodesWhatAStringWrote(t *testing.T) {
	legacy := `{"secret":"p<&\\\"w 😀"}`

	var holder textHolder
	if err := json.Unmarshal([]byte(legacy), &holder); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	defer holder.Secret.Destroy()

	var str stringTextHolder
	if err := json.Unmarshal([]byte(legacy), &str); err != nil {
		t.Fatalf("unmarshal string: %v", err)
	}
	got, err := holder.Secret.Copy()
	if err != nil || string(got) != str.Secret {
		t.Errorf("decoded %q, want %q (%v)", got, str.Secret, err)
	}
	if !holder.Opt.IsZero() {
		t.Error("an absent key must leave the field empty")
	}
}

func TestSecretText_OmitZeroDropsEmptyField(t *testing.T) {
	out, err := json.Marshal(textHolder{})
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != `{"secret":""}` {
		t.Errorf("got %s", out)
	}
}

func TestSecretText_NullAndMalformedJSON(t *testing.T) {
	holder := textHolder{}
	if err := holder.Secret.Set([]byte("x")); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"secret":null}`), &holder); err != nil {
		t.Fatalf("null: %v", err)
	}
	if !holder.Secret.IsZero() {
		t.Error("null must clear the field")
	}

	for _, bad := range []string{`{"secret":42}`, `{"secret":[1]}`, `{"secret":"\u12"}`} {
		var h textHolder
		if err := json.Unmarshal([]byte(bad), &h); err == nil {
			t.Errorf("%s must be rejected", bad)
		}
		h.Secret.Destroy()
	}
}

func TestSecretText_MarshalOfDestroyedCopyFails(t *testing.T) {
	a, err := NewSecretText([]byte("gone"))
	if err != nil {
		t.Fatal(err)
	}
	b := a
	a.Destroy()
	if _, err := json.Marshal(b); err == nil {
		t.Error("marshalling a destroyed secret must fail rather than write an empty string")
	}
}
