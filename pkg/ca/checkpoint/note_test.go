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

package checkpoint

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"
	"testing"
)

// The signed-note §Verifier keys example.
const (
	specVerifierKey = "example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k"
	specNote        = "This is an example message.\n\n— example.com/foo Uw2QOkn8srV1yJGh2VYRlL1Tnagv1YEq6TfXppzi2ONncAlTgK7Ztg1ERYNZXsYjOBH3mFXmRKuwHjG1Yu72IneyaQM=\n"
)

func TestOpenSpecExample(t *testing.T) {
	v, err := NewVerifier(specVerifierKey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.Name() != "example.com/foo" || v.KeyID() != 0x530d903a || v.Algorithm() != AlgorithmEd25519 {
		t.Fatalf("verifier = %s %08x %s", v.Name(), v.KeyID(), v.Algorithm())
	}
	n, err := Open([]byte(specNote), v)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if string(n.Text) != "This is an example message.\n" {
		t.Fatalf("text = %q", n.Text)
	}
	if len(n.Verified) != 1 || n.Verified[0].Name != "example.com/foo" || n.Verified[0].KeyID != 0x530d903a {
		t.Fatalf("verified = %+v", n.Verified)
	}

	tampered := strings.Replace(specNote, "example message", "example massage", 1)
	if _, err := Open([]byte(tampered), v); !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("tampered: err = %v, want ErrSignatureInvalid", err)
	}
}

func TestSignOpenEveryBuiltin(t *testing.T) {
	text := []byte("go-xkms checkpoint note\n")
	for _, tc := range builtinCases(t) {
		t.Run(tc.id, func(t *testing.T) {
			s, err := NewSigner("log.example/"+tc.id, tc.key, tc.opts...)
			if err != nil {
				t.Fatalf("NewSigner: %v", err)
			}
			if s.Algorithm() != tc.id {
				t.Fatalf("algorithm = %s, want %s", s.Algorithm(), tc.id)
			}
			v, err := NewVerifier(s.VerifierKey())
			if err != nil {
				t.Fatalf("NewVerifier(%s): %v", s.VerifierKey(), err)
			}
			if v.KeyID() != s.KeyID() || v.Algorithm() != tc.id {
				t.Fatalf("verifier %08x %s, signer %08x", v.KeyID(), v.Algorithm(), s.KeyID())
			}
			note, err := Sign(text, s)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			n, err := Open(note, v)
			if err != nil {
				t.Fatalf("Open: %v", err)
			}
			if !bytes.Equal(n.Text, text) || len(n.Verified) != 1 {
				t.Fatalf("opened %q with %d signatures", n.Text, len(n.Verified))
			}
			tampered := bytes.Replace(note, []byte("checkpoint"), []byte("checkpoinT"), 1)
			if _, err := Open(tampered, v); !errors.Is(err, ErrSignatureInvalid) {
				t.Fatalf("tampered: err = %v, want ErrSignatureInvalid", err)
			}
		})
	}
}

func TestOpenIgnoresUnknownKeys(t *testing.T) {
	log := newEd25519Signer(t, "log.example")
	witness := newEd25519Signer(t, "witness.example")
	note, err := Sign([]byte("text\n"), log, witness)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	n, err := Open(note, log.Verifier())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(n.Verified) != 1 || n.Verified[0].Name != "log.example" {
		t.Fatalf("verified = %+v", n.Verified)
	}
	if len(n.Unverified) != 1 || n.Unverified[0].Name != "witness.example" || n.Unverified[0].KeyID != witness.KeyID() {
		t.Fatalf("unverified = %+v", n.Unverified)
	}
}

func TestOpenRefusesNoKnownSignature(t *testing.T) {
	signer := newEd25519Signer(t, "log.example")
	sameName := newEd25519Signer(t, "log.example")
	note, err := Sign([]byte("text\n"), signer)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Open(note, sameName.Verifier()); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("wrong key: err = %v, want ErrNoValidSignature", err)
	}
}

func TestOpenRefusesBadVerifiers(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	note, err := Sign([]byte("text\n"), s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Open(note); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("no verifier: err = %v", err)
	}
	if _, err := Open(note, nil); !errors.Is(err, ErrNoVerifier) {
		t.Fatalf("nil verifier: err = %v", err)
	}
	if _, err := Open(note, s.Verifier(), s.Verifier()); !errors.Is(err, ErrDuplicateVerifier) {
		t.Fatalf("duplicate verifier: err = %v", err)
	}
}

func TestOpenRefusesMalformedNotes(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	sig := func(raw []byte) string { return base64.StdEncoding.EncodeToString(raw) }
	valid := sig([]byte{1, 2, 3, 4, 5})
	cases := map[string]struct {
		note string
		want error
	}{
		"no blank line":         {"text\n— a " + valid + "\n", ErrMalformedNote},
		"no final newline":      {"text\n\n— a " + valid, ErrMalformedNote},
		"no signature lines":    {"text\n\n", ErrMalformedNote},
		"hyphen not em dash":    {"text\n\n- a " + valid + "\n", ErrMalformedNote},
		"missing signature":     {"text\n\n— a\n", ErrMalformedNote},
		"plus in key name":      {"text\n\n— a+b " + valid + "\n", ErrMalformedNote},
		"empty key name":        {"text\n\n—  " + valid + "\n", ErrMalformedNote},
		"invalid base64":        {"text\n\n— a !!!!\n", ErrMalformedNote},
		"non-canonical base64":  {"text\n\n— a AQIDBAV=\n", ErrMalformedNote},
		"signature too short":   {"text\n\n— a " + sig([]byte{1, 2, 3, 4}) + "\n", ErrMalformedNote},
		"control character":     {"te\x01xt\n\n— a " + valid + "\n", ErrMalformedNote},
		"invalid UTF-8":         {"te\xffxt\n\n— a " + valid + "\n", ErrMalformedNote},
		"duplicate signature":   {"text\n\n— a " + valid + "\n— a " + valid + "\n", ErrDuplicateSignature},
		"blank signature line":  {"text\n\n— a " + valid + "\n\n", ErrMalformedNote},
		"carriage return":       {"text\r\n\n— a " + valid + "\n", ErrMalformedNote},
		"too many signatures":   {"text\n\n" + manySignatureLines(MaxSignatures+1), ErrTooManySignatures},
		"trailing space on key": {"text\n\n— a " + valid + " \n", ErrMalformedNote},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Open([]byte(tc.note), s.Verifier()); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestOpenAcceptsMaxSignatures(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	note, err := Sign([]byte("text\n"), s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	note = append(note, manySignatureLines(MaxSignatures-1)...)
	n, err := Open(note, s.Verifier())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if len(n.Unverified) != MaxSignatures-1 {
		t.Fatalf("unverified = %d", len(n.Unverified))
	}
}

// manySignatureLines returns n well-formed signature lines from distinct
// unknown keys.
func manySignatureLines(n int) string {
	var b strings.Builder
	for i := range n {
		b.WriteString("— unknown" + strconv.Itoa(i) + " " + base64.StdEncoding.EncodeToString([]byte{0, 0, 0, byte(i), 1}) + "\n")
	}
	return b.String()
}

func TestSignRefusesInvalidInput(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	textCases := map[string]string{
		"empty":             "",
		"no final newline":  "text",
		"control character": "te\x00xt\n",
		"invalid UTF-8":     "te\xffxt\n",
	}
	for name, text := range textCases {
		t.Run(name, func(t *testing.T) {
			if _, err := Sign([]byte(text), s); !errors.Is(err, ErrInvalidText) {
				t.Fatalf("err = %v, want ErrInvalidText", err)
			}
		})
	}
	if _, err := Sign([]byte("text\n")); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("no signer: err = %v", err)
	}
	if _, err := Sign([]byte("text\n"), s, nil); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("nil signer: err = %v", err)
	}
	if _, err := Sign([]byte("text\n"), s, s); !errors.Is(err, ErrDuplicateSignature) {
		t.Fatalf("duplicate signer: err = %v", err)
	}
}

func TestSignRefusesFailingSigner(t *testing.T) {
	good := newEd25519Signer(t, "log.example")
	pub := good.Verifier().key

	failing, err := NewSigner("log.example", &fakeSigner{pub: pub, err: errors.New("token removed")})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := Sign([]byte("text\n"), failing); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("signer error: err = %v, want ErrSigningFailed", err)
	}

	wrongScheme, err := NewSigner("log.example", &fakeSigner{pub: pub, sig: make([]byte, 64)})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if _, err := Sign([]byte("text\n"), wrongScheme); !errors.Is(err, ErrSigningFailed) {
		t.Fatalf("bad signature: err = %v, want ErrSigningFailed", err)
	}
}
