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
	"encoding/binary"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// MaxSignatures is the most signature lines Open accepts on one note.
// signed-note §Format requires accepting at least 16.
const MaxSignatures = 100

// signaturePrefix starts every signature line: an em dash (U+2014) and a
// space (signed-note §Format).
const signaturePrefix = "— "

// A Signature is one signature line of a note.
type Signature struct {
	// Name is the key name.
	Name string

	// KeyID is the key ID.
	KeyID uint32

	// Base64 is the base64 encoding of the key ID and the signature, as
	// written on the signature line.
	Base64 string
}

// A Note is a signed note opened by Open.
type Note struct {
	// Text is the note text, ending in a newline.
	Text []byte

	// Verified are the signatures that verified under a supplied verifier.
	Verified []Signature

	// Unverified are the signatures from keys no supplied verifier knows,
	// kept so a cosigner can carry them forward.
	Unverified []Signature
}

// verifierKey identifies a key by name and key ID (signed-note §Signatures).
type verifierKey struct {
	name string
	id   uint32
}

// Sign signs text with every signer and returns the signed note: the text,
// a blank line, and one signature line per signer (signed-note §Format).
// The text must be non-empty valid UTF-8 ending in a newline, without
// control characters other than newline. Two signers sharing a key name and
// key ID are refused with ErrDuplicateSignature.
func Sign(text []byte, signers ...*Signer) ([]byte, error) {
	if err := validateText(text); err != nil {
		return nil, err
	}
	if len(signers) == 0 {
		return nil, ErrNoSigner
	}
	seen := make(map[verifierKey]bool, len(signers))
	var lines bytes.Buffer
	for _, s := range signers {
		if s == nil {
			return nil, ErrNoSigner
		}
		k := verifierKey{name: s.Name(), id: s.KeyID()}
		if seen[k] {
			return nil, &errs.Detail{Err: ErrDuplicateSignature, Detail: k.name}
		}
		seen[k] = true
		sig, err := s.sign(text)
		if err != nil {
			return nil, err
		}
		lines.WriteString(signaturePrefix)
		lines.WriteString(k.name)
		lines.WriteByte(' ')
		lines.WriteString(base64.StdEncoding.EncodeToString(sig))
		lines.WriteByte('\n')
	}
	out := make([]byte, 0, len(text)+1+lines.Len())
	out = append(out, text...)
	out = append(out, '\n')
	return append(out, lines.Bytes()...), nil
}

// Open parses a signed note and verifies its signatures against verifiers
// (signed-note §Signatures). A signature from a key no verifier knows is
// ignored and returned in Note.Unverified. A signature from a known key that
// does not verify refuses the note with ErrSignatureInvalid, and a note with
// no verified signature is refused with ErrNoValidSignature. Two verifiers
// sharing a key name and key ID are refused with ErrDuplicateVerifier.
func Open(note []byte, verifiers ...*Verifier) (*Note, error) {
	known, err := indexVerifiers(verifiers)
	if err != nil {
		return nil, err
	}
	text, sigs, err := parseNote(note)
	if err != nil {
		return nil, err
	}
	n := &Note{Text: text}
	for _, sig := range sigs {
		v, ok := known[verifierKey{name: sig.Name, id: sig.KeyID}]
		if !ok {
			n.Unverified = append(n.Unverified, sig.Signature)
			continue
		}
		if !v.Verify(text, sig.raw) {
			return nil, &errs.Detail{Err: ErrSignatureInvalid, Detail: sig.Name}
		}
		n.Verified = append(n.Verified, sig.Signature)
	}
	if len(n.Verified) == 0 {
		return nil, ErrNoValidSignature
	}
	return n, nil
}

// indexVerifiers maps verifiers by key name and key ID.
func indexVerifiers(verifiers []*Verifier) (map[verifierKey]*Verifier, error) {
	if len(verifiers) == 0 {
		return nil, ErrNoVerifier
	}
	known := make(map[verifierKey]*Verifier, len(verifiers))
	for _, v := range verifiers {
		if v == nil {
			return nil, ErrNoVerifier
		}
		k := verifierKey{name: v.name, id: v.id}
		if _, dup := known[k]; dup {
			return nil, &errs.Detail{Err: ErrDuplicateVerifier, Detail: v.name}
		}
		known[k] = v
	}
	return known, nil
}

// parsedSignature is a signature line with its decoded signature bytes.
type parsedSignature struct {
	Signature
	raw []byte
}

// parseNote splits a note into its text and signature lines. The text ends
// at the last blank line; every following line must be a signature line
// with a valid key name and canonical base64 of at least five bytes.
func parseNote(note []byte) ([]byte, []parsedSignature, error) {
	if !validNoteBytes(note) {
		return nil, nil, &errs.Detail{Err: ErrMalformedNote, Detail: "invalid UTF-8 or control character"}
	}
	split := bytes.LastIndex(note, []byte("\n\n"))
	if split < 0 || !bytes.HasSuffix(note, []byte("\n")) {
		return nil, nil, &errs.Detail{Err: ErrMalformedNote, Detail: "missing signature block"}
	}
	text := note[:split+1]
	block := note[split+2:]
	if len(block) == 0 {
		return nil, nil, &errs.Detail{Err: ErrMalformedNote, Detail: "no signature lines"}
	}
	lines := bytes.Split(block[:len(block)-1], []byte("\n"))
	if len(lines) > MaxSignatures {
		return nil, nil, &errs.Detail{Err: ErrTooManySignatures, Detail: strconv.Itoa(len(lines))}
	}
	sigs := make([]parsedSignature, 0, len(lines))
	seen := make(map[verifierKey]bool, len(lines))
	for _, line := range lines {
		sig, err := parseSignatureLine(string(line))
		if err != nil {
			return nil, nil, err
		}
		k := verifierKey{name: sig.Name, id: sig.KeyID}
		if seen[k] {
			return nil, nil, &errs.Detail{Err: ErrDuplicateSignature, Detail: sig.Name}
		}
		seen[k] = true
		sigs = append(sigs, sig)
	}
	return text, sigs, nil
}

// parseSignatureLine parses "— <name> <base64(key ID || signature)>".
func parseSignatureLine(line string) (parsedSignature, error) {
	rest, ok := strings.CutPrefix(line, signaturePrefix)
	if !ok {
		return parsedSignature{}, &errs.Detail{Err: ErrMalformedNote, Detail: "signature line must start with an em dash and a space"}
	}
	name, b64, ok := strings.Cut(rest, " ")
	if !ok || !validKeyName(name) {
		return parsedSignature{}, &errs.Detail{Err: ErrMalformedNote, Detail: "invalid signature key name"}
	}
	raw, ok := decodeBase64(b64)
	if !ok || len(raw) < 5 {
		return parsedSignature{}, &errs.Detail{Err: ErrMalformedNote, Detail: "invalid signature encoding"}
	}
	return parsedSignature{
		Signature: Signature{Name: name, KeyID: binary.BigEndian.Uint32(raw), Base64: b64},
		raw:       raw[4:],
	}, nil
}

// validateText refuses note text Sign cannot sign (signed-note §Format).
func validateText(text []byte) error {
	if len(text) == 0 || text[len(text)-1] != '\n' {
		return &errs.Detail{Err: ErrInvalidText, Detail: "text must end in a newline"}
	}
	if !validNoteBytes(text) {
		return &errs.Detail{Err: ErrInvalidText, Detail: "invalid UTF-8 or control character"}
	}
	return nil
}

// validNoteBytes reports whether b is valid UTF-8 without control
// characters other than newline (signed-note §Format).
func validNoteBytes(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if r != '\n' && unicode.IsControl(r) {
			return false
		}
	}
	return true
}
