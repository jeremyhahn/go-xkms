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
	"slices"
	"strings"
	"testing"
)

var testRoot = bytes.Repeat([]byte{0xab}, HashSize)

func TestCheckpointMarshalParse(t *testing.T) {
	c := &Checkpoint{
		Origin:     "example.com/log",
		Size:       18446744073709551615,
		Hash:       testRoot,
		Extensions: []string{"extension one", "extension two"},
	}
	text, err := c.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := "example.com/log\n18446744073709551615\n" + base64.StdEncoding.EncodeToString(testRoot) + "\nextension one\nextension two\n"
	if string(text) != want {
		t.Fatalf("text = %q, want %q", text, want)
	}
	got, err := ParseCheckpoint(text)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	if got.Origin != c.Origin || got.Size != c.Size || !bytes.Equal(got.Hash, c.Hash) || !slices.Equal(got.Extensions, c.Extensions) {
		t.Fatalf("parsed %+v, want %+v", got, c)
	}

	empty := &Checkpoint{Origin: "example.com/log", Hash: testRoot}
	text, err = empty.Marshal()
	if err != nil {
		t.Fatalf("Marshal size 0: %v", err)
	}
	got, err = ParseCheckpoint(text)
	if err != nil {
		t.Fatalf("ParseCheckpoint size 0: %v", err)
	}
	if got.Size != 0 || got.Extensions != nil {
		t.Fatalf("parsed %+v", got)
	}
}

func TestCheckpointMarshalRefusesInvalidFields(t *testing.T) {
	cases := map[string]struct {
		c    Checkpoint
		want error
	}{
		"short root hash":     {Checkpoint{Origin: "o", Hash: testRoot[:31]}, ErrInvalidRootHash},
		"missing root hash":   {Checkpoint{Origin: "o"}, ErrInvalidRootHash},
		"empty origin":        {Checkpoint{Hash: testRoot}, ErrMalformedCheckpoint},
		"newline in origin":   {Checkpoint{Origin: "o\nx", Hash: testRoot}, ErrMalformedCheckpoint},
		"control in origin":   {Checkpoint{Origin: "o\x01", Hash: testRoot}, ErrMalformedCheckpoint},
		"empty extension":     {Checkpoint{Origin: "o", Hash: testRoot, Extensions: []string{""}}, ErrMalformedCheckpoint},
		"invalid UTF-8 extra": {Checkpoint{Origin: "o", Hash: testRoot, Extensions: []string{"\xff"}}, ErrMalformedCheckpoint},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := tc.c.Marshal(); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestParseCheckpointRefusesMalformedText(t *testing.T) {
	root := base64.StdEncoding.EncodeToString(testRoot)
	nonCanonical := []byte(base64.StdEncoding.EncodeToString(make([]byte, HashSize)))
	nonCanonical[42] = 'B'
	cases := map[string]struct {
		text string
		want error
	}{
		"empty":                {"", ErrMalformedCheckpoint},
		"no final newline":     {"o\n1\n" + root, ErrMalformedCheckpoint},
		"two lines":            {"o\n1\n", ErrMalformedCheckpoint},
		"empty line":           {"o\n1\n" + root + "\n\next\n", ErrMalformedCheckpoint},
		"empty origin":         {"\n1\n" + root + "\n", ErrMalformedCheckpoint},
		"control character":    {"o\x01\n1\n" + root + "\n", ErrMalformedCheckpoint},
		"invalid UTF-8":        {"o\xff\n1\n" + root + "\n", ErrMalformedCheckpoint},
		"leading zero":         {"o\n01\n" + root + "\n", ErrInvalidTreeSize},
		"negative size":        {"o\n-1\n" + root + "\n", ErrInvalidTreeSize},
		"plus sign":            {"o\n+1\n" + root + "\n", ErrInvalidTreeSize},
		"hex size":             {"o\n1a\n" + root + "\n", ErrInvalidTreeSize},
		"size overflow":        {"o\n18446744073709551616\n" + root + "\n", ErrInvalidTreeSize},
		"root not base64":      {"o\n1\n!!!!\n", ErrInvalidRootHash},
		"root 31 bytes":        {"o\n1\n" + base64.StdEncoding.EncodeToString(testRoot[:31]) + "\n", ErrInvalidRootHash},
		"root unpadded":        {"o\n1\n" + strings.TrimSuffix(root, "=") + "\n", ErrInvalidRootHash},
		"root non-canonical":   {"o\n1\n" + string(nonCanonical) + "\n", ErrInvalidRootHash},
		"root URL-safe base64": {"o\n1\n" + base64.URLEncoding.EncodeToString(bytes.Repeat([]byte{0xff}, HashSize)) + "\n", ErrInvalidRootHash},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseCheckpoint([]byte(tc.text)); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSignOpenCheckpoint(t *testing.T) {
	log := newEd25519Signer(t, "example.com/log")
	witness := newEd25519Signer(t, "witness.example")
	c := &Checkpoint{Origin: "example.com/log", Size: 42, Hash: testRoot}
	note, err := SignCheckpoint(c, log, witness)
	if err != nil {
		t.Fatalf("SignCheckpoint: %v", err)
	}
	got, n, err := OpenCheckpoint(note, log.Verifier())
	if err != nil {
		t.Fatalf("OpenCheckpoint: %v", err)
	}
	if got.Origin != c.Origin || got.Size != 42 || !bytes.Equal(got.Hash, testRoot) {
		t.Fatalf("checkpoint = %+v", got)
	}
	if len(n.Verified) != 1 || len(n.Unverified) != 1 {
		t.Fatalf("verified %d, unverified %d", len(n.Verified), len(n.Unverified))
	}
}

func TestSignOpenCheckpointRefusals(t *testing.T) {
	log := newEd25519Signer(t, "example.com/log")
	if _, err := SignCheckpoint(&Checkpoint{Origin: "example.com/log"}, log); !errors.Is(err, ErrInvalidRootHash) {
		t.Fatalf("SignCheckpoint: err = %v, want ErrInvalidRootHash", err)
	}
	if _, _, err := OpenCheckpoint([]byte("not a note"), log.Verifier()); !errors.Is(err, ErrMalformedNote) {
		t.Fatalf("OpenCheckpoint malformed: err = %v", err)
	}
	notCheckpoint, err := Sign([]byte("just one line\n"), log)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, _, err := OpenCheckpoint(notCheckpoint, log.Verifier()); !errors.Is(err, ErrMalformedCheckpoint) {
		t.Fatalf("OpenCheckpoint non-checkpoint: err = %v, want ErrMalformedCheckpoint", err)
	}
}
