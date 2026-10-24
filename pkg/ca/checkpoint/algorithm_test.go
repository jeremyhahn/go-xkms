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
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strconv"
	"strings"
	"sync"
	"testing"
)

// ed25519phAlgorithm is a custom algorithm: Ed25519ph (RFC 8032 §5.1), which
// signs the SHA-512 digest of the note text.
func ed25519phAlgorithm(id string) Algorithm {
	return Algorithm{
		ID:              id,
		Type:            TypeExtended,
		SignerOpts:      crypto.SHA512,
		EncodePublicKey: encodeEd25519,
		DecodePublicKey: decodeEd25519,
		Verify: func(pub crypto.PublicKey, text, sig []byte) bool {
			key, ok := pub.(ed25519.PublicKey)
			opts := &ed25519.Options{Hash: crypto.SHA512}
			return ok && ed25519.VerifyWithOptions(key, digest(crypto.SHA512, text), sig, opts) == nil
		},
	}
}

func TestRegisterCustomAlgorithmRoundTrip(t *testing.T) {
	isolateRegistry(t)
	const id = "example.com/ed25519ph"
	if err := Register(ed25519phAlgorithm(id)); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// The assigned Ed25519 type still wins when no algorithm is named.
	plain, err := NewSigner("log.example", key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if plain.Algorithm() != AlgorithmEd25519 {
		t.Fatalf("algorithm = %s, want %s", plain.Algorithm(), AlgorithmEd25519)
	}

	s, err := NewSigner("log.example", key, WithAlgorithm(id))
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.KeyID() == plain.KeyID() {
		t.Fatal("extended and assigned algorithms share a key ID")
	}
	v, err := NewVerifier(s.VerifierKey())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	if v.Algorithm() != id {
		t.Fatalf("verifier algorithm = %s", v.Algorithm())
	}
	note, err := Sign([]byte("text\n"), s)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if _, err := Open(note, v); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if _, err := Open(note, plain.Verifier()); !errors.Is(err, ErrNoValidSignature) {
		t.Fatalf("Open with the Ed25519 verifier: err = %v", err)
	}
}

func TestRegisterAssignedTypeOnce(t *testing.T) {
	isolateRegistry(t)
	alg := ed25519phAlgorithm("example.com/type-04")
	alg.Type = 0x04
	if err := Register(alg); err != nil {
		t.Fatalf("Register 0x04: %v", err)
	}
	again := ed25519phAlgorithm("example.com/type-04-again")
	again.Type = 0x04
	if err := Register(again); !errors.Is(err, ErrDuplicateAlgorithm) {
		t.Fatalf("second 0x04: err = %v, want ErrDuplicateAlgorithm", err)
	}
}

func TestRegisterRefusesInvalidAlgorithms(t *testing.T) {
	isolateRegistry(t)
	with := func(edit func(*Algorithm)) Algorithm {
		alg := ed25519phAlgorithm("example.com/invalid")
		edit(&alg)
		return alg
	}
	cases := map[string]struct {
		alg  Algorithm
		want error
	}{
		"empty ID":           {with(func(a *Algorithm) { a.ID = "" }), ErrInvalidAlgorithm},
		"space in ID":        {with(func(a *Algorithm) { a.ID = "example.com/a b" }), ErrInvalidAlgorithm},
		"non-ASCII ID":       {with(func(a *Algorithm) { a.ID = "example.com/é" }), ErrInvalidAlgorithm},
		"ID too long":        {with(func(a *Algorithm) { a.ID = strings.Repeat("a", MaxIdentifierLength+1) }), ErrInvalidAlgorithm},
		"no SignerOpts":      {with(func(a *Algorithm) { a.SignerOpts = nil }), ErrInvalidAlgorithm},
		"no encoder":         {with(func(a *Algorithm) { a.EncodePublicKey = nil }), ErrInvalidAlgorithm},
		"no decoder":         {with(func(a *Algorithm) { a.DecodePublicKey = nil }), ErrInvalidAlgorithm},
		"no verify":          {with(func(a *Algorithm) { a.Verify = nil }), ErrInvalidAlgorithm},
		"reserved 0x03":      {with(func(a *Algorithm) { a.Type = 0x03 }), ErrReservedType},
		"reserved 0xfa":      {with(func(a *Algorithm) { a.Type = 0xfa }), ErrReservedType},
		"unassigned 0x00":    {with(func(a *Algorithm) { a.Type = 0x00 }), ErrReservedType},
		"unassigned 0x07":    {with(func(a *Algorithm) { a.Type = 0x07 }), ErrReservedType},
		"built-in ID":        {with(func(a *Algorithm) { a.ID = AlgorithmMLDSA65 }), ErrDuplicateAlgorithm},
		"built-in type 0x01": {with(func(a *Algorithm) { a.Type = 0x01 }), ErrDuplicateAlgorithm},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if err := Register(tc.alg); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if err := Register(with(func(a *Algorithm) { a.ID = strings.Repeat("a", MaxIdentifierLength) })); err != nil {
		t.Fatalf("longest ID: %v", err)
	}
}

func TestRegisterConcurrent(t *testing.T) {
	isolateRegistry(t)
	const n = 32
	var wg sync.WaitGroup
	distinct := make([]error, n)
	same := make([]error, n)
	for i := range n {
		wg.Go(func() {
			distinct[i] = Register(ed25519phAlgorithm("example.com/concurrent-" + strconv.Itoa(i)))
			same[i] = Register(ed25519phAlgorithm("example.com/contended"))
		})
	}
	wg.Wait()
	won := 0
	for i := range n {
		if distinct[i] != nil {
			t.Fatalf("distinct registration %d: %v", i, distinct[i])
		}
		if same[i] == nil {
			won++
		} else if !errors.Is(same[i], ErrDuplicateAlgorithm) {
			t.Fatalf("contended registration: %v", same[i])
		}
	}
	if won != 1 {
		t.Fatalf("%d contended registrations succeeded, want 1", won)
	}
	for i := range n {
		if _, err := lookupID("example.com/concurrent-" + strconv.Itoa(i)); err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
	}
}

func TestSignerFailsWhenAlgorithmCannotDecodeItsKey(t *testing.T) {
	isolateRegistry(t)
	alg := ed25519phAlgorithm("example.com/no-decode")
	alg.DecodePublicKey = func([]byte) (crypto.PublicKey, error) { return nil, ErrMalformedVerifierKey }
	if err := Register(alg); err != nil {
		t.Fatalf("Register: %v", err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if _, err := NewSigner("log.example", key, WithAlgorithm(alg.ID)); !errors.Is(err, ErrInvalidAlgorithm) {
		t.Fatalf("err = %v, want ErrInvalidAlgorithm", err)
	}
}

func TestKeyTypeEncoding(t *testing.T) {
	ed, err := lookupID(AlgorithmEd25519)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	if got := ed.keyType(); string(got) != "\x01" {
		t.Fatalf("Ed25519 key type = %x", got)
	}
	ml, err := lookupID(AlgorithmMLDSA44)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}
	want := "\xff" + string(rune(len(AlgorithmMLDSA44))) + AlgorithmMLDSA44
	if got := ml.keyType(); string(got) != want {
		t.Fatalf("ML-DSA-44 key type = %q, want %q", got, want)
	}
	if _, err := lookupID("example.com/none"); !errors.Is(err, ErrUnknownAlgorithm) {
		t.Fatalf("unknown ID: err = %v", err)
	}
}

func TestHexByte(t *testing.T) {
	for b, want := range map[byte]string{0x00: "0x00", 0x0a: "0x0a", 0xff: "0xff", 0x3c: "0x3c"} {
		if got := hexByte(b); got != want {
			t.Fatalf("hexByte(%d) = %s, want %s", b, got, want)
		}
	}
}
