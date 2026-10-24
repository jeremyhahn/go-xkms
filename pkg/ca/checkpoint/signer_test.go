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
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
)

func TestSignerAccessors(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	v := s.Verifier()
	if s.Name() != "log.example" || v.Name() != "log.example" {
		t.Fatalf("names = %q, %q", s.Name(), v.Name())
	}
	if s.KeyID() != v.KeyID() || s.Algorithm() != v.Algorithm() {
		t.Fatal("signer and verifier disagree")
	}
	vkey := s.VerifierKey()
	if !strings.HasPrefix(vkey, "log.example+") || len(strings.Split(vkey, "+")[1]) != 8 {
		t.Fatalf("verifier key = %s", vkey)
	}
}

func TestNewSignerWitnessECDSAKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner("witness.example", key)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	sum := sha256.Sum256(spki)
	if s.KeyID() != binary.BigEndian.Uint32(sum[:]) {
		t.Fatalf("key ID %08x is not SHA-256(SPKI)[:4]", s.KeyID())
	}
}

func TestNewSignerRefusesInvalidInput(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	xKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := map[string]struct {
		name string
		key  *fakeSigner
		opts []SignerOption
		want error
	}{
		"empty name":           {"", &fakeSigner{pub: &ecKey.PublicKey}, nil, ErrInvalidKeyName},
		"space in name":        {"log example", &fakeSigner{pub: &ecKey.PublicKey}, nil, ErrInvalidKeyName},
		"plus in name":         {"log+example", &fakeSigner{pub: &ecKey.PublicKey}, nil, ErrInvalidKeyName},
		"control in name":      {"log\x7f", &fakeSigner{pub: &ecKey.PublicKey}, nil, ErrInvalidKeyName},
		"invalid UTF-8 name":   {"log\xff", &fakeSigner{pub: &ecKey.PublicKey}, nil, ErrInvalidKeyName},
		"unsupported key":      {"log.example", &fakeSigner{pub: xKey.PublicKey()}, nil, ErrUnsupportedKey},
		"ambiguous RSA key":    {"log.example", &fakeSigner{pub: &rsaTestKey().PublicKey}, nil, ErrAmbiguousAlgorithm},
		"unknown algorithm":    {"log.example", &fakeSigner{pub: &ecKey.PublicKey}, []SignerOption{WithAlgorithm("example.com/none")}, ErrUnknownAlgorithm},
		"key of another alg":   {"log.example", &fakeSigner{pub: &ecKey.PublicKey}, []SignerOption{WithAlgorithm(AlgorithmEd25519)}, ErrUnsupportedKey},
		"curve of another alg": {"log.example", &fakeSigner{pub: &ecKey.PublicKey}, []SignerOption{WithAlgorithm(AlgorithmECDSAP384SHA384)}, ErrUnsupportedKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewSigner(tc.name, tc.key, tc.opts...); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
	if _, err := NewSigner("log.example", nil); !errors.Is(err, ErrNoSigner) {
		t.Fatalf("nil signer: err = %v", err)
	}
}

func TestNewVerifierRefusesMalformedKeys(t *testing.T) {
	b64 := func(b ...byte) string { return base64.StdEncoding.EncodeToString(b) }
	ed := make([]byte, 33)
	ed[0] = 0x01
	extended := func(id string, material ...byte) string {
		return b64(append(append([]byte{TypeExtended, byte(len(id))}, id...), material...)...)
	}
	cases := map[string]struct {
		vkey string
		want error
	}{
		"no separators":         {"example.com/foo", ErrMalformedVerifierKey},
		"empty name":            {"+530d903a+" + b64(ed...), ErrInvalidKeyName},
		"space in name":         {"example com+530d903a+" + b64(ed...), ErrInvalidKeyName},
		"missing public key":    {"example.com/foo+530d903a", ErrMalformedVerifierKey},
		"uppercase key ID":      {"example.com/foo+530D903A+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k", ErrMalformedVerifierKey},
		"short key ID":          {"example.com/foo+530d903+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k", ErrMalformedVerifierKey},
		"invalid base64":        {"example.com/foo+530d903a+!!!!", ErrMalformedVerifierKey},
		"unpadded base64":       {"example.com/foo+530d903a+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2", ErrMalformedVerifierKey},
		"key bytes too short":   {"example.com/foo+530d903a+" + b64(0x01), ErrMalformedVerifierKey},
		"reserved type byte":    {"example.com/foo+530d903a+" + b64(append([]byte{0x03}, ed[1:]...)...), ErrUnknownAlgorithm},
		"unregistered type":     {"example.com/foo+530d903a+" + b64(append([]byte{0x04}, ed[1:]...)...), ErrUnknownAlgorithm},
		"short Ed25519 key":     {"example.com/foo+530d903a+" + b64(ed[:32]...), ErrMalformedVerifierKey},
		"key ID mismatch":       {"example.com/foo+530d903b+AekyeRrm56hApGFkyQR4ZCbV54Id2LKaANYcrnKv3U2k", ErrKeyIDMismatch},
		"empty extended ID":     {"example.com/foo+530d903a+" + b64(TypeExtended, 0, 1), ErrMalformedVerifierKey},
		"truncated extended ID": {"example.com/foo+530d903a+" + b64(TypeExtended, 10, 'a'), ErrMalformedVerifierKey},
		"no extended material":  {"example.com/foo+530d903a+" + extended(AlgorithmMLDSA44), ErrMalformedVerifierKey},
		"unknown extended ID":   {"example.com/foo+530d903a+" + extended("example.com/none", 1), ErrUnknownAlgorithm},
		"extended assigned alg": {"example.com/foo+530d903a+" + extended(AlgorithmEd25519, ed[1:]...), ErrUnknownAlgorithm},
		"bad ML-DSA material":   {"example.com/foo+530d903a+" + extended(AlgorithmMLDSA44, 1, 2, 3), ErrMalformedVerifierKey},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := NewVerifier(tc.vkey); !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestVerifierRefusesForeignSignature(t *testing.T) {
	s := newEd25519Signer(t, "log.example")
	other := newEd25519Signer(t, "log.example")
	note, err := Sign([]byte("text\n"), other)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	n, err := Open(note, other.Verifier())
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(n.Verified[0].Base64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !other.Verifier().Verify(n.Text, raw[4:]) {
		t.Fatal("signer's own verifier refused its signature")
	}
	if s.Verifier().Verify(n.Text, raw[4:]) {
		t.Fatal("verifier accepted another key's signature")
	}
}
