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

package refvalue

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/veraison/corim/corim"
	cose "github.com/veraison/go-cose"
)

// signMeta is the corim-meta the Sign tests use.
func signMeta() Meta {
	return Meta{
		SignerName: "Example Reference Value Provider",
		SignerURI:  "https://example.com/rvp",
		NotBefore:  fixedNow.Add(-time.Hour),
		NotAfter:   fixedNow.Add(time.Hour),
	}
}

func newRSAKey(t *testing.T, bits int) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatalf("rsa key: %v", err)
	}
	return k
}

func TestSign_RoundTrip(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
		alg    cose.Algorithm
	}{
		{"ES256", newKey(t, elliptic.P256()), cose.AlgorithmES256},
		{"ES384", newKey(t, elliptic.P384()), cose.AlgorithmES384},
		{"ES512", newKey(t, elliptic.P521()), cose.AlgorithmES512},
		{"PS256", newRSAKey(t, 2048), cose.AlgorithmPS256},
		{"EdDSA", edKey, cose.AlgorithmEdDSA},
	} {
		t.Run(tc.name, func(t *testing.T) {
			unsigned := buildUnsigned(t, buildCoMID(t), nil)
			data, err := Sign(unsigned, signMeta(), tc.signer)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			m, err := VerifySigned(data, VerifyOptions{PublicKey: tc.signer.Public(), Now: fixedNow})
			if err != nil {
				t.Fatalf("VerifySigned: %v", err)
			}
			checkManifest(t, m)
			if m.Signer != "Example Reference Value Provider" {
				t.Fatalf("signer = %q", m.Signer)
			}
			if !m.NotBefore.Equal(fixedNow.Add(-time.Hour)) || !m.NotAfter.Equal(fixedNow.Add(time.Hour)) {
				t.Fatalf("validity = %v..%v", m.NotBefore, m.NotAfter)
			}
			checkProtectedHeader(t, data, tc.alg)
		})
	}
}

// checkProtectedHeader asserts the §4.2 shape: tag 18, alg, content type,
// corim-meta, and a payload tagged #6.501.
func checkProtectedHeader(t *testing.T, data []byte, alg cose.Algorithm) {
	t.Helper()
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		t.Fatalf("COSE_Sign1: %v", err)
	}
	got, err := msg.Headers.Protected.Algorithm()
	if err != nil || got != alg {
		t.Fatalf("alg = %v (%v), want %v", got, err, alg)
	}
	if ct := msg.Headers.Protected[cose.HeaderLabelContentType]; ct != corim.ContentType {
		t.Fatalf("content type = %v", ct)
	}
	if _, ok := msg.Headers.Protected[corim.HeaderLabelCorimMeta]; !ok {
		t.Fatal("protected header has no corim-meta")
	}
	var tag cbor.RawTag
	if err := cbor.Unmarshal(msg.Payload, &tag); err != nil || tag.Number != tagUnsignedCorim {
		t.Fatalf("payload tag = %d (%v), want %d", tag.Number, err, tagUnsignedCorim)
	}
}

func TestSign_TaggedInputAndRSAStrength(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	tagged, err := cbor.Marshal(cbor.RawTag{Number: tagUnsignedCorim, Content: unsigned})
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	key := newRSAKey(t, 3072)
	data, err := Sign(tagged, Meta{SignerName: "rvp"}, key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	m, err := VerifySigned(data, VerifyOptions{PublicKey: key.Public(), Now: fixedNow})
	if err != nil {
		t.Fatalf("VerifySigned: %v", err)
	}
	if !m.NotBefore.IsZero() || !m.NotAfter.IsZero() {
		t.Fatalf("validity = %v..%v, want none", m.NotBefore, m.NotAfter)
	}
	checkProtectedHeader(t, data, cose.AlgorithmPS384)
}

func TestRSAAlgorithm(t *testing.T) {
	for bits, want := range map[int]cose.Algorithm{
		2048: cose.AlgorithmPS256,
		3072: cose.AlgorithmPS384,
		4096: cose.AlgorithmPS512,
	} {
		if got, err := rsaAlgorithm(bits); err != nil || got != want {
			t.Fatalf("rsaAlgorithm(%d) = %v, %v; want %v", bits, got, err, want)
		}
	}
	if _, err := rsaAlgorithm(1024); !errors.Is(err, ErrSignerKey) {
		t.Fatalf("rsaAlgorithm(1024) err = %v, want ErrSignerKey", err)
	}
}

// failingSigner is a P-256 signer whose Sign always fails, as a backend
// signer does when its token is gone.
type failingSigner struct{ crypto.Signer }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("token removed")
}

func TestSign_Errors(t *testing.T) {
	key := newKey(t, elliptic.P256())
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	p224, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("p224 key: %v", err)
	}
	wrongTag, err := cbor.Marshal(cbor.RawTag{Number: 500, Content: unsigned})
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	for _, tc := range []struct {
		name     string
		unsigned []byte
		meta     Meta
		signer   crypto.Signer
		want     error
	}{
		{"nil signer", unsigned, signMeta(), nil, ErrSignerKey},
		{"P-224 key", unsigned, signMeta(), p224, ErrSignerKey},
		{"short RSA key", unsigned, signMeta(), newRSAKey(t, 1024), ErrSignerKey},
		{"not CBOR", []byte{0xff}, signMeta(), key, ErrMalformed},
		{"wrong tag", wrongTag, signMeta(), key, ErrMalformed},
		{"empty signer name", unsigned, Meta{}, key, ErrMeta},
		{"inverted validity", unsigned, Meta{SignerName: "rvp", NotBefore: fixedNow, NotAfter: fixedNow.Add(-time.Hour)}, key, ErrMeta},
		{"not-before alone", unsigned, Meta{SignerName: "rvp", NotBefore: fixedNow}, key, ErrMeta},
		{"bad signer uri", unsigned, Meta{SignerName: "rvp", SignerURI: "::not a uri"}, key, ErrMeta},
		{"signer fails", unsigned, signMeta(), failingSigner{key}, ErrSign},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := Sign(tc.unsigned, tc.meta, tc.signer); !errors.Is(err, tc.want) {
				t.Fatalf("Sign err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestSign_TamperedPayloadFailsVerification(t *testing.T) {
	key := newKey(t, elliptic.P256())
	data, err := Sign(buildUnsigned(t, buildCoMID(t), nil), signMeta(), key)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	var msg cose.Sign1Message
	if err := msg.UnmarshalCBOR(data); err != nil {
		t.Fatalf("COSE_Sign1: %v", err)
	}
	other := buildUnsigned(t, buildCoMID(t), window(fixedNow.Add(-2*time.Hour), fixedNow.Add(2*time.Hour)))
	msg.Payload, err = cbor.Marshal(cbor.RawTag{Number: tagUnsignedCorim, Content: other})
	if err != nil {
		t.Fatalf("tag: %v", err)
	}
	tampered, err := msg.MarshalCBOR()
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if _, err := VerifySigned(tampered, VerifyOptions{PublicKey: key.Public(), Now: fixedNow}); !errors.Is(err, ErrSignature) {
		t.Fatalf("VerifySigned err = %v, want ErrSignature", err)
	}
}
