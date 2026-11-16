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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"testing"

	"github.com/veraison/go-cose"
)

// testSignerName is the signer checkManifest expects.
const testSignerName = "Example Reference Value Provider"

func TestSignRoundTrip(t *testing.T) {
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 key: %v", err)
	}
	cases := []struct {
		name string
		alg  cose.Algorithm
		key  crypto.Signer
	}{
		{"ES256", cose.AlgorithmES256, newKey(t, elliptic.P256())},
		{"ES384", cose.AlgorithmES384, newKey(t, elliptic.P384())},
		{"EdDSA", cose.AlgorithmEdDSA, edKey},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			unsigned := buildUnsigned(t, buildCoMID(t), nil)
			signed, err := Sign(context.Background(), unsigned, tc.key, tc.alg, testSignerName)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			m, err := VerifySigned(signed, VerifyOptions{PublicKey: tc.key.Public()})
			if err != nil {
				t.Fatalf("VerifySigned: %v", err)
			}
			checkManifest(t, m)
		})
	}
}

func TestSignWrongKeyFailsVerify(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	signed, err := Sign(context.Background(), unsigned, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	other := newKey(t, elliptic.P256())
	if _, err := VerifySigned(signed, VerifyOptions{PublicKey: other.Public()}); !errors.Is(err, ErrSignature) {
		t.Fatalf("VerifySigned with the wrong key: got %v, want ErrSignature", err)
	}
}

func TestSignRefusesNilSigner(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(context.Background(), unsigned, nil, cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrNilSigner) {
		t.Fatalf("got %v, want ErrNilSigner", err)
	}
}

// opaqueSigner is a crypto.Signer whose public key go-cose does not know.
type opaqueSigner struct{}

func (opaqueSigner) Public() crypto.PublicKey { return struct{}{} }

func (opaqueSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("opaque signer cannot sign")
}

func TestSignRefusesUnsupportedKey(t *testing.T) {
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(context.Background(), unsigned, opaqueSigner{}, cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("got %v, want ErrUnsupportedKey", err)
	}
}

func TestSignRefusesMalformedCoRIM(t *testing.T) {
	if _, err := Sign(context.Background(), []byte{0xff, 0x00}, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName); !errors.Is(err, ErrMalformed) {
		t.Fatalf("got %v, want ErrMalformed", err)
	}
}

// TestSignRefusesEmptySignerName: corim's SetSigner returns nil for an empty
// name, so Sign must refuse it with an error rather than panic.
func TestSignRefusesEmptySignerName(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Sign panicked on an empty signer name: %v", r)
		}
	}()
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(context.Background(), unsigned, newKey(t, elliptic.P256()), cose.AlgorithmES256, ""); !errors.Is(err, ErrNoSignerName) {
		t.Fatalf("got %v, want ErrNoSignerName", err)
	}
}

// strictSigner is a KMS-like ECDSA signer: like AWS KMS it rejects nil
// SignerOpts, and like GCP KMS it signs with the hash the options name, so it
// refuses a hash that does not match the curve's COSE algorithm.
type strictSigner struct {
	key  *ecdsa.PrivateKey
	want crypto.Hash
}

func (s strictSigner) Public() crypto.PublicKey { return s.key.Public() }

func (s strictSigner) Sign(r io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if opts == nil {
		return nil, errors.New("strictSigner: nil SignerOpts")
	}
	if opts.HashFunc() != s.want {
		return nil, fmt.Errorf("strictSigner: hash %v, want %v", opts.HashFunc(), s.want)
	}
	return s.key.Sign(r, digest, opts)
}

// TestSignPassesTheAlgorithmHashToTheSigner: go-cose calls an opaque ECDSA
// signer with nil SignerOpts; Sign must name the COSE algorithm's hash.
func TestSignPassesTheAlgorithmHashToTheSigner(t *testing.T) {
	for _, tc := range []struct {
		name  string
		curve elliptic.Curve
		alg   cose.Algorithm
		hash  crypto.Hash
	}{
		{"P-256", elliptic.P256(), cose.AlgorithmES256, crypto.SHA256},
		{"P-384", elliptic.P384(), cose.AlgorithmES384, crypto.SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			signer := strictSigner{key: newKey(t, tc.curve), want: tc.hash}
			unsigned := buildUnsigned(t, buildCoMID(t), nil)
			signed, err := Sign(context.Background(), unsigned, signer, tc.alg, testSignerName)
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if _, err := VerifySigned(signed, VerifyOptions{PublicKey: signer.Public()}); err != nil {
				t.Fatalf("VerifySigned: %v", err)
			}
		})
	}
}

func TestSignHonoursCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	unsigned := buildUnsigned(t, buildCoMID(t), nil)
	if _, err := Sign(ctx, unsigned, newKey(t, elliptic.P256()), cose.AlgorithmES256, testSignerName); !errors.Is(err, context.Canceled) {
		t.Fatalf("got %v, want context.Canceled", err)
	}
}
