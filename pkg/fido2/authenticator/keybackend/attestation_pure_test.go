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

package keybackend

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

// TestCoseAlgorithmForKey covers every curve the attestation path accepts
// and the two ways a key can be refused: an unsupported curve and a
// non-ECDSA key type.
func TestCoseAlgorithmForKey(t *testing.T) {
	tests := []struct {
		name  string
		curve elliptic.Curve
		want  int
	}{
		{"P-256", elliptic.P256(), COSEAlgES256},
		{"P-384", elliptic.P384(), COSEAlgES384},
		{"P-521", elliptic.P521(), COSEAlgES512},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			priv, err := ecdsa.GenerateKey(tc.curve, rand.Reader)
			if err != nil {
				t.Fatalf("ecdsa.GenerateKey() error = %v", err)
			}
			got, err := coseAlgorithmForKey(&priv.PublicKey)
			if err != nil {
				t.Fatalf("coseAlgorithmForKey() error = %v", err)
			}
			if got != tc.want {
				t.Errorf("coseAlgorithmForKey() = %d, want %d", got, tc.want)
			}
		})
	}

	t.Run("unsupported curve", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		if _, err := coseAlgorithmForKey(&priv.PublicKey); !errors.Is(err, ErrUnsupportedAttestationKey) {
			t.Fatalf("coseAlgorithmForKey(P-224) error = %v, want ErrUnsupportedAttestationKey", err)
		}
	})

	t.Run("non-ecdsa key", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		if _, err := coseAlgorithmForKey(&rsaKey.PublicKey); !errors.Is(err, ErrUnsupportedAttestationKey) {
			t.Fatalf("coseAlgorithmForKey(RSA) error = %v, want ErrUnsupportedAttestationKey", err)
		}
	})
}

// TestHashForCOSEAlgorithm covers the three COSE ECDSA algorithms this
// package attests with and the refusal of anything else, including the
// EdDSA/RSA algorithm identifiers this function is not paired with a hash
// for.
func TestHashForCOSEAlgorithm(t *testing.T) {
	tests := []struct {
		algorithm int
		wantBits  int
	}{
		{COSEAlgES256, 256},
		{COSEAlgES384, 384},
		{COSEAlgES512, 512},
	}
	for _, tc := range tests {
		got, err := hashForCOSEAlgorithm(tc.algorithm)
		if err != nil {
			t.Fatalf("hashForCOSEAlgorithm(%d) error = %v", tc.algorithm, err)
		}
		if got.Size()*8 != tc.wantBits {
			t.Errorf("hashForCOSEAlgorithm(%d) = %v (%d bits), want %d bits", tc.algorithm, got, got.Size()*8, tc.wantBits)
		}
	}

	if _, err := hashForCOSEAlgorithm(COSEAlgEdDSA); !errors.Is(err, ErrUnsupportedAttestationKey) {
		t.Fatalf("hashForCOSEAlgorithm(EdDSA) error = %v, want ErrUnsupportedAttestationKey", err)
	}
}

// TestEncodeCOSERSAKey covers the TPM IAK RSA public key encoding path:
// the only place in this package an RSA key reaches COSE. The CBOR output
// is decoded back rather than compared as opaque bytes, so the assertion is
// on the field values the RFC 8230 RSA key type requires (kty, alg, n, e),
// not on encoder byte-ordering.
func TestEncodeCOSERSAKey(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}

	encoded, err := encodeCOSERSAKey(&priv.PublicKey, COSEAlgRS256)
	if err != nil {
		t.Fatalf("encodeCOSERSAKey() error = %v", err)
	}
	if len(encoded) == 0 {
		t.Fatal("expected non-empty CBOR output")
	}

	var decoded map[int]interface{}
	if err := cbor.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("cbor.Unmarshal() error = %v", err)
	}

	kty, ok := decoded[1].(uint64)
	if !ok || int(kty) != COSEKeyTypeRSA {
		t.Errorf("kty = %v, want %d (RSA)", decoded[1], COSEKeyTypeRSA)
	}
	alg, ok := decoded[3].(int64)
	if !ok || int(alg) != COSEAlgRS256 {
		t.Errorf("alg = %v, want %d", decoded[3], COSEAlgRS256)
	}
	n, ok := decoded[-1].([]byte)
	if !ok || len(n) == 0 {
		t.Error("expected a non-empty modulus (n)")
	}
	e, ok := decoded[-2].([]byte)
	if !ok || len(e) == 0 {
		t.Error("expected a non-empty public exponent (e)")
	}
}

// TestVerifyAttestationSignature covers all three outcomes of the
// self-verification PackedAttestationStatement performs before it will hand
// back a signature: a leaf key type it cannot check, a signature that does
// not verify, and one that does. Only the last of the three is reachable
// through PackedAttestationStatement itself, because that path already
// requires the leaf and signer to carry the same (necessarily ECDSA) public
// key, so the other two are exercised directly here.
func TestVerifyAttestationSignature(t *testing.T) {
	t.Run("rejects a leaf key it cannot verify against", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey() error = %v", err)
		}
		leaf := &x509.Certificate{PublicKey: &rsaKey.PublicKey}

		err = verifyAttestationSignature(leaf, crypto.SHA256, []byte("data"), []byte("sig"))
		require.ErrorIs(t, err, ErrUnsupportedAttestationKey)
	})

	t.Run("rejects a signature that does not verify", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		leaf := &x509.Certificate{PublicKey: &priv.PublicKey}

		err = verifyAttestationSignature(leaf, crypto.SHA256, []byte("data"), []byte("not-a-valid-signature"))
		require.ErrorIs(t, err, ErrAttestationSignatureInvalid)
	})

	t.Run("accepts a genuine signature", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey() error = %v", err)
		}
		leaf := &x509.Certificate{PublicKey: &priv.PublicKey}

		data := []byte("attested-data")
		digest := sha256.Sum256(data)
		sig, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
		if err != nil {
			t.Fatalf("ecdsa.SignASN1() error = %v", err)
		}

		require.NoError(t, verifyAttestationSignature(leaf, crypto.SHA256, data, sig))
	})
}

// TestPublicKeysEqual covers the two outcomes an Equal-implementing key can
// produce and the refusal of a key type that implements no Equal method at
// all -- crypto.PublicKey carries no such constraint, so a caller can hand
// back anything.
func TestPublicKeysEqual(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}

	if !publicKeysEqual(&priv.PublicKey, &priv.PublicKey) {
		t.Error("publicKeysEqual() = false, want true for the same key")
	}
	if publicKeysEqual(&priv.PublicKey, &other.PublicKey) {
		t.Error("publicKeysEqual() = true, want false for different keys")
	}
	if publicKeysEqual("not-a-key", &priv.PublicKey) {
		t.Error("publicKeysEqual() = true, want false for a type with no Equal method")
	}
}
