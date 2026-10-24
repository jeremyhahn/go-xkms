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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
)

// convertibleMLDSA stands in for a key provider's ML-DSA public key that
// converts to a crypto/mldsa key.
type convertibleMLDSA struct {
	key *mldsa.PublicKey
	err error
}

func (c convertibleMLDSA) MLDSA() (*mldsa.PublicKey, error) { return c.key, c.err }

func TestMLDSAAcceptsConvertibleKeys(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA65())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := NewSigner("log.example", &fakeSigner{pub: convertibleMLDSA{key: sk.PublicKey()}})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	if s.Algorithm() != AlgorithmMLDSA65 {
		t.Fatalf("algorithm = %s", s.Algorithm())
	}
	broken := &fakeSigner{pub: convertibleMLDSA{err: errors.New("bad encoding")}}
	if _, err := NewSigner("log.example", broken); !errors.Is(err, ErrUnsupportedKey) {
		t.Fatalf("broken convertible: err = %v, want ErrUnsupportedKey", err)
	}
}

func TestBuiltinEncodersRefuseForeignKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ml44, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := map[string]struct {
		id  string
		pub crypto.PublicKey
	}{
		"Ed25519 of ECDSA":       {AlgorithmEd25519, &ecKey.PublicKey},
		"Ed25519 short key":      {AlgorithmEd25519, ed25519.PublicKey{1, 2, 3}},
		"witness ECDSA of P-224": {AlgorithmECDSA, &mustECDSA(t, elliptic.P224()).PublicKey},
		"witness ECDSA nil key":  {AlgorithmECDSA, (*ecdsa.PublicKey)(nil)},
		"P-384 SHA-384 of P-256": {AlgorithmECDSAP384SHA384, &ecKey.PublicKey},
		"RSA of ECDSA":           {AlgorithmRSAPSSSHA256, &ecKey.PublicKey},
		"RSA 1024-bit":           {AlgorithmRSAPKCS1SHA256, &small.PublicKey},
		"RSA nil key":            {AlgorithmRSAPKCS1SHA256, (*rsa.PublicKey)(nil)},
		"ML-DSA-65 of ML-DSA-44": {AlgorithmMLDSA65, ml44.PublicKey()},
		"ML-DSA of ECDSA":        {AlgorithmMLDSA44, &ecKey.PublicKey},
		"ML-DSA nil key":         {AlgorithmMLDSA44, (*mldsa.PublicKey)(nil)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			alg, err := lookupID(tc.id)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if _, err := alg.EncodePublicKey(tc.pub); err == nil {
				t.Fatal("encoder accepted a foreign key")
			}
		})
	}
}

func TestBuiltinDecodersRefuseForeignMaterial(t *testing.T) {
	spki := func(pub crypto.PublicKey) []byte {
		der, err := x509.MarshalPKIXPublicKey(pub)
		if err != nil {
			t.Fatalf("MarshalPKIXPublicKey: %v", err)
		}
		return der
	}
	small, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := map[string]struct {
		id       string
		material []byte
	}{
		"witness ECDSA garbage":  {AlgorithmECDSA, []byte{1, 2, 3}},
		"witness ECDSA of RSA":   {AlgorithmECDSA, spki(&rsaTestKey().PublicKey)},
		"witness ECDSA of P-224": {AlgorithmECDSA, spki(&mustECDSA(t, elliptic.P224()).PublicKey)},
		"P-521 SHA-512 of P-256": {AlgorithmECDSAP521SHA512, spki(&mustECDSA(t, elliptic.P256()).PublicKey)},
		"RSA garbage":            {AlgorithmRSAPSSSHA512, []byte{1, 2, 3}},
		"RSA of ECDSA":           {AlgorithmRSAPKCS1SHA384, spki(&mustECDSA(t, elliptic.P256()).PublicKey)},
		"RSA 1024-bit":           {AlgorithmRSAPKCS1SHA512, spki(&small.PublicKey)},
		"ML-DSA-87 wrong size":   {AlgorithmMLDSA87, make([]byte, mldsa.MLDSA65PublicKeySize)},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			alg, err := lookupID(tc.id)
			if err != nil {
				t.Fatalf("lookup: %v", err)
			}
			if _, err := alg.DecodePublicKey(tc.material); !errors.Is(err, ErrMalformedVerifierKey) {
				t.Fatalf("err = %v, want ErrMalformedVerifierKey", err)
			}
		})
	}
}

func TestBuiltinVerifiersRefuseForeignKeys(t *testing.T) {
	ecKey := mustECDSA(t, elliptic.P256())
	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	for _, alg := range algorithms.Load().byID {
		var foreign crypto.PublicKey = &ecKey.PublicKey
		if _, err := alg.EncodePublicKey(foreign); err == nil {
			foreign = edKey.Public()
		}
		if alg.Verify(foreign, []byte("text\n"), make([]byte, 64)) {
			t.Fatalf("%s verified under a foreign key", alg.ID)
		}
	}
}

func TestDigest(t *testing.T) {
	text := []byte("text\n")
	if got := digest(0, text); string(got) != string(text) {
		t.Fatalf("digest(0) = %q", got)
	}
	if got := digest(crypto.SHA384, text); len(got) != crypto.SHA384.Size() {
		t.Fatalf("digest(SHA-384) is %d bytes", len(got))
	}
}

func mustECDSA(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return key
}
