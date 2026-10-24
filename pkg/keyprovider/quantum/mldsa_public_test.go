package quantum

import (
	"crypto/mldsa"
	"errors"
	"testing"
)

func TestMLDSAPublicKeyMLDSA(t *testing.T) {
	for name, params := range mldsaParameters {
		t.Run(name, func(t *testing.T) {
			sk, err := mldsa.GenerateKey(params)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			pk := &MLDSAPublicKey{Algorithm: name, Key: sk.PublicKey().Bytes()}
			got, err := pk.MLDSA()
			if err != nil {
				t.Fatalf("MLDSA: %v", err)
			}
			if !got.Equal(sk.PublicKey()) {
				t.Fatal("MLDSA returned a different key")
			}
		})
	}
}

func TestMLDSAPublicKeyMLDSARefusesInvalidKeys(t *testing.T) {
	sk, err := mldsa.GenerateKey(mldsa.MLDSA44())
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	cases := map[string]*MLDSAPublicKey{
		"nil":            nil,
		"ML-KEM name":    {Algorithm: "ML-KEM-768", Key: sk.PublicKey().Bytes()},
		"wrong set size": {Algorithm: "ML-DSA-65", Key: sk.PublicKey().Bytes()},
		"empty encoding": {Algorithm: "ML-DSA-44"},
	}
	for name, pk := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := pk.MLDSA(); err == nil {
				t.Fatal("MLDSA accepted an invalid key")
			}
		})
	}
	if _, err := (&MLDSAPublicKey{Algorithm: "ML-KEM-768"}).MLDSA(); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("err = %v, want ErrUnsupportedAlgorithm", err)
	}
}
