// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
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

package signing

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"
)

// signPKCS1v15 hashes message with hash and signs the digest with key.
func signPKCS1v15(t *testing.T, key *rsa.PrivateKey, hash crypto.Hash, message []byte) ([]byte, []byte) {
	t.Helper()
	hasher := hash.New()
	if _, err := hasher.Write(message); err != nil {
		t.Fatalf("hash: %v", err)
	}
	digest := hasher.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, hash, digest)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return digest, signature
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return key
}

func TestVerify(t *testing.T) {
	key := newRSAKey(t)
	message := []byte("host manifest")

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run("Valid"+hash.String(), func(t *testing.T) {
			digest, signature := signPKCS1v15(t, key, hash, message)
			if err := Verify(&key.PublicKey, hash, digest, signature); err != nil {
				t.Fatalf("Verify() = %v, want nil", err)
			}
		})
	}

	t.Run("Invalid", func(t *testing.T) {
		digest, _ := signPKCS1v15(t, key, crypto.SHA256, message)
		other := newRSAKey(t)
		err := Verify(&other.PublicKey, crypto.SHA256, digest, []byte("invalid"))
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("Verify() = %v, want ErrVerificationFailed", err)
		}
	})

	t.Run("WrongKey", func(t *testing.T) {
		digest, signature := signPKCS1v15(t, key, crypto.SHA256, message)
		other := newRSAKey(t)
		err := Verify(&other.PublicKey, crypto.SHA256, digest, signature)
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("Verify() = %v, want ErrVerificationFailed", err)
		}
	})

	t.Run("HashMismatch", func(t *testing.T) {
		digest, signature := signPKCS1v15(t, key, crypto.SHA256, message)
		err := Verify(&key.PublicKey, crypto.SHA384, digest, signature)
		if !errors.Is(err, ErrVerificationFailed) {
			t.Fatalf("Verify() = %v, want ErrVerificationFailed", err)
		}
	})

	t.Run("NilPublicKey", func(t *testing.T) {
		digest, signature := signPKCS1v15(t, key, crypto.SHA256, message)
		if err := Verify(nil, crypto.SHA256, digest, signature); !errors.Is(err, ErrPublicKeyRequired) {
			t.Fatalf("Verify() = %v, want ErrPublicKeyRequired", err)
		}
		var typedNil *rsa.PublicKey
		if err := Verify(typedNil, crypto.SHA256, digest, signature); !errors.Is(err, ErrPublicKeyRequired) {
			t.Fatalf("Verify(typed nil) = %v, want ErrPublicKeyRequired", err)
		}
	})

	t.Run("EmptySignature", func(t *testing.T) {
		digest, _ := signPKCS1v15(t, key, crypto.SHA256, message)
		if err := Verify(&key.PublicKey, crypto.SHA256, digest, nil); !errors.Is(err, ErrSignatureRequired) {
			t.Fatalf("Verify() = %v, want ErrSignatureRequired", err)
		}
	})
}

func TestVerifyRefusesNonRSAKeys(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ECDSA key: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	digest := make([]byte, 32)

	for name, pub := range map[string]crypto.PublicKey{
		"ECDSA":   &ecKey.PublicKey,
		"Ed25519": edPub,
	} {
		t.Run(name, func(t *testing.T) {
			err := Verify(pub, crypto.SHA256, digest, []byte("signature"))
			if !errors.Is(err, ErrUnsupportedKeyType) {
				t.Fatalf("Verify() = %v, want ErrUnsupportedKeyType", err)
			}
		})
	}
}

func TestVerifyRefusesOtherHashes(t *testing.T) {
	key := newRSAKey(t)
	message := []byte("host manifest")

	for _, hash := range []crypto.Hash{crypto.SHA1, crypto.SHA224, crypto.SHA3_256, crypto.Hash(0)} {
		t.Run(hash.String(), func(t *testing.T) {
			digest, signature := signPKCS1v15(t, key, crypto.SHA256, message)
			err := Verify(&key.PublicKey, hash, digest, signature)
			if !errors.Is(err, ErrInvalidHashFunction) {
				t.Fatalf("Verify() = %v, want ErrInvalidHashFunction", err)
			}
		})
	}
}
