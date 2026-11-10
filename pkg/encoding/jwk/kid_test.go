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

package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"
)

// Fixed DER SubjectPublicKeyInfo prefixes (RFC 5480 §2 for P-256 with an
// uncompressed point, RFC 8410 §4 for Ed25519), so the expected kid is
// computed without x509.MarshalPKIXPublicKey.
const (
	p256SPKIPrefix    = "3059301306072a8648ce3d020106082a8648ce3d030107034200"
	ed25519SPKIPrefix = "302a300506032b6570032100"
)

func expectedSPKIKeyID(t *testing.T, prefixHex string, keyBytes []byte) string {
	t.Helper()
	prefix, err := hex.DecodeString(prefixHex)
	if err != nil {
		t.Fatalf("decode prefix: %v", err)
	}
	sum := sha256.Sum256(append(prefix, keyBytes...))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func TestSPKIKeyID(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate P-256 key: %v", err)
	}
	ecdhPub, err := ecKey.PublicKey.ECDH()
	if err != nil {
		t.Fatalf("P-256 point: %v", err)
	}
	edPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}

	tests := []struct {
		name string
		pub  crypto.PublicKey
		want string
	}{
		{"P-256", &ecKey.PublicKey, expectedSPKIKeyID(t, p256SPKIPrefix, ecdhPub.Bytes())},
		{"Ed25519", edPub, expectedSPKIKeyID(t, ed25519SPKIPrefix, edPub)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := SPKIKeyID(tc.pub)
			if err != nil {
				t.Fatalf("SPKIKeyID: %v", err)
			}
			if got != tc.want {
				t.Fatalf("SPKIKeyID = %q, want %q", got, tc.want)
			}
			// 32 SHA-256 bytes, unpadded base64url (RFC 7515 §2).
			if len(got) != 43 {
				t.Fatalf("len(kid) = %d, want 43", len(got))
			}
		})
	}
}

func TestSPKIKeyIDDistinctKeys(t *testing.T) {
	a, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	b, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	kidA, err := SPKIKeyID(&a.PublicKey)
	if err != nil {
		t.Fatalf("SPKIKeyID(a): %v", err)
	}
	kidB, err := SPKIKeyID(&b.PublicKey)
	if err != nil {
		t.Fatalf("SPKIKeyID(b): %v", err)
	}
	if kidA == kidB {
		t.Fatal("distinct keys derived the same kid")
	}
}

func TestSPKIKeyIDErrors(t *testing.T) {
	tests := []struct {
		name     string
		pub      crypto.PublicKey
		wantType string
	}{
		{"nil key", nil, "<nil>"},
		{"unsupported type", struct{}{}, "struct {}"},
		{"byte slice", []byte{0x04}, "[]uint8"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kid, err := SPKIKeyID(tc.pub)
			if err == nil {
				t.Fatalf("SPKIKeyID = %q, want error", kid)
			}
			var kidErr *KeyIDError
			if !errors.As(err, &kidErr) {
				t.Fatalf("error %T is not *KeyIDError", err)
			}
			if kidErr.KeyType != tc.wantType {
				t.Fatalf("KeyType = %q, want %q", kidErr.KeyType, tc.wantType)
			}
			if kidErr.Unwrap() == nil {
				t.Fatal("KeyIDError wraps no cause")
			}
			if kid != "" {
				t.Fatalf("kid = %q on error, want empty", kid)
			}
		})
	}
}
