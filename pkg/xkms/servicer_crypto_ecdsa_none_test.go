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

package xkms

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// TestSign_ECDSAUnderNONE_SignsTheSuppliedDigest is PKCS#11 CKM_ECDSA: the
// caller hashes, names no hash, and the service signs the digest as given.
// Go 1.27's ecdsa.PrivateKey.Sign refuses crypto.Hash(0), so the service has
// to name the hash the digest length implies.
func TestSign_ECDSAUnderNONE_SignsTheSuppliedDigest(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(&ServiceConfig{Backends: map[string]Backend{"software": newRealSoftwareBackend(t)}})
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		curve  string
		digest []byte
	}{
		{curve: "P-256", digest: sum256("charon auth")},
		{curve: "P-384", digest: sum384("charon auth")},
	}
	for _, tc := range cases {
		t.Run(tc.curve, func(t *testing.T) {
			keyID := "ike-" + tc.curve
			gen, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
				KeyID: keyID, Backend: "software", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: tc.curve,
			})
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			resp, err := svc.Sign(ctx, &transport.SignRequest{
				Backend: "software", KeyID: keyID, Data: tc.digest, Hash: "NONE", DataIsDigest: true,
			})
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			block, _ := pem.Decode([]byte(gen.PublicKeyPEM))
			pub, err := x509.ParsePKIXPublicKey(block.Bytes)
			if err != nil {
				t.Fatal(err)
			}
			if !ecdsa.VerifyASN1(pub.(*ecdsa.PublicKey), tc.digest, resp.Signature) {
				t.Fatal("signature does not verify over the supplied digest")
			}
		})
	}
}

func TestSign_ECDSAUnderNONE_RefusesUnnamedDigestLength(t *testing.T) {
	ctx := context.Background()
	svc, err := NewService(&ServiceConfig{Backends: map[string]Backend{"software": newRealSoftwareBackend(t)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := svc.GenerateKey(ctx, &transport.GenerateKeyRequest{
		KeyID: "ike", Backend: "software", KeyType: "ECDSA", Algorithm: "ECDSA", Curve: "P-256",
	}); err != nil {
		t.Fatal(err)
	}
	// 20 bytes is a SHA-1 digest, deliberately not inferred.
	_, err = svc.Sign(ctx, &transport.SignRequest{
		Backend: "software", KeyID: "ike", Data: make([]byte, 20), Hash: "NONE", DataIsDigest: true,
	})
	if !errors.Is(err, ErrInvalidHashFunction) {
		t.Fatalf("Sign error = %v, want ErrInvalidHashFunction", err)
	}
}

func sum256(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func sum384(s string) []byte {
	sum := sha512.Sum384([]byte(s))
	return sum[:]
}
