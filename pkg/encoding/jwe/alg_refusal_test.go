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

package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// compactJWE encrypts plaintext with go-jose directly, so the test can use a
// key algorithm that NewEncrypter would never produce.
func compactJWE(t *testing.T, alg jose.KeyAlgorithm, key interface{}) string {
	t.Helper()
	enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: alg, Key: key}, nil)
	if err != nil {
		t.Fatalf("NewEncrypter(%s): %v", alg, err)
	}
	obj, err := enc.Encrypt([]byte("refused"))
	if err != nil {
		t.Fatalf("Encrypt(%s): %v", alg, err)
	}
	s, err := obj.CompactSerialize()
	if err != nil {
		t.Fatalf("CompactSerialize(%s): %v", alg, err)
	}
	return s
}

// TestDecrypt_RefusesAKeyAlgorithmOutsideTheAllowList proves that Decrypt's
// parse step refuses a well-formed JWE whose "alg" is not in its key
// algorithm allow-list, even when the caller holds the right key.
func TestDecrypt_RefusesAKeyAlgorithmOutsideTheAllowList(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	password := []byte("correct horse battery staple")

	cases := []struct {
		name    string
		jwe     string
		decrypt interface{}
	}{
		{"RSA1_5", compactJWE(t, jose.RSA1_5, &rsaKey.PublicKey), rsaKey},
		{"PBES2-HS256+A128KW", compactJWE(t, jose.PBES2_HS256_A128KW, password), password},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDecrypter().Decrypt(tc.jwe, tc.decrypt)
			if err == nil {
				t.Fatalf("Decrypt accepted a JWE with alg %s", tc.name)
			}
			if !strings.Contains(err.Error(), "failed to parse JWE") {
				t.Fatalf("Decrypt refused alg %s at the wrong step: %v", tc.name, err)
			}
		})
	}

	t.Run("A128KW is accepted", func(t *testing.T) {
		kek := make([]byte, 16)
		if _, err := rand.Read(kek); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
		got, err := NewDecrypter().Decrypt(compactJWE(t, jose.A128KW, kek), kek)
		if err != nil {
			t.Fatalf("Decrypt refused an allowed alg: %v", err)
		}
		if string(got) != "refused" {
			t.Fatalf("Decrypt returned %q", got)
		}
	})
}
