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
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
)

// Fixed compact JWEs (enc A128GCM, plaintext "refused") whose "alg" is outside
// Decrypt's key algorithm allow-list. They are constants so the refusal is
// tested without encrypting under RSA1_5 or PBES2, which GODEBUG=fips140=only
// refuses before the parser is ever reached.
const (
	rsa15JWE = "eyJhbGciOiJSU0ExXzUiLCJlbmMiOiJBMTI4R0NNIn0." +
		"P4uiPnEDDuGTa7cVcNkrqyHfiGo3guptzNnaP2yDXGphLULWMXlZxvU_wrwFQZOR_yYf33Q1irdqR6IgfuinCgDG9lBjWBwdq7JrinT9tQIZDcLtdxXRBKU-z2mYiRMQz9AUKTYSFOGkkj4n6Stjx5l30DCju4ahR78hHqB5bSNSk8fJbTz2WAAoQUsw_zP1vO3En5aDqONMvNmfdezWLTP-i1MKavZBn1GbF8YaB3y3DLpe_3qJShG6kBh1A0OCvDJtFrJp1KvZsMUGK8b5CQrEw7NSlsKMVB2BPvXMTxMqjuRfcG6bfIfLDUAkeLQgIlV1JtpxFmFYpg1I0Am3WQ." +
		"4n9e5-v9TWI6B6kB.i0vB18ykgg.1YxbvJtTIAOvkWktJGdqWw"
	pbes2JWE = "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJlbmMiOiJBMTI4R0NNIiwicDJjIjoxMDAwLCJwMnMiOiJ4NkE0Wi10Tlh4TVVkZGpnTUZLSEpBIn0." +
		"z1FxvbbL5jYss6Y9xD4PEfPi1gLsoTlg.PEyIZc4FFWP7jL4G.T96V4VqAug.vI_W_4-M5UPJQResQfmrGQ"
)

// TestDecrypt_RefusesAKeyAlgorithmOutsideTheAllowList proves that Decrypt's
// parse step refuses a well-formed JWE whose "alg" is not in its key
// algorithm allow-list, before any key is used.
func TestDecrypt_RefusesAKeyAlgorithmOutsideTheAllowList(t *testing.T) {
	password := []byte("correct horse battery staple")

	cases := []struct {
		name string
		jwe  string
	}{
		{"RSA1_5", rsa15JWE},
		{"PBES2-HS256+A128KW", pbes2JWE},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewDecrypter().Decrypt(tc.jwe, password)
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
		compact, ok := requireJWE(t, func() (string, error) {
			enc, err := jose.NewEncrypter(jose.A128GCM, jose.Recipient{Algorithm: jose.A128KW, Key: kek}, nil)
			if err != nil {
				return "", err
			}
			obj, err := enc.Encrypt([]byte("refused"))
			if err != nil {
				return "", err
			}
			return obj.CompactSerialize()
		})
		if !ok {
			return
		}
		got, err := NewDecrypter().Decrypt(compact, kek)
		if err != nil {
			t.Fatalf("Decrypt refused an allowed alg: %v", err)
		}
		if string(got) != "refused" {
			t.Fatalf("Decrypt returned %q", got)
		}
	})
}
