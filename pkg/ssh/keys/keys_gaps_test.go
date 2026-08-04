// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.

package keys

import (
	"context"
	"crypto"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/ssh/scope"
)

// TestGenerate_AllAlgorithms exercises generatePrivateKey and
// keyFromCryptoPrivate across every supported algorithm, covering the ECDSA
// P-384/P-521 and RSA branches that the round-trip tests otherwise skip.
func TestGenerate_AllAlgorithms(t *testing.T) {
	cases := []struct {
		algo Algorithm
		bits int
	}{
		{AlgorithmEd25519, 0},
		{AlgorithmRSA, minRSABits},
		{AlgorithmECDSAP256, 0},
		{AlgorithmECDSAP384, 0},
		{AlgorithmECDSAP521, 0},
	}
	for _, tc := range cases {
		t.Run(string(tc.algo), func(t *testing.T) {
			k, err := Generate(GenerateOptions{Algorithm: tc.algo, RSABits: tc.bits, Comment: "gap"})
			if err != nil {
				t.Fatalf("Generate(%s): %v", tc.algo, err)
			}
			defer k.Destroy()
			if k.PublicKey == nil {
				t.Fatalf("Generate(%s): nil public key", tc.algo)
			}
			if k.Algorithm != tc.algo {
				t.Fatalf("algorithm mismatch: got %s want %s", k.Algorithm, tc.algo)
			}
			if k.Fingerprint == "" {
				t.Fatalf("Generate(%s): empty fingerprint", tc.algo)
			}
			if k.Comment != "gap" {
				t.Fatalf("comment not preserved: %q", k.Comment)
			}
		})
	}
}

// TestGenerate_RSATooSmall covers the InvalidKeySizeError branch.
func TestGenerate_RSATooSmall(t *testing.T) {
	_, err := Generate(GenerateOptions{Algorithm: AlgorithmRSA, RSABits: 1024})
	var iks *InvalidKeySizeError
	if !errors.As(err, &iks) {
		t.Fatalf("expected InvalidKeySizeError, got %v", err)
	}
}

// TestGenerate_Unsupported covers the default branch of generatePrivateKey.
func TestGenerate_Unsupported(t *testing.T) {
	_, err := Generate(GenerateOptions{Algorithm: Algorithm("bogus-algo")})
	var ua *UnsupportedAlgorithmError
	if !errors.As(err, &ua) {
		t.Fatalf("expected UnsupportedAlgorithmError, got %v", err)
	}
}

// TestGenerateOnBackend_InvalidIdentity covers the backendKeyID error branch:
// an empty owner makes scope.BuildKeyID fail before the backend is touched.
func TestGenerateOnBackend_InvalidIdentity(t *testing.T) {
	p := newFakeProvider()
	_, err := GenerateOnBackend(context.Background(), p, "tpm2",
		GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "", "keyname")
	if err == nil {
		t.Fatalf("expected error for empty owner")
	}
	var mal *scope.KeyIDMalformedError
	if !errors.As(err, &mal) {
		t.Fatalf("expected KeyIDMalformedError, got %v", err)
	}
}

// nilSignerProvider returns (nil, nil) from GenerateKey to exercise the
// nil-signer guard in GenerateOnBackend.
type nilSignerProvider struct{}

func (nilSignerProvider) GenerateKey(context.Context, string, string, Algorithm, int) (crypto.Signer, error) {
	return nil, nil
}
func (nilSignerProvider) Signer(context.Context, string, string, Algorithm) (crypto.Signer, error) {
	return nil, nil
}

// TestGenerateOnBackend_NilSigner covers the guard for a backend that returns
// no signer without an error.
func TestGenerateOnBackend_NilSigner(t *testing.T) {
	_, err := GenerateOnBackend(context.Background(), nilSignerProvider{}, "tpm2",
		GenerateOptions{Algorithm: AlgorithmEd25519}, scope.User, "alice", "keyname")
	var km *KeyMaterialError
	if !errors.As(err, &km) {
		t.Fatalf("expected KeyMaterialError for nil signer, got %v", err)
	}
}
