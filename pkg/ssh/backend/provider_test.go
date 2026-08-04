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

package backend

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// newSoftwareResolver builds a Resolver backed by an in-memory software
// KeyProvider so the test exercises the real generate/sign path without
// hardware or disk.
func newSoftwareResolver(t *testing.T) Resolver {
	t.Helper()
	kp, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	if err != nil {
		t.Fatalf("software.NewBackend: %v", err)
	}
	return ResolverFunc(func(_ context.Context, backendID string) (types.KeyProvider, error) {
		if backendID != "software" {
			return nil, errors.New("unknown backend")
		}
		return kp, nil
	})
}

func TestProvider_GenerateAndSign(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Cover every algorithm, with explicit attention to RSA-2048 and
	// ECDSA-P256 — the cross-backend defaults that TPM 2.0, SoftHSM2, and the
	// software backend all support. For RSA we exercise the rsa-sha2-256
	// AlgorithmSigner path (modern servers reject the legacy SHA-1 ssh-rsa),
	// proving the backend's crypto.Signer honors the hashed-digest scheme.
	cases := []struct {
		algo       keys.Algorithm
		bits       int
		rsaSHA2    string // non-empty ⇒ sign via SignWithAlgorithm and assert the format
		wantSigAlg string // expected ssh.Signature.Format
	}{
		{keys.AlgorithmEd25519, 0, "", ssh.KeyAlgoED25519},
		{keys.AlgorithmECDSAP256, 0, "", ssh.KeyAlgoECDSA256},
		{keys.AlgorithmECDSAP384, 0, "", ssh.KeyAlgoECDSA384},
		{keys.AlgorithmRSA, 2048, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA256},
		{keys.AlgorithmRSA, 2048, ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA512},
	}

	for _, tc := range cases {
		name := tc.algo.String()
		if tc.rsaSHA2 != "" {
			name += "-" + tc.rsaSHA2
		}
		t.Run(name, func(t *testing.T) {
			keyID := "ssh-user-alice-" + name
			signer, err := p.GenerateKey(ctx, "software", keyID, tc.algo, tc.bits)
			if err != nil {
				t.Fatalf("GenerateKey: %v", err)
			}
			sshPub, err := ssh.NewPublicKey(signer.Public())
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}

			// Resolve the signer again (simulating a later Sign) and verify.
			again, err := p.Signer(ctx, "software", keyID, tc.algo)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			sshSigner, err := ssh.NewSignerFromSigner(again)
			if err != nil {
				t.Fatalf("NewSignerFromSigner: %v", err)
			}

			msg := []byte("verify me")
			var sig *ssh.Signature
			if tc.rsaSHA2 != "" {
				as, ok := sshSigner.(ssh.AlgorithmSigner)
				if !ok {
					t.Fatalf("%s signer is not an ssh.AlgorithmSigner", tc.algo)
				}
				sig, err = as.SignWithAlgorithm(rand.Reader, msg, tc.rsaSHA2)
			} else {
				sig, err = sshSigner.Sign(rand.Reader, msg)
			}
			if err != nil {
				t.Fatalf("Sign: %v", err)
			}
			if sig.Format != tc.wantSigAlg {
				t.Fatalf("expected signature format %q, got %q", tc.wantSigAlg, sig.Format)
			}
			if err := sshPub.Verify(msg, sig); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

func TestProvider_DeleteKey(t *testing.T) {
	ctx := context.Background()
	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	keyID := "ssh-user-bob-del"
	if _, err := p.GenerateKey(ctx, "software", keyID, keys.AlgorithmEd25519, 0); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if err := p.DeleteKey(ctx, "software", keyID, keys.AlgorithmEd25519); err != nil {
		t.Fatalf("DeleteKey: %v", err)
	}
	// After deletion the signer should no longer resolve.
	if _, err := p.Signer(ctx, "software", keyID, keys.AlgorithmEd25519); err == nil {
		t.Fatal("expected error resolving signer for deleted key")
	}
}

func TestProvider_Errors(t *testing.T) {
	ctx := context.Background()

	if _, err := New(nil); err == nil {
		t.Fatal("expected error for nil resolver")
	}

	p, err := New(newSoftwareResolver(t))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Unknown backend (resolver returns error).
	if _, err := p.GenerateKey(ctx, "tpm2", "k", keys.AlgorithmEd25519, 0); err == nil {
		t.Fatal("expected error for unknown backend")
	}

	// Unsupported algorithm.
	if _, err := p.GenerateKey(ctx, "software", "k", keys.Algorithm("bogus"), 0); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}

	// Signer for a non-existent key.
	if _, err := p.Signer(ctx, "software", "does-not-exist", keys.AlgorithmEd25519); err == nil {
		t.Fatal("expected error resolving signer for missing key")
	}
}
