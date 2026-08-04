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

//go:build integration

// Package sshbackend confirms that SSH key generation, signer resolution, and
// SSH signing/verification work end-to-end on EVERY crypto backend the platform
// supports — software, TPM 2.0 (simulator), PKCS#11 (SoftHSM2), and the cloud
// KMS providers (AWS via Floci, GCP/Azure via self-consistent mocks, and a
// real-cloud opt-in lane).
//
// Each backend lane builds a real types.KeyProvider, wraps it in a
// pkg/ssh/backend.Resolver, and drives the same generate → derive public key →
// resolve Signer → ssh.NewSignerFromSigner → sign → verify matrix. This is the
// exact production path the GUI/CLI use (SSHService → embedded client → backend
// provider), so a green lane proves an SSH key really works on that backend.
package sshbackend

import (
	"context"
	"crypto/rand"
	"errors"
	"testing"

	"golang.org/x/crypto/ssh"

	sshbackend "github.com/jeremyhahn/go-xkms/pkg/ssh/backend"
	"github.com/jeremyhahn/go-xkms/pkg/ssh/keys"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// errUnknownBackend is returned by a lane resolver for any backend ID other
// than the one it was built for.
var errUnknownBackend = errors.New("unknown backend")

// algoCase is one algorithm to exercise in the matrix.
type algoCase struct {
	algo       keys.Algorithm
	bits       int    // RSA bit size (0 for non-RSA)
	rsaSHA2    string // non-empty ⇒ sign via SignWithAlgorithm with this scheme
	wantSigAlg string // expected ssh.Signature.Format ("" ⇒ skip the assertion)
}

// cloudAlgos is the cross-cloud-safe SSH algorithm set: ECDSA-P256 is the only
// algorithm AWS, GCP, and Azure all generate AND sign in an SSH-valid way
// (AWS RSA is PSS-only → invalid for SSH; ed25519 is unsupported everywhere).
var cloudAlgos = []algoCase{
	{keys.AlgorithmECDSAP256, 0, "", ssh.KeyAlgoECDSA256},
}

// hardwareAlgos covers the cross-backend defaults TPM 2.0 and SoftHSM2 both
// support: ECDSA-P256 and RSA-2048 (rsa-sha2-256, the modern SSH scheme).
var hardwareAlgos = []algoCase{
	{keys.AlgorithmECDSAP256, 0, "", ssh.KeyAlgoECDSA256},
	{keys.AlgorithmRSA, 2048, ssh.KeyAlgoRSASHA256, ssh.KeyAlgoRSASHA256},
}

// resolverFor builds a single-backend Resolver that answers only for id.
func resolverFor(id string, kp types.KeyProvider) sshbackend.Resolver {
	return sshbackend.ResolverFunc(func(_ context.Context, backendID string) (types.KeyProvider, error) {
		if backendID != id {
			return nil, errUnknownBackend
		}
		return kp, nil
	})
}

// runMatrix runs the full SSH lifecycle for each algorithm on the backend
// behind resolver. When verify is false (mock backends that cannot produce
// verifiable signatures) the signature is still produced but not checked.
func runMatrix(t *testing.T, resolver sshbackend.Resolver, backendID string, cases []algoCase, verify bool) {
	t.Helper()
	ctx := context.Background()
	p, err := sshbackend.New(resolver)
	if err != nil {
		t.Fatalf("backend.New: %v", err)
	}
	for _, tc := range cases {
		name := tc.algo.String()
		if tc.rsaSHA2 != "" {
			name += "-" + tc.rsaSHA2
		}
		t.Run(name, func(t *testing.T) {
			keyID := "ssh-user-test-" + backendID + "-" + name

			signer, err := p.GenerateKey(ctx, backendID, keyID, tc.algo, tc.bits)
			if err != nil {
				t.Fatalf("GenerateKey(%s/%s): %v", backendID, tc.algo, err)
			}
			sshPub, err := ssh.NewPublicKey(signer.Public())
			if err != nil {
				t.Fatalf("NewPublicKey: %v", err)
			}

			// Re-resolve the signer (simulating a later sign) and sign.
			again, err := p.Signer(ctx, backendID, keyID, tc.algo)
			if err != nil {
				t.Fatalf("Signer: %v", err)
			}
			sshSigner, err := ssh.NewSignerFromSigner(again)
			if err != nil {
				t.Fatalf("NewSignerFromSigner: %v", err)
			}

			msg := []byte("xkms ssh backend matrix")
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
			if tc.wantSigAlg != "" && sig.Format != tc.wantSigAlg {
				t.Fatalf("signature format = %q, want %q", sig.Format, tc.wantSigAlg)
			}
			if verify {
				if err := sshPub.Verify(msg, sig); err != nil {
					t.Fatalf("verify: %v", err)
				}
			}
		})
	}
}

// assertRejects asserts that generating algo on backendID fails — used to prove
// the cloud backends correctly reject ed25519 (which no cloud KMS supports).
func assertRejects(t *testing.T, resolver sshbackend.Resolver, backendID string, algo keys.Algorithm) {
	t.Helper()
	p, err := sshbackend.New(resolver)
	if err != nil {
		t.Fatalf("backend.New: %v", err)
	}
	if _, err := p.GenerateKey(context.Background(), backendID, "ssh-user-test-reject", algo, 0); err == nil {
		t.Fatalf("expected algorithm %s to be rejected on backend %s, got nil error", algo, backendID)
	}
}
