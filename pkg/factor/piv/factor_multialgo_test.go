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

package piv

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// TestPIVFactor_Verify_MultiAlgorithm locks in that Verify accepts every
// algorithm Enroll can produce (go-xkms#1289): a genuine signature passes,
// and each of the standard forgery attempts (wrong signature, key-type
// mismatch, signature by a different key of the same type) fails.
func TestPIVFactor_Verify_MultiAlgorithm(t *testing.T) {
	algorithms := []string{"ecdsap256", "rsa2048", "ed25519"}

	for _, algorithm := range algorithms {
		t.Run(algorithm, func(t *testing.T) {
			f := New(Config{})
			enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
				UserID:       "custodian-" + algorithm,
				MethodParams: map[string]any{"algorithm": algorithm},
			})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			slot := pivcert.PIVSlot(enrollment.Metadata["slot"])

			challenge, err := f.Challenge(context.Background(), enrollment)
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}

			t.Run("genuine signature passes", func(t *testing.T) {
				sig, err := f.SignNonce(context.Background(), slot, challenge.Nonce)
				if err != nil {
					t.Fatalf("SignNonce: %v", err)
				}
				err = f.Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{
					Value: sig,
				})
				if err != nil {
					t.Fatalf("Verify: %v", err)
				}
			})

			t.Run("wrong signature fails", func(t *testing.T) {
				// Sign a different message than the one being verified, so the
				// signature is well-formed for the algorithm but mathematically
				// invalid against challenge.Nonce.
				sig, err := f.SignNonce(context.Background(), slot, []byte("not the challenge nonce"))
				if err != nil {
					t.Fatalf("SignNonce: %v", err)
				}
				var failed *qrdbsdk.AuthFactorVerificationFailedError
				err = f.Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{
					Value: sig,
				})
				if !errors.As(err, &failed) {
					t.Fatalf("Verify(wrong sig) err = %v, want VerificationFailedError", err)
				}
			})

			t.Run("key-type mismatch fails", func(t *testing.T) {
				sig, err := f.SignNonce(context.Background(), slot, challenge.Nonce)
				if err != nil {
					t.Fatalf("SignNonce: %v", err)
				}
				// The enrolled key (read only from the challenge) is of a
				// different algorithm than the key that signed.
				mismatched := *challenge
				mismatched.MethodData = map[string]any{methodDataEnrolledCert: string(differentAlgorithmPublicKeyPEM(t, algorithm))}
				var failed *qrdbsdk.AuthFactorVerificationFailedError
				err = f.Verify(context.Background(), &mismatched, &qrdbsdk.AuthFactorResponse{Value: sig})
				if !errors.As(err, &failed) {
					t.Fatalf("Verify(key-type mismatch) err = %v, want VerificationFailedError", err)
				}
			})

			t.Run("signature by a different key of the same type fails", func(t *testing.T) {
				other := New(Config{})
				otherEnrollment, err := other.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
					UserID:       "other-custodian-" + algorithm,
					MethodParams: map[string]any{"algorithm": algorithm},
				})
				if err != nil {
					t.Fatalf("Enroll other: %v", err)
				}
				otherSlot := pivcert.PIVSlot(otherEnrollment.Metadata["slot"])
				sig, err := other.SignNonce(context.Background(), otherSlot, challenge.Nonce)
				if err != nil {
					t.Fatalf("SignNonce other: %v", err)
				}
				var failed *qrdbsdk.AuthFactorVerificationFailedError
				err = f.Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{
					Value: sig,
				})
				if !errors.As(err, &failed) {
					t.Fatalf("Verify(different key, same type) err = %v, want VerificationFailedError", err)
				}
			})
		})
	}
}

// TestPIVFactor_Verify_RejectsUndersizedRSAKey proves Verify enforces the
// RSAKeySize2048 floor (types.ValidateRSAKeySize) independently of Enroll's
// own algorithm vocabulary, which never offers a sub-2048-bit RSA choice in
// the first place. The key is built directly with crypto/rsa rather than
// through Enroll so the floor is exercised even for a key Enroll itself
// could never have produced.
func TestPIVFactor_Verify_RejectsUndersizedRSAKey(t *testing.T) {
	// The FIPS 140-3 module refuses to generate or use an RSA key below 2048
	// bits, so the undersized key is built, not generated: Verify must refuse
	// it on the size floor before any RSA operation.
	n := new(big.Int).Lsh(big.NewInt(1), 1023)
	n.Add(n, big.NewInt(1))
	weakKey := &rsa.PublicKey{N: n, E: 65537}
	der, err := x509.MarshalPKIXPublicKey(weakKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	f := New(Config{})
	enrollment, err := f.Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{UserID: "u1"})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(context.Background(), enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}

	sig := make([]byte, weakKey.Size())
	if _, err := rand.Read(sig); err != nil {
		t.Fatalf("rand.Read: %v", err)
	}

	// Simulate an enrollment whose key is below the RSA floor (Enroll's own
	// vocabulary can't produce one): the enrolled key reaches Verify only
	// through the challenge.
	challenge.MethodData = map[string]any{methodDataEnrolledCert: string(pubPEM)}
	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err = f.Verify(context.Background(), challenge, &qrdbsdk.AuthFactorResponse{Value: sig})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(undersized RSA) err = %v, want VerificationFailedError", err)
	}
	if !strings.Contains(failed.Reason, "RSA key size") {
		t.Fatalf("Verify(undersized RSA) Reason = %q, want it to name the RSA key size floor", failed.Reason)
	}
}

// differentAlgorithmPublicKeyPEM returns a PEM-encoded PUBLIC KEY block for a
// freshly generated key whose algorithm family differs from algorithm, so a
// genuine signature from the real enrolled key fails verification against it.
func differentAlgorithmPublicKeyPEM(t *testing.T, algorithm string) []byte {
	t.Helper()
	var pub crypto.PublicKey
	switch algorithm {
	case "ed25519":
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("ecdsa.GenerateKey: %v", err)
		}
		pub = &key.PublicKey
	case "rsa2048", "rsa4096":
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("ed25519.GenerateKey: %v", err)
		}
		pub = priv.Public()
	default: // ecdsap256, ecdsap384
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("rsa.GenerateKey: %v", err)
		}
		pub = &key.PublicKey
	}
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}
