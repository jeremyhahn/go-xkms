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

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	challengemsg "github.com/jeremyhahn/go-xkms/pkg/factor/internal/challenge"
)

// ecKeyPair generates an ECDSA P-256 key pair and returns the base64 DER
// (PKIX) public key plus a sign function producing an ASN.1 DER signature over
// SHA-256 of a message.
func ecKeyPair(t *testing.T) (pubDER string, sign func(message []byte) []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ec key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal ec public: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), func(message []byte) []byte {
		digest := sha256.Sum256(message)
		sig, signErr := priv.Sign(rand.Reader, digest[:], crypto.SHA256)
		if signErr != nil {
			t.Fatalf("ec sign: %v", signErr)
		}
		return sig
	}
}

// rsaKeyPair generates an RSA-2048 key pair and returns the base64 DER public
// key plus a PKCS#1 v1.5 sign function over SHA-256 of a message.
func rsaKeyPair(t *testing.T) (pubDER string, sign func(message []byte) []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate rsa key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshal rsa public: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der), func(message []byte) []byte {
		digest := sha256.Sum256(message)
		sig, signErr := rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, digest[:])
		if signErr != nil {
			t.Fatalf("rsa sign: %v", signErr)
		}
		return sig
	}
}

func TestPKCS11Factor_NewDefaults(t *testing.T) {
	f := New(Config{})
	if got := f.Name(); got != FactorName {
		t.Fatalf("Name() = %q, want %q", got, FactorName)
	}
	if f.cfg.DefaultMechanism != defaultMechanism {
		t.Fatalf("DefaultMechanism = %q, want %q", f.cfg.DefaultMechanism, defaultMechanism)
	}
	if f.cfg.ChallengeTTLSeconds != defaultChallengeTTLSeconds {
		t.Fatalf("ChallengeTTLSeconds = %d, want %d", f.cfg.ChallengeTTLSeconds, defaultChallengeTTLSeconds)
	}
}

func TestPKCS11Factor_RoundTrip(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})

	tests := []struct {
		name    string
		keyPair func(t *testing.T) (string, func([]byte) []byte)
		algo    string
	}{
		{"ecdsa", ecKeyPair, "ecdsa"},
		{"rsa", rsaKeyPair, "rsa"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pubDER, sign := tc.keyPair(t)

			enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
				UserID: "custodian-1",
				MethodParams: map[string]any{
					"public_key_der": pubDER,
					"slot_id":        0,
					"token_label":    "TestToken",
					"key_id":         "abc123",
				},
			})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			if enrollment.FactorName != FactorName {
				t.Fatalf("FactorName = %q, want %q", enrollment.FactorName, FactorName)
			}
			if enrollment.Metadata["algorithm"] != tc.algo {
				t.Fatalf("algorithm = %q, want %q", enrollment.Metadata["algorithm"], tc.algo)
			}
			if enrollment.Metadata["key_id"] != "abc123" {
				t.Fatalf("key_id = %q, want abc123", enrollment.Metadata["key_id"])
			}
			if enrollment.Metadata["slot"] != "0" {
				t.Fatalf("slot = %q, want 0", enrollment.Metadata["slot"])
			}
			if len(enrollment.PublicKey) == 0 {
				t.Fatal("PublicKey is empty")
			}

			challenge, err := f.Challenge(ctx, enrollment)
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			if len(challenge.Nonce) != nonceLength {
				t.Fatalf("nonce length = %d, want %d", len(challenge.Nonce), nonceLength)
			}

			if got := challenge.MethodData[methodDataEnrolledKey]; got != pubDER {
				t.Fatalf("challenge MethodData[%q] = %v, want the enrolled key", methodDataEnrolledKey, got)
			}

			// The response carries only the signature: the verification key
			// comes from the challenge.
			response := &qrdbsdk.AuthFactorResponse{Value: sign(challengemsg.Message(challenge))}
			if err := f.Verify(ctx, challenge, response); err != nil {
				t.Fatalf("Verify: %v", err)
			}
		})
	}
}

func TestPKCS11Factor_Enroll_RejectsNilParams(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Enroll(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Enroll(nil) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestPKCS11Factor_Enroll_RejectsMalformedDER(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	_, err := New(Config{}).Enroll(context.Background(), &qrdbsdk.AuthFactorEnrollParams{
		UserID: "u1",
		MethodParams: map[string]any{
			"public_key_der": base64.StdEncoding.EncodeToString([]byte("not-a-der-key")),
		},
	})
	if !errors.As(err, &inv) {
		t.Fatalf("Enroll(bad der) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestPKCS11Factor_Verify_RejectsExpiredChallenge(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	pubDER, _ := ecKeyPair(t)
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"public_key_der": pubDER},
	})
	challenge, _ := f.Challenge(ctx, enrollment)
	challenge.ExpiresAt = challenge.ExpiresAt.Add(-time.Hour)

	var expired *qrdbsdk.AuthFactorChallengeExpiredError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{})
	if !errors.As(err, &expired) {
		t.Fatalf("Verify(expired) err = %v, want ChallengeExpiredError", err)
	}
}

// TestPKCS11Factor_Verify_RejectsChallengeWithoutEnrolledKey proves Verify has
// no second source for the key: with the enrolled key absent from the
// challenge it refuses, even when the response carries the genuine one.
// TestPKCS11Factor_Verify_BindsTheChallengeMessage pins the proof to go-qrdb's
// challenge message (#1684): a signature over the message for the challenge's
// own ID, purpose and nonce verifies, while the old proof over SHA-256(nonce)
// and a proof made for another purpose with the same nonce are both refused.
func TestPKCS11Factor_Verify_BindsTheChallengeMessage(t *testing.T) {
	ctx := context.Background()
	keyPairs := map[string]func(*testing.T) (string, func([]byte) []byte){
		"ecdsa": ecKeyPair,
		"rsa":   rsaKeyPair,
	}
	for name, newKeyPair := range keyPairs {
		t.Run(name, func(t *testing.T) {
			f := New(Config{})
			pubDER, sign := newKeyPair(t)
			enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
				UserID:       "u1",
				MethodParams: map[string]any{"public_key_der": pubDER},
			})
			if err != nil {
				t.Fatalf("Enroll: %v", err)
			}
			challenge, err := f.Challenge(ctx, enrollment)
			if err != nil {
				t.Fatalf("Challenge: %v", err)
			}
			challenge.MethodData[qrdbsdk.QuorumChallengePurposeKey] = "quorum:a"

			valid := sign(qrdbsdk.QuorumChallengeMessage(challenge.ChallengeID, "quorum:a", challenge.Nonce))
			if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: valid}); err != nil {
				t.Fatalf("Verify(challenge message) = %v, want nil", err)
			}

			otherNonce := append([]byte(nil), challenge.Nonce...)
			otherNonce[0] ^= 0xFF
			refused := map[string][]byte{
				"bare nonce":    sign(challenge.Nonce),
				"other purpose": sign(qrdbsdk.QuorumChallengeMessage(challenge.ChallengeID, "quorum:b", challenge.Nonce)),
				"other nonce":   sign(qrdbsdk.QuorumChallengeMessage(challenge.ChallengeID, "quorum:a", otherNonce)),
			}
			for proof, sig := range refused {
				var failed *qrdbsdk.AuthFactorVerificationFailedError
				if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
					t.Errorf("Verify(%s) err = %v, want VerificationFailedError", proof, err)
				}
			}
		})
	}
}

// TestPKCS11Factor_Verify_RejectsEmptyNonce verifies that a challenge carrying
// no nonce is refused, as go-qrdb's own mtls factor refuses it.
func TestPKCS11Factor_Verify_RejectsEmptyNonce(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	pubDER, sign := ecKeyPair(t)
	enrollment, err := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"public_key_der": pubDER},
	})
	if err != nil {
		t.Fatalf("Enroll: %v", err)
	}
	challenge, err := f.Challenge(ctx, enrollment)
	if err != nil {
		t.Fatalf("Challenge: %v", err)
	}
	challenge.Nonce = nil

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	sig := sign(challengemsg.Message(challenge))
	if err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{Value: sig}); !errors.As(err, &failed) {
		t.Fatalf("Verify(empty nonce) err = %v, want VerificationFailedError", err)
	}
}

// TestPKCS11Factor_Verify_RejectsAttackerKeyInResponse is the #1282
// regression: a response signed by a key the attacker controls, carrying that
// key in its metadata, must not verify against the enrollment.
func TestPKCS11Factor_Verify_RejectsAttackerKeyInResponse(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	pubDER, _ := ecKeyPair(t)
	attackerDER, signAttacker := ecKeyPair(t)
	enrollment, _ := f.Enroll(ctx, &qrdbsdk.AuthFactorEnrollParams{
		UserID:       "u1",
		MethodParams: map[string]any{"public_key_der": pubDER},
	})
	challenge, _ := f.Challenge(ctx, enrollment)

	var failed *qrdbsdk.AuthFactorVerificationFailedError
	err := f.Verify(ctx, challenge, &qrdbsdk.AuthFactorResponse{
		Value:    signAttacker(challengemsg.Message(challenge)),
		Metadata: map[string]string{"public_key_der": attackerDER},
	})
	if !errors.As(err, &failed) {
		t.Fatalf("Verify(attacker key) err = %v, want VerificationFailedError", err)
	}
}

func TestPKCS11Factor_Verify_RejectsNilArgs(t *testing.T) {
	ctx := context.Background()
	f := New(Config{})
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if err := f.Verify(ctx, nil, &qrdbsdk.AuthFactorResponse{}); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil challenge) err = %v, want EnrollmentInvalidError", err)
	}
	if err := f.Verify(ctx, &qrdbsdk.AuthFactorChallenge{}, nil); !errors.As(err, &inv) {
		t.Fatalf("Verify(nil response) err = %v, want EnrollmentInvalidError", err)
	}
}

func TestPKCS11Factor_Challenge_RejectsNilEnrollment(t *testing.T) {
	var inv *qrdbsdk.AuthFactorEnrollmentInvalidError
	if _, err := New(Config{}).Challenge(context.Background(), nil); !errors.As(err, &inv) {
		t.Fatalf("Challenge(nil) err = %v, want EnrollmentInvalidError", err)
	}
}
