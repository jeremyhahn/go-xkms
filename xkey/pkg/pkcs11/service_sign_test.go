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

//go:build codec_json

package pkcs11

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// signTestMessage is the message every combination signs. Each signature is
// checked against it with the standard library's verifier, so a transport
// that hashed a digest twice, or ignored the padding, fails the check.
var signTestMessage = []byte("the operation this signature authorizes")

// generateSignKey creates a key on the software backend and returns its
// public key, parsed from the PEM the transport reports.
func generateSignKey(t *testing.T, tr *EmbeddedTransport, req *transport.GenerateKeyRequest) crypto.PublicKey {
	t.Helper()
	req.Backend = deriveBackend
	resp, err := tr.GenerateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("GenerateKey(%s) error = %v", req.KeyType, err)
	}
	block, _ := pem.Decode([]byte(resp.PublicKeyPEM))
	if block == nil {
		t.Fatalf("GenerateKey(%s) returned no PEM public key", req.KeyType)
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("ParsePKIXPublicKey() error = %v", err)
	}
	return pub
}

// TestEmbeddedTransport_SignCombinations signs the same message as raw data
// and as a SHA-384 digest, for every padding and key type, and checks each
// signature with the standard library verifier and with the transport's own
// Verify.
func TestEmbeddedTransport_SignCombinations(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()

	rsaPub := generateSignKey(t, tr, &transport.GenerateKeyRequest{KeyID: "combo-rsa", Algorithm: "RSA", KeySize: 2048}).(*rsa.PublicKey)
	ecPub := generateSignKey(t, tr, &transport.GenerateKeyRequest{KeyID: "combo-ecdsa", Algorithm: "ECDSA", Curve: "P-384"}).(*ecdsa.PublicKey)

	digest := sha512.Sum384(signTestMessage)

	tests := []struct {
		name       string
		keyID      string
		padding    string
		saltLength int
		verify     func(sig []byte) error
	}{
		{
			name: "rsa pkcs1v15", keyID: "combo-rsa",
			verify: func(sig []byte) error { return rsa.VerifyPKCS1v15(rsaPub, crypto.SHA384, digest[:], sig) },
		},
		{
			name: "rsa pss auto salt", keyID: "combo-rsa", padding: "pss",
			verify: func(sig []byte) error {
				return rsa.VerifyPSS(rsaPub, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
			},
		},
		{
			name: "rsa pss salt equals hash", keyID: "combo-rsa", padding: "pss", saltLength: rsa.PSSSaltLengthEqualsHash,
			verify: func(sig []byte) error {
				return rsa.VerifyPSS(rsaPub, crypto.SHA384, digest[:], sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			},
		},
		{
			name: "ecdsa", keyID: "combo-ecdsa",
			verify: func(sig []byte) error {
				if !ecdsa.VerifyASN1(ecPub, digest[:], sig) {
					return errors.New("ecdsa.VerifyASN1 rejected the signature")
				}
				return nil
			},
		},
	}

	inputs := []struct {
		name         string
		data         []byte
		dataIsDigest bool
	}{
		{name: "raw", data: signTestMessage},
		{name: "digest", data: digest[:], dataIsDigest: true},
	}

	for _, tt := range tests {
		for _, in := range inputs {
			t.Run(tt.name+" "+in.name, func(t *testing.T) {
				signResp, err := tr.Sign(ctx, &transport.SignRequest{
					Backend: deriveBackend, KeyID: tt.keyID, Data: in.data, Hash: "SHA-384",
					DataIsDigest: in.dataIsDigest, Padding: tt.padding, SaltLength: tt.saltLength,
				})
				if err != nil {
					t.Fatalf("Sign() error = %v", err)
				}
				if err := tt.verify(signResp.Signature); err != nil {
					t.Fatalf("stdlib verify: %v", err)
				}

				verifyResp, err := tr.Verify(ctx, &transport.VerifyRequest{
					Backend: deriveBackend, KeyID: tt.keyID, Data: in.data, Signature: signResp.Signature, Hash: "SHA-384",
					DataIsDigest: in.dataIsDigest, Padding: tt.padding, SaltLength: tt.saltLength,
				})
				if err != nil {
					t.Fatalf("Verify() error = %v", err)
				}
				if !verifyResp.Valid {
					t.Error("Verify() Valid = false, want true for a genuine signature")
				}
			})
		}
	}
}

// TestEmbeddedTransport_SignEd25519 covers Ed25519, which signs the message
// itself: raw data verifies with ed25519.Verify, and a digest is refused with
// a typed error on both Sign and Verify rather than signed as if it were the
// message.
func TestEmbeddedTransport_SignEd25519(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()
	pub := generateSignKey(t, tr, &transport.GenerateKeyRequest{KeyID: "combo-ed25519", Algorithm: "Ed25519"}).(ed25519.PublicKey)

	t.Run("raw", func(t *testing.T) {
		signResp, err := tr.Sign(ctx, &transport.SignRequest{
			Backend: deriveBackend, KeyID: "combo-ed25519", Data: signTestMessage,
		})
		if err != nil {
			t.Fatalf("Sign() error = %v", err)
		}
		if !ed25519.Verify(pub, signTestMessage, signResp.Signature) {
			t.Fatal("ed25519.Verify rejected the signature")
		}
	})

	t.Run("digest refused by sign", func(t *testing.T) {
		digest := sha512.Sum512(signTestMessage)
		_, err := tr.Sign(ctx, &transport.SignRequest{
			Backend: deriveBackend, KeyID: "combo-ed25519", Data: digest[:], Hash: "SHA-512", DataIsDigest: true,
		})
		if !errors.Is(err, xkms.ServiceErrEd25519DigestInput) {
			t.Fatalf("Sign() error = %v, want ServiceErrEd25519DigestInput", err)
		}
		if !errors.Is(err, ErrSigningFailed) {
			t.Errorf("Sign() error = %v, want ErrSigningFailed", err)
		}
	})

	t.Run("digest refused by verify", func(t *testing.T) {
		digest := sha512.Sum512(signTestMessage)
		_, err := tr.Verify(ctx, &transport.VerifyRequest{
			Backend: deriveBackend, KeyID: "combo-ed25519", Data: digest[:], Signature: make([]byte, ed25519.SignatureSize),
			Hash: "SHA-512", DataIsDigest: true,
		})
		if !errors.Is(err, xkms.ServiceErrEd25519DigestInput) {
			t.Fatalf("Verify() error = %v, want ServiceErrEd25519DigestInput", err)
		}
		if !errors.Is(err, ErrVerifyFailed) {
			t.Errorf("Verify() error = %v, want ErrVerifyFailed", err)
		}
	})
}

// TestEmbeddedTransport_SignDigestErrors covers requests the signing rules
// refuse before the key is used: a supplied digest whose length does not
// match the named hash, and PSS padding on an ECDSA key.
func TestEmbeddedTransport_SignDigestErrors(t *testing.T) {
	tr := newDeriveTestTransport(t)
	ctx := context.Background()
	generateSignKey(t, tr, &transport.GenerateKeyRequest{KeyID: "err-ecdsa", Algorithm: "ECDSA", Curve: "P-256"})

	tests := []struct {
		name string
		req  *transport.SignRequest
	}{
		{
			name: "digest length does not match hash",
			req: &transport.SignRequest{
				Backend: deriveBackend, KeyID: "err-ecdsa", Data: []byte("too short"), Hash: "SHA-256", DataIsDigest: true,
			},
		},
		{
			name: "pss padding on ecdsa",
			req: &transport.SignRequest{
				Backend: deriveBackend, KeyID: "err-ecdsa", Data: signTestMessage, Padding: "pss",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := tr.Sign(ctx, tt.req)
			if !errors.Is(err, ErrSigningFailed) {
				t.Fatalf("Sign() error = %v, want ErrSigningFailed", err)
			}
		})
	}
}
