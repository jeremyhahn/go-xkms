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

package phone

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"testing"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

func TestPhoneSigner_Public(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{}
	b := newTestBackend(t, sender)

	signer := newPhoneSigner(b, "test-key", "ES256", &key.PublicKey)

	pub := signer.Public()
	if pub == nil {
		t.Fatal("expected non-nil public key")
	}

	ecPub, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("expected *ecdsa.PublicKey, got %T", pub)
	}
	if !ecPub.Equal(&key.PublicKey) {
		t.Error("public key does not match original")
	}
}

func TestPhoneSigner_Sign_Success(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	expectedSig := []byte("mock-signature-bytes")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalSign {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalSign, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalSignResult{
				Signature: expectedSig,
				Algorithm: "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	signer := newPhoneSigner(b, "test-key", "ES256", &key.PublicKey)

	digest := []byte("data-to-sign-hash-32-bytes-long!")
	sig, err := signer.Sign(rand.Reader, digest, crypto.SHA256)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(sig) != string(expectedSig) {
		t.Errorf("expected signature %v, got %v", expectedSig, sig)
	}
}

func TestPhoneSigner_Sign_RPCError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeBiometricFailed, "biometric failed"), nil
		},
	}

	b := newTestBackend(t, sender)
	signer := newPhoneSigner(b, "test-key", "ES256", &key.PublicKey)

	_, err = signer.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
	if err != ErrSigningFailed {
		t.Errorf("expected ErrSigningFailed, got %v", err)
	}
}

func TestPhoneSigner_Sign_TransportError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, errors.New("connection dropped")
		},
	}

	b := newTestBackend(t, sender)
	signer := newPhoneSigner(b, "test-key", "ES256", &key.PublicKey)

	_, err = signer.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
	if err != ErrSigningFailed {
		t.Errorf("expected ErrSigningFailed, got %v", err)
	}
}

func TestPhoneSigner_Sign_BackendClosed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{}
	b := newTestBackend(t, sender)
	signer := newPhoneSigner(b, "test-key", "ES256", &key.PublicKey)

	_ = b.Close()

	_, err = signer.Sign(rand.Reader, []byte("digest"), crypto.SHA256)
	if err != ErrSigningFailed {
		t.Errorf("expected ErrSigningFailed (wrapping ErrBackendClosed), got %v", err)
	}
}

func TestPhoneSigner_ImplementsCryptoSigner(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			switch req.Method {
			case phoneproto.MethodLocalGetKeyInfo:
				return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
					KeyInfo: phoneproto.KeyInfo{
						KeyID:     "test-key",
						Algorithm: "ES256",
					},
				}), nil
			case phoneproto.MethodLocalGetPublicKey:
				return mockSuccessResponse(phoneproto.LocalGetPublicKeyResult{
					PublicKey: pubDER,
					Algorithm: "ES256",
				}), nil
			default:
				return nil, errors.New("unexpected method")
			}
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	// Verify GenerateKey returns something that implements crypto.Signer.
	privKey, err := b.GetKey(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if _, ok := privKey.(crypto.Signer); !ok {
		t.Fatal("GetKey result does not implement crypto.Signer")
	}
}
