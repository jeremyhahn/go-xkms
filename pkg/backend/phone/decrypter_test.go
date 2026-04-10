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
	"errors"
	"testing"

	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

func TestPhoneDecrypter_Public(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{}
	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	pub := dec.Public()
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

func TestPhoneDecrypter_Decrypt_Success(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	expectedPlaintext := []byte("decrypted-data-here")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalDecrypt {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalDecrypt, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalDecryptResult{
				Plaintext: expectedPlaintext,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	ciphertext := []byte("encrypted-data")
	plaintext, err := dec.Decrypt(rand.Reader, ciphertext, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(plaintext) != string(expectedPlaintext) {
		t.Errorf("expected plaintext %q, got %q", expectedPlaintext, plaintext)
	}
}

func TestPhoneDecrypter_Decrypt_RPCError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeDecryptFailed, "decryption failed"), nil
		},
	}

	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	_, err = dec.Decrypt(rand.Reader, []byte("encrypted"), nil)
	if err != ErrProtocolError {
		t.Errorf("expected ErrProtocolError, got %v", err)
	}
}

func TestPhoneDecrypter_Decrypt_TransportError(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	transportErr := errors.New("transport failure")
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, transportErr
		},
	}

	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	_, err = dec.Decrypt(rand.Reader, []byte("encrypted"), nil)
	if err != transportErr {
		t.Errorf("expected transport error, got %v", err)
	}
}

func TestPhoneDecrypter_Decrypt_BackendClosed(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{}
	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	_ = b.Close()

	_, err = dec.Decrypt(rand.Reader, []byte("encrypted"), nil)
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestPhoneDecrypter_ImplementsCryptoDecrypter(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}

	sender := &mockSender{}
	b := newTestBackend(t, sender)
	dec := newPhoneDecrypter(b, "test-key", "ES256", &key.PublicKey)

	// Compile-time assertion that phoneDecrypter satisfies crypto.Decrypter.
	var _ crypto.Decrypter = dec
}
