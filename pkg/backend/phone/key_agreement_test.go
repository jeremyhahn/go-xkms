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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

func generatePeerPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return der
}

func TestBackend_DeriveKeyECDH_Success_NoKDF(t *testing.T) {
	sharedSecret := []byte("shared-secret-32-bytes-long-key!")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalECDH {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalECDH, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	result, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(result) != string(sharedSecret) {
		t.Errorf("expected shared secret %q, got %q", sharedSecret, result)
	}
}

func TestBackend_DeriveKeyECDH_Success_WithHKDF(t *testing.T) {
	sharedSecret := []byte("raw-shared-secret-from-ecdh-here")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 32,
		Salt:      []byte("salt"),
		Info:      []byte("info"),
	}

	result, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result) != 32 {
		t.Errorf("expected 32-byte derived key, got %d bytes", len(result))
	}

	// Ensure the derived key is different from the raw shared secret.
	if string(result) == string(sharedSecret) {
		t.Error("derived key should not equal raw shared secret after KDF")
	}
}

func TestBackend_DeriveKeyECDH_Success_WithHKDF_SHA384(t *testing.T) {
	sharedSecret := []byte("raw-ecdh-shared-secret-material!")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-384",
		KeyLength: 48,
	}

	result, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result) != 48 {
		t.Errorf("expected 48-byte derived key, got %d bytes", len(result))
	}
}

func TestBackend_DeriveKeyECDH_Success_WithHKDF_SHA512(t *testing.T) {
	sharedSecret := []byte("raw-ecdh-shared-secret-material!")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-512",
		KeyLength: 64,
	}

	result, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(result) != 64 {
		t.Errorf("expected 64-byte derived key, got %d bytes", len(result))
	}
}

func TestBackend_DeriveKeyECDH_Success_WithHKDF_SHA3(t *testing.T) {
	sharedSecret := []byte("raw-ecdh-shared-secret-material!")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	hashTests := []struct {
		hash      string
		keyLength int
	}{
		{"SHA3-256", 32},
		{"SHA3-384", 48},
		{"SHA3-512", 64},
	}

	for _, ht := range hashTests {
		t.Run(ht.hash, func(t *testing.T) {
			kdfParams := &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      ht.hash,
				KeyLength: ht.keyLength,
			}

			result, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
			if err != nil {
				t.Fatalf("expected nil error for %s, got %v", ht.hash, err)
			}
			if len(result) != ht.keyLength {
				t.Errorf("expected %d-byte key for %s, got %d", ht.keyLength, ht.hash, len(result))
			}
		})
	}
}

func TestBackend_DeriveKeyECDH_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, nil)
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	peerKey := generatePeerPublicKeyDER(t)

	_, err := b.DeriveKeyECDH(context.Background(), nil, peerKey, nil)
	if err != ErrInvalidKeyAttributes {
		t.Errorf("expected ErrInvalidKeyAttributes, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_EmptyPeerKey(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("my-key")

	_, err := b.DeriveKeyECDH(context.Background(), attrs, nil, nil)
	if err != ErrInvalidPeerPublicKey {
		t.Errorf("expected ErrInvalidPeerPublicKey for nil, got %v", err)
	}

	_, err = b.DeriveKeyECDH(context.Background(), attrs, []byte{}, nil)
	if err != ErrInvalidPeerPublicKey {
		t.Errorf("expected ErrInvalidPeerPublicKey for empty, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_EmptySharedSecret(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: nil,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, nil)
	if err != ErrEmptySharedSecret {
		t.Errorf("expected ErrEmptySharedSecret, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeECDHFailed, "ecdh failed"), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, nil)
	// ErrorCodeECDHFailed is not in the rpcErrorMapping, so it maps to ErrProtocolError.
	if err != ErrProtocolError {
		t.Errorf("expected ErrProtocolError, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_InvalidKDFParams(t *testing.T) {
	sharedSecret := []byte("raw-shared-secret-from-ecdh-here")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	// Invalid KDF params: KeyLength <= 0.
	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 0,
	}

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	if err != ErrInvalidKDFParams {
		t.Errorf("expected ErrInvalidKDFParams, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_UnsupportedKDFAlgorithm(t *testing.T) {
	sharedSecret := []byte("raw-shared-secret-from-ecdh-here")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithm("SP800-108-COUNTER"),
		Hash:      "SHA-256",
		KeyLength: 32,
	}

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	if err != ErrUnsupportedKDFAlgorithm {
		t.Errorf("expected ErrUnsupportedKDFAlgorithm, got %v", err)
	}
}

func TestBackend_DeriveKeyECDH_UnsupportedHashAlgorithm(t *testing.T) {
	sharedSecret := []byte("raw-shared-secret-from-ecdh-here")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalECDHResult{
				SharedSecret: sharedSecret,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	peerKey := generatePeerPublicKeyDER(t)
	attrs := ecdsaP256Attrs("my-key")

	kdfParams := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "MD5",
		KeyLength: 32,
	}

	_, err := b.DeriveKeyECDH(context.Background(), attrs, peerKey, kdfParams)
	// The KDFParams.Validate() will reject "MD5" as an unsupported hash.
	if err != ErrInvalidKDFParams {
		t.Errorf("expected ErrInvalidKDFParams for unsupported hash, got %v", err)
	}
}

// --- SupportedCurves ---

func TestBackend_SupportedCurves(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	curves := b.SupportedCurves()
	if len(curves) != 3 {
		t.Fatalf("expected 3 curves, got %d", len(curves))
	}

	expected := map[string]bool{
		"P-256": true,
		"P-384": true,
		"P-521": true,
	}

	for _, c := range curves {
		if !expected[c] {
			t.Errorf("unexpected curve: %s", c)
		}
	}
}

// --- applyKDF ---

func TestApplyKDF_HKDF_SHA256(t *testing.T) {
	secret := []byte("test-shared-secret-for-kdf-test!")
	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "SHA-256",
		KeyLength: 32,
		Salt:      []byte("salt"),
		Info:      []byte("info"),
	}

	result, err := applyKDF(secret, params)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(result) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(result))
	}
}

func TestApplyKDF_UnsupportedAlgorithm(t *testing.T) {
	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithm("PBKDF2"),
		Hash:      "SHA-256",
		KeyLength: 32,
	}

	_, err := applyKDF([]byte("secret"), params)
	if err != ErrUnsupportedKDFAlgorithm {
		t.Errorf("expected ErrUnsupportedKDFAlgorithm, got %v", err)
	}
}

func TestApplyKDF_UnsupportedHash(t *testing.T) {
	params := &types.KDFParams{
		Algorithm: types.KDFAlgorithmHKDF,
		Hash:      "MD5",
		KeyLength: 32,
	}

	_, err := applyKDF([]byte("secret"), params)
	if err != ErrUnsupportedHashAlgorithm {
		t.Errorf("expected ErrUnsupportedHashAlgorithm, got %v", err)
	}
}

func TestApplyKDF_AllSupportedHashes(t *testing.T) {
	secret := []byte("test-secret-for-hash-validation!")

	hashes := []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"}

	for _, hash := range hashes {
		t.Run(hash, func(t *testing.T) {
			params := &types.KDFParams{
				Algorithm: types.KDFAlgorithmHKDF,
				Hash:      hash,
				KeyLength: 32,
			}
			result, err := applyKDF(secret, params)
			if err != nil {
				t.Fatalf("unexpected error for hash %s: %v", hash, err)
			}
			if len(result) != 32 {
				t.Errorf("expected 32 bytes for hash %s, got %d", hash, len(result))
			}
		})
	}
}

// --- hashFuncMapping ---

func TestHashFuncMapping_AllEntries(t *testing.T) {
	expectedHashes := []string{"SHA-256", "SHA-384", "SHA-512", "SHA3-256", "SHA3-384", "SHA3-512"}

	for _, name := range expectedHashes {
		t.Run(name, func(t *testing.T) {
			fn, ok := hashFuncMapping[name]
			if !ok {
				t.Errorf("hash %s not in hashFuncMapping", name)
				return
			}
			h := fn()
			if h == nil {
				t.Errorf("hash function for %s returned nil", name)
			}
		})
	}
}
