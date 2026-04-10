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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// --- GenerateSymmetricKey ---

func TestBackend_GenerateSymmetricKey_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalGenerateKey {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalGenerateKey, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:     "sym-key",
				Algorithm: "AES256-GCM",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:                 "sym-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil symmetric key")
	}
	if key.Algorithm() != string(types.SymmetricAES256GCM) {
		t.Errorf("expected algorithm %s, got %s", types.SymmetricAES256GCM, key.Algorithm())
	}
	if key.KeySize() != 256 {
		t.Errorf("expected key size 256, got %d", key.KeySize())
	}
}

func TestBackend_GenerateSymmetricKey_AES128(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:     "sym-key-128",
				Algorithm: "AES128-GCM",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:                 "sym-key-128",
		SymmetricAlgorithm: types.SymmetricAES128GCM,
	}

	key, err := b.GenerateSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if key.KeySize() != 128 {
		t.Errorf("expected key size 128, got %d", key.KeySize())
	}
}

func TestBackend_GenerateSymmetricKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	attrs := &types.KeyAttributes{
		CN:                 "sym-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := b.GenerateSymmetricKey(attrs)
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_GenerateSymmetricKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GenerateSymmetricKey(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_GenerateSymmetricKey_UnsupportedAlgorithm(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	attrs := &types.KeyAttributes{
		CN:                 "sym-key",
		SymmetricAlgorithm: types.SymmetricAlgorithm("unsupported-algo"),
	}

	_, err := b.GenerateSymmetricKey(attrs)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestBackend_GenerateSymmetricKey_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyExists, "exists"), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:                 "existing-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	_, err := b.GenerateSymmetricKey(attrs)
	if err != ErrKeyExists {
		t.Errorf("expected ErrKeyExists, got %v", err)
	}
}

// --- GetSymmetricKey ---

func TestBackend_GetSymmetricKey_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
				KeyInfo: phoneproto.KeyInfo{
					KeyID:     "sym-key",
					Algorithm: "AES256-GCM",
				},
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:                 "sym-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	key, err := b.GetSymmetricKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if key == nil {
		t.Fatal("expected non-nil key")
	}
	if key.Algorithm() != string(types.SymmetricAES256GCM) {
		t.Errorf("expected algorithm %s, got %s", types.SymmetricAES256GCM, key.Algorithm())
	}
}

func TestBackend_GetSymmetricKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.GetSymmetricKey(&types.KeyAttributes{CN: "key"})
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_GetSymmetricKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GetSymmetricKey(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_GetSymmetricKey_NotFound(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.GetSymmetricKey(&types.KeyAttributes{CN: "missing"})
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// --- SymmetricEncrypter ---

func TestBackend_SymmetricEncrypter_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
				KeyInfo: phoneproto.KeyInfo{
					KeyID:     "sym-key",
					Algorithm: "AES256-GCM",
				},
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:                 "sym-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}

	enc, err := b.SymmetricEncrypter(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if enc == nil {
		t.Fatal("expected non-nil encrypter")
	}
}

func TestBackend_SymmetricEncrypter_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.SymmetricEncrypter(&types.KeyAttributes{CN: "key"})
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_SymmetricEncrypter_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.SymmetricEncrypter(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_SymmetricEncrypter_KeyNotFound(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.SymmetricEncrypter(&types.KeyAttributes{CN: "missing"})
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// --- phoneSymmetricKey ---

func TestPhoneSymmetricKey_Raw_NotSupported(t *testing.T) {
	key := &phoneSymmetricKey{
		keyID:     "test",
		algorithm: "AES256-GCM",
		keySize:   256,
	}

	_, err := key.Raw()
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported, got %v", err)
	}
}

func TestPhoneSymmetricKey_Algorithm(t *testing.T) {
	key := &phoneSymmetricKey{
		keyID:     "test",
		algorithm: "AES256-GCM",
		keySize:   256,
	}

	if key.Algorithm() != "AES256-GCM" {
		t.Errorf("expected AES256-GCM, got %s", key.Algorithm())
	}
}

func TestPhoneSymmetricKey_KeySize(t *testing.T) {
	key := &phoneSymmetricKey{
		keyID:     "test",
		algorithm: "AES128-GCM",
		keySize:   128,
	}

	if key.KeySize() != 128 {
		t.Errorf("expected 128, got %d", key.KeySize())
	}
}

// --- phoneSymmetricEncrypter ---

func TestPhoneSymmetricEncrypter_Encrypt_Success(t *testing.T) {
	expectedCiphertext := []byte("iv-encrypted-data-tag")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalSymmetricEncrypt {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalSymmetricEncrypt, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalSymmetricEncryptResult{
				Ciphertext: expectedCiphertext,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	result, err := enc.Encrypt([]byte("hello world"), nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(result.Ciphertext) != string(expectedCiphertext) {
		t.Errorf("expected ciphertext %q, got %q", expectedCiphertext, result.Ciphertext)
	}
	if result.Algorithm != "AES256-GCM" {
		t.Errorf("expected algorithm AES256-GCM, got %s", result.Algorithm)
	}
}

func TestPhoneSymmetricEncrypter_Encrypt_WithAAD(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalSymmetricEncryptResult{
				Ciphertext: []byte("encrypted"),
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	opts := &types.EncryptOptions{
		AdditionalData: []byte("additional-auth-data"),
	}

	result, err := enc.Encrypt([]byte("plaintext"), opts)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}
}

func TestPhoneSymmetricEncrypter_Encrypt_NilPlaintext(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	_, err := enc.Encrypt(nil, nil)
	if err != ErrSymmetricEncryptFailed {
		t.Errorf("expected ErrSymmetricEncryptFailed, got %v", err)
	}
}

func TestPhoneSymmetricEncrypter_Encrypt_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, errors.New("connection lost")
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	_, err := enc.Encrypt([]byte("data"), nil)
	if err == nil {
		t.Error("expected error, got nil")
	}
}

func TestPhoneSymmetricEncrypter_Decrypt_Success(t *testing.T) {
	expectedPlaintext := []byte("decrypted-plaintext")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalSymmetricDecrypt {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalSymmetricDecrypt, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalSymmetricDecryptResult{
				Plaintext: expectedPlaintext,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	data := &types.EncryptedData{
		Ciphertext: []byte("iv-encrypted-tag"),
		Algorithm:  "AES256-GCM",
	}

	plaintext, err := enc.Decrypt(data, nil)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(plaintext) != string(expectedPlaintext) {
		t.Errorf("expected plaintext %q, got %q", expectedPlaintext, plaintext)
	}
}

func TestPhoneSymmetricEncrypter_Decrypt_WithAAD(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalSymmetricDecryptResult{
				Plaintext: []byte("decrypted"),
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	data := &types.EncryptedData{
		Ciphertext: []byte("iv-encrypted-tag"),
	}
	opts := &types.DecryptOptions{
		AdditionalData: []byte("additional-auth-data"),
	}

	plaintext, err := enc.Decrypt(data, opts)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(plaintext) != "decrypted" {
		t.Errorf("expected decrypted, got %s", plaintext)
	}
}

func TestPhoneSymmetricEncrypter_Decrypt_NilData(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	_, err := enc.Decrypt(nil, nil)
	if err != ErrSymmetricDecryptFailed {
		t.Errorf("expected ErrSymmetricDecryptFailed, got %v", err)
	}
}

func TestPhoneSymmetricEncrypter_Decrypt_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeDecryptFailed, "decrypt failed"), nil
		},
	}

	b := newTestBackend(t, sender)
	enc := &phoneSymmetricEncrypter{
		backend:   b,
		keyID:     "sym-key",
		algorithm: "AES256-GCM",
	}

	data := &types.EncryptedData{
		Ciphertext: []byte("bad-ciphertext"),
	}

	_, err := enc.Decrypt(data, nil)
	if err != ErrProtocolError {
		t.Errorf("expected ErrProtocolError, got %v", err)
	}
}

// --- mapSymmetricAlgorithm ---

func TestMapSymmetricAlgorithm_AllSupported(t *testing.T) {
	tests := []struct {
		algo     types.SymmetricAlgorithm
		expected string
	}{
		{types.SymmetricAES128GCM, "AES128-GCM"},
		{types.SymmetricAES192GCM, "AES192-GCM"},
		{types.SymmetricAES256GCM, "AES256-GCM"},
		{types.SymmetricChaCha20Poly1305, "CHACHA20-POLY1305"},
		{types.SymmetricXChaCha20Poly1305, "XCHACHA20-POLY1305"},
	}

	for _, tc := range tests {
		t.Run(string(tc.algo), func(t *testing.T) {
			result, err := mapSymmetricAlgorithm(tc.algo)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, result)
			}
		})
	}
}

func TestMapSymmetricAlgorithm_Unsupported(t *testing.T) {
	_, err := mapSymmetricAlgorithm(types.SymmetricAlgorithm("DES-CBC"))
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

// --- resolveSymmetricAlgorithm ---

func TestResolveSymmetricAlgorithm_KnownAlgo(t *testing.T) {
	result := resolveSymmetricAlgorithm("AES256-GCM", types.SymmetricAES128GCM)
	if result != types.SymmetricAES256GCM {
		t.Errorf("expected SymmetricAES256GCM, got %v", result)
	}
}

func TestResolveSymmetricAlgorithm_UnknownFallback(t *testing.T) {
	result := resolveSymmetricAlgorithm("UNKNOWN-ALGO", types.SymmetricAES128GCM)
	if result != types.SymmetricAES128GCM {
		t.Errorf("expected fallback to SymmetricAES128GCM, got %v", result)
	}
}

func TestResolveSymmetricAlgorithm_ShortNames(t *testing.T) {
	// Test the short name aliases like "AES128" -> SymmetricAES128GCM.
	result := resolveSymmetricAlgorithm("AES128", types.SymmetricAES256GCM)
	if result != types.SymmetricAES128GCM {
		t.Errorf("expected SymmetricAES128GCM from AES128, got %v", result)
	}

	result = resolveSymmetricAlgorithm("AES256", types.SymmetricAES128GCM)
	if result != types.SymmetricAES256GCM {
		t.Errorf("expected SymmetricAES256GCM from AES256, got %v", result)
	}
}
