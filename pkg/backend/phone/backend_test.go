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
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// mockSender is a test double that intercepts SendRequest calls and
// returns configurable responses.
type mockSender struct {
	sendFunc func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error)
}

func (m *mockSender) SendRequest(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
	return m.sendFunc(ctx, req)
}

// --- test helpers ---

func validConfig() *Config {
	return &Config{
		Transport:      TransportBLE,
		DeviceAddress:  "AA:BB:CC:DD:EE:FF",
		NoiseStaticKey: "deadbeef01020304",
		PhoneStaticKey: "cafebabe05060708",
	}
}

func mockSuccessResponse(result interface{}) *phoneproto.Response {
	data, _ := json.Marshal(result)
	return &phoneproto.Response{
		JSONRPC: phoneproto.JSONRPCVersion,
		ID:      1,
		Result:  json.RawMessage(data),
	}
}

func mockErrorResponse(code int, message string) *phoneproto.Response {
	return &phoneproto.Response{
		JSONRPC: phoneproto.JSONRPCVersion,
		ID:      1,
		Error: &phoneproto.RPCError{
			Code:    code,
			Message: message,
		},
	}
}

// mockInvalidResultResponse returns a response with invalid JSON in the Result
// field, which causes DecodeResult to fail.
func mockInvalidResultResponse() *phoneproto.Response {
	return &phoneproto.Response{
		JSONRPC: phoneproto.JSONRPCVersion,
		ID:      1,
		Result:  json.RawMessage([]byte("{{invalid json")),
	}
}

func generateTestECDSAPublicKeyDER(t *testing.T) []byte {
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

func generateTestRSAPublicKeyDER(t *testing.T) []byte {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("failed to marshal public key: %v", err)
	}
	return der
}

func newTestBackend(t *testing.T, sender Sender) *Backend {
	t.Helper()
	cfg := validConfig()
	b, err := NewBackend(cfg, sender)
	if err != nil {
		t.Fatalf("failed to create backend: %v", err)
	}
	return b
}

func ecdsaP256Attrs(cn string) *types.KeyAttributes {
	return &types.KeyAttributes{
		CN:           cn,
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
}

// --- NewBackend tests ---

func TestNewBackend_Valid(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(nil), nil
		},
	}

	b, err := NewBackend(validConfig(), sender)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if b == nil {
		t.Fatal("expected non-nil backend")
	}
}

func TestNewBackend_NilConfig(t *testing.T) {
	sender := &mockSender{}

	_, err := NewBackend(nil, sender)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestNewBackend_InvalidConfig(t *testing.T) {
	sender := &mockSender{}
	cfg := &Config{
		Transport: "invalid",
	}

	_, err := NewBackend(cfg, sender)
	if err != ErrInvalidTransport {
		t.Errorf("expected ErrInvalidTransport, got %v", err)
	}
}

func TestNewBackend_NilSender(t *testing.T) {
	_, err := NewBackend(validConfig(), nil)
	if err != ErrNotConnected {
		t.Errorf("expected ErrNotConnected, got %v", err)
	}
}

// --- Type and Capabilities ---

func TestBackend_Type(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	if b.Type() != types.BackendTypePhone {
		t.Errorf("expected BackendTypePhone, got %v", b.Type())
	}
}

func TestBackend_Capabilities(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	caps := b.Capabilities()

	if !caps.Keys {
		t.Error("expected Keys capability")
	}
	if !caps.HardwareBacked {
		t.Error("expected HardwareBacked capability")
	}
	if !caps.Signing {
		t.Error("expected Signing capability")
	}
	if !caps.Decryption {
		t.Error("expected Decryption capability")
	}
	if caps.KeyRotation {
		t.Error("expected KeyRotation to be false")
	}
	if !caps.SymmetricEncryption {
		t.Error("expected SymmetricEncryption capability")
	}
	if caps.Sealing {
		t.Error("expected Sealing to be false")
	}
	if caps.Import {
		t.Error("expected Import to be false")
	}
	if caps.Export {
		t.Error("expected Export to be false")
	}
	if !caps.KeyAgreement {
		t.Error("expected KeyAgreement capability")
	}
	if !caps.Attestation {
		t.Error("expected Attestation capability")
	}
}

// --- GenerateKey ---

func TestBackend_GenerateKey_Success(t *testing.T) {
	pubKeyDER := generateTestECDSAPublicKeyDER(t)

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:        "test-key",
				PublicKeyDER: pubKeyDER,
				Algorithm:    "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	privKey, err := b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if privKey == nil {
		t.Fatal("expected non-nil private key")
	}

	signer, ok := privKey.(*phoneSigner)
	if !ok {
		t.Fatal("expected *phoneSigner type")
	}
	if signer.Public() == nil {
		t.Error("expected non-nil public key from signer")
	}
}

func TestBackend_GenerateKey_RSA_WithAttributes(t *testing.T) {
	pubKeyDER := generateTestRSAPublicKeyDER(t)

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:        "rsa-key",
				PublicKeyDER: pubKeyDER,
				Algorithm:    "RS256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := &types.KeyAttributes{
		CN:           "rsa-key",
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 4096,
		},
	}

	privKey, err := b.GenerateKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if privKey == nil {
		t.Fatal("expected non-nil private key")
	}
}

func TestBackend_GenerateKey_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	_, err := b.GenerateKey(attrs)
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid decode, got %v", err)
	}
}

func TestBackend_GenerateKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	attrs := ecdsaP256Attrs("test-key")
	_, err := b.GenerateKey(attrs)
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_GenerateKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GenerateKey(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig for nil attrs, got %v", err)
	}
}

func TestBackend_GenerateKey_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyExists, "key exists"), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("existing-key")

	_, err := b.GenerateKey(attrs)
	if err != ErrKeyExists {
		t.Errorf("expected ErrKeyExists, got %v", err)
	}
}

func TestBackend_GenerateKey_TransportError(t *testing.T) {
	transportErr := errors.New("transport failure")
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return nil, transportErr
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	_, err := b.GenerateKey(attrs)
	if err != transportErr {
		t.Errorf("expected transport error, got %v", err)
	}
}

func TestBackend_GenerateKey_UnsupportedAlgorithm(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	attrs := &types.KeyAttributes{
		CN:           "test-key",
		KeyAlgorithm: x509.PublicKeyAlgorithm(99),
	}

	_, err := b.GenerateKey(attrs)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestBackend_GenerateKey_ECDSANilCurve(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	attrs := &types.KeyAttributes{
		CN:            "test-key",
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: nil,
	}

	_, err := b.GenerateKey(attrs)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm for nil ECCAttributes, got %v", err)
	}
}

func TestBackend_GenerateKey_InvalidPublicKeyDER(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:        "test-key",
				PublicKeyDER: []byte("not-a-valid-der-key"),
				Algorithm:    "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	_, err := b.GenerateKey(attrs)
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestBackend_GenerateKey_EmptyPublicKeyDER(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGenerateKeyResult{
				KeyID:        "test-key",
				PublicKeyDER: nil,
				Algorithm:    "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	_, err := b.GenerateKey(attrs)
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey for empty DER, got %v", err)
	}
}

// --- GetKey ---

func TestBackend_GetKey_Success(t *testing.T) {
	pubKeyDER := generateTestECDSAPublicKeyDER(t)

	callCount := 0
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			callCount++
			switch req.Method {
			case phoneproto.MethodLocalGetKeyInfo:
				return mockSuccessResponse(phoneproto.LocalGetKeyInfoResult{
					KeyInfo: phoneproto.KeyInfo{
						KeyID:     "test-key",
						Algorithm: "ES256",
						KeyType:   "signing",
					},
				}), nil
			case phoneproto.MethodLocalGetPublicKey:
				return mockSuccessResponse(phoneproto.LocalGetPublicKeyResult{
					PublicKey: pubKeyDER,
					Format:    "der",
					Algorithm: "ES256",
				}), nil
			default:
				t.Errorf("unexpected method: %s", req.Method)
				return nil, errors.New("unexpected method")
			}
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	privKey, err := b.GetKey(attrs)
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if privKey == nil {
		t.Fatal("expected non-nil private key")
	}
	if callCount != 2 {
		t.Errorf("expected 2 RPC calls (getKeyInfo + getPublicKey), got %d", callCount)
	}
}

func TestBackend_GetKey_NotFound(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("nonexistent")

	_, err := b.GetKey(attrs)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_GetKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GetKey(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_GetKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.GetKey(ecdsaP256Attrs("test-key"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_GetKey_InvalidKeyInfoDecode(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method == phoneproto.MethodLocalGetKeyInfo {
				return mockInvalidResultResponse(), nil
			}
			return nil, errors.New("unexpected")
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.GetKey(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid getKeyInfo decode, got %v", err)
	}
}

func TestBackend_GetKey_GetPublicKeyRPCError(t *testing.T) {
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
				return mockErrorResponse(phoneproto.ErrorCodeInternalError, "internal"), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.GetKey(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for getPublicKey RPC error, got %v", err)
	}
}

func TestBackend_GetKey_InvalidPublicKeyDecode(t *testing.T) {
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
				return mockInvalidResultResponse(), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.GetKey(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid publicKey decode, got %v", err)
	}
}

func TestBackend_GetKey_InvalidPublicKeyParse(t *testing.T) {
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
					PublicKey: []byte("invalid-der-bytes"),
					Format:    "der",
					Algorithm: "ES256",
				}), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.GetKey(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey for bad DER, got %v", err)
	}
}

// --- DeleteKey ---

func TestBackend_DeleteKey_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalDeleteKeyResult{
				Deleted: true,
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	err := b.DeleteKey(attrs)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}
}

func TestBackend_DeleteKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	err := b.DeleteKey(ecdsaP256Attrs("test-key"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_DeleteKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err := b.DeleteKey(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_DeleteKey_NotDeleted(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalDeleteKeyResult{
				Deleted: false,
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	err := b.DeleteKey(ecdsaP256Attrs("missing-key"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound when Deleted is false, got %v", err)
	}
}

func TestBackend_DeleteKey_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	err := b.DeleteKey(ecdsaP256Attrs("missing-key"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_DeleteKey_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)

	err := b.DeleteKey(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid decode, got %v", err)
	}
}

// --- ListKeys ---

func TestBackend_ListKeys_Success(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalListKeysResult{
				Keys: []phoneproto.KeyInfo{
					{KeyID: "key-1", Algorithm: "ES256", KeyType: "signing"},
					{KeyID: "key-2", Algorithm: "RS256", KeyType: "encryption"},
					{KeyID: "key-3", Algorithm: "EdDSA", KeyType: "tls"},
				},
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	keys, err := b.ListKeys()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(keys))
	}

	if keys[0].CN != "key-1" {
		t.Errorf("expected key-1, got %s", keys[0].CN)
	}
	if keys[0].KeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA for key-1, got %v", keys[0].KeyAlgorithm)
	}
	if keys[1].CN != "key-2" {
		t.Errorf("expected key-2, got %s", keys[1].CN)
	}
	if keys[1].KeyAlgorithm != x509.RSA {
		t.Errorf("expected RSA for key-2, got %v", keys[1].KeyAlgorithm)
	}
	if keys[2].CN != "key-3" {
		t.Errorf("expected key-3, got %s", keys[2].CN)
	}
}

func TestBackend_ListKeys_Empty(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalListKeysResult{
				Keys: []phoneproto.KeyInfo{},
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	keys, err := b.ListKeys()
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("expected 0 keys, got %d", len(keys))
	}
}

func TestBackend_ListKeys_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.ListKeys()
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_ListKeys_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeInternalError, "internal"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.ListKeys()
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse, got %v", err)
	}
}

func TestBackend_ListKeys_InvalidDecodeResult(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockInvalidResultResponse(), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.ListKeys()
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for corrupt result, got %v", err)
	}
}

// --- Signer ---

func TestBackend_Signer_Success(t *testing.T) {
	pubKeyDER := generateTestECDSAPublicKeyDER(t)

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
					PublicKey: pubKeyDER,
					Format:    "der",
					Algorithm: "ES256",
				}), nil
			default:
				return nil, errors.New("unexpected method")
			}
		},
	}

	b := newTestBackend(t, sender)

	signer, err := b.Signer(ecdsaP256Attrs("test-key"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
	if signer.Public() == nil {
		t.Error("expected non-nil public key")
	}
}

func TestBackend_Signer_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.Signer(ecdsaP256Attrs("test-key"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_Signer_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.Signer(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_Signer_GetKeyError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Signer(ecdsaP256Attrs("missing"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// --- Decrypter ---

func TestBackend_Decrypter_Success(t *testing.T) {
	pubKeyDER := generateTestECDSAPublicKeyDER(t)

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
					PublicKey: pubKeyDER,
					Format:    "der",
					Algorithm: "ES256",
				}), nil
			default:
				return nil, errors.New("unexpected method")
			}
		},
	}

	b := newTestBackend(t, sender)

	decrypter, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if decrypter == nil {
		t.Fatal("expected non-nil decrypter")
	}
	if decrypter.Public() == nil {
		t.Error("expected non-nil public key")
	}
}

func TestBackend_Decrypter_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_Decrypter_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.Decrypter(nil)
	if err != ErrInvalidConfig {
		t.Errorf("expected ErrInvalidConfig, got %v", err)
	}
}

func TestBackend_Decrypter_GetKeyInfoError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Decrypter(ecdsaP256Attrs("missing"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestBackend_Decrypter_InvalidKeyInfoDecode(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method == phoneproto.MethodLocalGetKeyInfo {
				return mockInvalidResultResponse(), nil
			}
			return nil, errors.New("unexpected")
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid decode, got %v", err)
	}
}

func TestBackend_Decrypter_GetPublicKeyRPCError(t *testing.T) {
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
				return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound for public key RPC error, got %v", err)
	}
}

func TestBackend_Decrypter_InvalidPublicKeyDecode(t *testing.T) {
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
				return mockInvalidResultResponse(), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidResponse {
		t.Errorf("expected ErrInvalidResponse for invalid decode, got %v", err)
	}
}

func TestBackend_Decrypter_InvalidPublicKeyParse(t *testing.T) {
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
					PublicKey: []byte("invalid-der"),
					Format:    "der",
					Algorithm: "ES256",
				}), nil
			default:
				return nil, errors.New("unexpected")
			}
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.Decrypter(ecdsaP256Attrs("test-key"))
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey for bad DER, got %v", err)
	}
}

// --- RotateKey ---

func TestBackend_RotateKey_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err := b.RotateKey(ecdsaP256Attrs("test-key"))
	if err != ErrRotationNotSupported {
		t.Errorf("expected ErrRotationNotSupported, got %v", err)
	}
}

// --- Close ---

func TestBackend_Close(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err := b.Close()
	if err != nil {
		t.Errorf("expected nil error on close, got %v", err)
	}

	// Operations after close should return ErrBackendClosed.
	_, err = b.GenerateKey(ecdsaP256Attrs("test-key"))
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed after close, got %v", err)
	}
}

func TestBackend_Close_Idempotent(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err1 := b.Close()
	err2 := b.Close()

	if err1 != nil {
		t.Errorf("first close error: %v", err1)
	}
	if err2 != nil {
		t.Errorf("second close error: %v", err2)
	}
}

// --- mapAlgorithm ---

func TestMapAlgorithm_ECDSA_P256(t *testing.T) {
	attrs := ecdsaP256Attrs("test")
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algo != "ES256" {
		t.Errorf("expected ES256, got %s", algo)
	}
}

func TestMapAlgorithm_ECDSA_P384(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algo != "ES384" {
		t.Errorf("expected ES384, got %s", algo)
	}
}

func TestMapAlgorithm_ECDSA_P521(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: elliptic.P521(),
		},
	}
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algo != "ES512" {
		t.Errorf("expected ES512, got %s", algo)
	}
}

func TestMapAlgorithm_RSA_Default(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
	}
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algo != "RS256" {
		t.Errorf("expected RS256 default, got %s", algo)
	}
}

func TestMapAlgorithm_RSA_WithHash(t *testing.T) {
	tests := []struct {
		name     string
		hash     crypto.Hash
		expected string
	}{
		{"SHA256", crypto.SHA256, "RS256"},
		{"SHA384", crypto.SHA384, "RS384"},
		{"SHA512", crypto.SHA512, "RS512"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			attrs := &types.KeyAttributes{
				CN:           "test",
				KeyAlgorithm: x509.RSA,
				Hash:         tc.hash,
			}
			algo, err := mapAlgorithm(attrs)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if algo != tc.expected {
				t.Errorf("expected %s, got %s", tc.expected, algo)
			}
		})
	}
}

func TestMapAlgorithm_RSA_UnsupportedHash(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.RSA,
		Hash:         crypto.MD5,
	}
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Unsupported hash falls back to RS256 default.
	if algo != "RS256" {
		t.Errorf("expected RS256 fallback, got %s", algo)
	}
}

func TestMapAlgorithm_Ed25519(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.Ed25519,
	}
	algo, err := mapAlgorithm(attrs)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if algo != "EdDSA" {
		t.Errorf("expected EdDSA, got %s", algo)
	}
}

func TestMapAlgorithm_Unsupported(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.PublicKeyAlgorithm(99),
	}
	_, err := mapAlgorithm(attrs)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}
}

func TestMapAlgorithm_ECDSA_NilCurveInAttributes(t *testing.T) {
	attrs := &types.KeyAttributes{
		CN:           "test",
		KeyAlgorithm: x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{
			Curve: nil,
		},
	}
	_, err := mapAlgorithm(attrs)
	if err != ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm for nil curve, got %v", err)
	}
}

// --- parsePublicKey ---

func TestParsePublicKey_ValidECDSA(t *testing.T) {
	der := generateTestECDSAPublicKeyDER(t)

	pubKey, err := parsePublicKey(der, "ES256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pubKey == nil {
		t.Fatal("expected non-nil public key")
	}

	_, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		t.Errorf("expected *ecdsa.PublicKey, got %T", pubKey)
	}
}

func TestParsePublicKey_ValidRSA(t *testing.T) {
	der := generateTestRSAPublicKeyDER(t)

	pubKey, err := parsePublicKey(der, "RS256")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pubKey == nil {
		t.Fatal("expected non-nil public key")
	}

	_, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		t.Errorf("expected *rsa.PublicKey, got %T", pubKey)
	}
}

func TestParsePublicKey_EmptyDER(t *testing.T) {
	_, err := parsePublicKey(nil, "ES256")
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

func TestParsePublicKey_InvalidDER(t *testing.T) {
	_, err := parsePublicKey([]byte("garbage"), "ES256")
	if err != ErrInvalidPublicKey {
		t.Errorf("expected ErrInvalidPublicKey, got %v", err)
	}
}

// --- mapRPCError ---

func TestMapRPCError_NilError(t *testing.T) {
	err := mapRPCError(nil)
	if err != nil {
		t.Errorf("expected nil for nil RPCError, got %v", err)
	}
}

func TestMapRPCError_KnownCode(t *testing.T) {
	rpcErr := &phoneproto.RPCError{
		Code:    phoneproto.ErrorCodeKeyNotFound,
		Message: "key not found",
	}

	err := mapRPCError(rpcErr)
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

func TestMapRPCError_UnknownCode(t *testing.T) {
	rpcErr := &phoneproto.RPCError{
		Code:    -99999,
		Message: "unknown error",
	}

	err := mapRPCError(rpcErr)
	if err != ErrProtocolError {
		t.Errorf("expected ErrProtocolError for unknown code, got %v", err)
	}
}

func TestMapRPCError_AllMappedCodes(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected error
	}{
		{"KeyNotFound", phoneproto.ErrorCodeKeyNotFound, ErrKeyNotFound},
		{"UserCancelled", phoneproto.ErrorCodeUserCancelled, ErrUserCancelled},
		{"BiometricFailed", phoneproto.ErrorCodeBiometricFailed, ErrBiometricFailed},
		{"UnsupportedAlg", phoneproto.ErrorCodeUnsupportedAlg, ErrUnsupportedAlgorithm},
		{"OperationTimeout", phoneproto.ErrorCodeOperationTimeout, ErrOperationTimeout},
		{"KeyExists", phoneproto.ErrorCodeKeyExists, ErrKeyExists},
		{"ParseError", phoneproto.ErrorCodeParseError, ErrProtocolError},
		{"InvalidRequest", phoneproto.ErrorCodeInvalidRequest, ErrProtocolError},
		{"InvalidParams", phoneproto.ErrorCodeInvalidParams, ErrProtocolError},
		{"MethodNotFound", phoneproto.ErrorCodeMethodNotFound, ErrProtocolError},
		{"InternalError", phoneproto.ErrorCodeInternalError, ErrInvalidResponse},
		{"BackendDenied", phoneproto.ErrorCodeBackendDenied, ErrProtocolError},
		{"AttestFailed", phoneproto.ErrorCodeAttestFailed, ErrAttestationFailed},
		{"AttestUnsupported", phoneproto.ErrorCodeAttestUnsupported, ErrProtocolError},
		{"OperationDenied", phoneproto.ErrorCodeOperationDenied, ErrProtocolError},
		{"InvalidPublicKey", phoneproto.ErrorCodeInvalidPublicKey, ErrInvalidPublicKey},
		{"DecryptFailed", phoneproto.ErrorCodeDecryptFailed, ErrProtocolError},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rpcErr := &phoneproto.RPCError{Code: tc.code, Message: tc.name}
			err := mapRPCError(rpcErr)
			if err != tc.expected {
				t.Errorf("expected %v, got %v", tc.expected, err)
			}
		})
	}
}

// --- mapKeyInfoToAttributes ---

func TestMapKeyInfoToAttributes(t *testing.T) {
	info := &phoneproto.KeyInfo{
		KeyID:     "my-key",
		Algorithm: "ES256",
		KeyType:   "signing",
	}

	attrs := mapKeyInfoToAttributes(info)
	if attrs.CN != "my-key" {
		t.Errorf("expected CN my-key, got %s", attrs.CN)
	}
	if attrs.StoreType != types.StorePhone {
		t.Errorf("expected StorePhone, got %v", attrs.StoreType)
	}
	if attrs.KeyAlgorithm != x509.ECDSA {
		t.Errorf("expected ECDSA for ES256, got %v", attrs.KeyAlgorithm)
	}
	if attrs.ECCAttributes == nil {
		t.Error("expected non-nil ECCAttributes for ES256")
	}
}

func TestMapKeyInfoToAttributes_RSA(t *testing.T) {
	info := &phoneproto.KeyInfo{
		KeyID:       "rsa-key",
		Algorithm:   "RS256",
		KeyType:     "encryption",
		KeySizeBits: 4096,
	}

	attrs := mapKeyInfoToAttributes(info)
	if attrs.KeyAlgorithm != x509.RSA {
		t.Errorf("expected RSA, got %v", attrs.KeyAlgorithm)
	}
	if attrs.RSAAttributes == nil {
		t.Fatal("expected non-nil RSAAttributes for RS256")
	}
	if attrs.RSAAttributes.KeySize != 4096 {
		t.Errorf("expected key size 4096, got %d", attrs.RSAAttributes.KeySize)
	}
	if attrs.KeyType != types.KeyTypeEncryption {
		t.Errorf("expected KeyTypeEncryption, got %v", attrs.KeyType)
	}
}

func TestMapKeyInfoToAttributes_UnknownAlgorithm(t *testing.T) {
	info := &phoneproto.KeyInfo{
		KeyID:     "unknown-key",
		Algorithm: "UNKNOWN-ALG",
		KeyType:   "unknown-type",
	}

	attrs := mapKeyInfoToAttributes(info)
	if attrs.KeyAlgorithm != x509.UnknownPublicKeyAlgorithm {
		t.Errorf("expected UnknownPublicKeyAlgorithm, got %v", attrs.KeyAlgorithm)
	}
	if attrs.KeyType != types.KeyTypeSigning {
		t.Errorf("expected default KeyTypeSigning, got %v", attrs.KeyType)
	}
}

// --- mapKeyType ---

func TestMapKeyType_AllTypes(t *testing.T) {
	tests := []struct {
		input    string
		expected types.KeyType
	}{
		{"signing", types.KeyTypeSigning},
		{"encryption", types.KeyTypeEncryption},
		{"tls", types.KeyTypeTLS},
		{"hmac", types.KeyTypeHMAC},
		{"fido2", types.KeyTypeSigning},
		{"ssh", types.KeyTypeSigning},
		{"unknown", types.KeyTypeSigning},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			result := mapKeyType(tc.input)
			if result != tc.expected {
				t.Errorf("mapKeyType(%q) = %v, want %v", tc.input, result, tc.expected)
			}
		})
	}
}

// --- mapAlgorithmToAttributes ---

func TestMapAlgorithmToAttributes(t *testing.T) {
	tests := []struct {
		algo     string
		keySize  int
		expectKA x509.PublicKeyAlgorithm
		expectEC bool
		expectRS bool
	}{
		{"ES256", 0, x509.ECDSA, true, false},
		{"ES384", 0, x509.ECDSA, true, false},
		{"ES512", 0, x509.ECDSA, true, false},
		{"RS256", 2048, x509.RSA, false, true},
		{"RS384", 4096, x509.RSA, false, true},
		{"RS512", 0, x509.RSA, false, true},
		{"EdDSA", 0, x509.Ed25519, false, false},
		{"UNKNOWN", 0, x509.UnknownPublicKeyAlgorithm, false, false},
	}

	for _, tc := range tests {
		t.Run(tc.algo, func(t *testing.T) {
			_, ka, ecc, rsaAttr := mapAlgorithmToAttributes(tc.algo, tc.keySize)
			if ka != tc.expectKA {
				t.Errorf("expected key algorithm %v, got %v", tc.expectKA, ka)
			}
			if (ecc != nil) != tc.expectEC {
				t.Errorf("expected ECCAttributes=%v, got %v", tc.expectEC, ecc != nil)
			}
			if (rsaAttr != nil) != tc.expectRS {
				t.Errorf("expected RSAAttributes=%v, got %v", tc.expectRS, rsaAttr != nil)
			}
		})
	}
}

func TestMapAlgorithmToAttributes_RSADefaultKeySize(t *testing.T) {
	_, _, _, rsaAttr := mapAlgorithmToAttributes("RS256", 0)
	if rsaAttr == nil {
		t.Fatal("expected non-nil RSAAttributes")
	}
	if rsaAttr.KeySize != 2048 {
		t.Errorf("expected default RSA key size 2048, got %d", rsaAttr.KeySize)
	}
}

// --- SenderFunc ---

func TestSenderFunc_ImplementsSender(t *testing.T) {
	var _ Sender = SenderFunc(nil) // Compile-time check

	called := false
	fn := SenderFunc(func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
		called = true
		return &phoneproto.Response{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  json.RawMessage(`{"status":"ok"}`),
		}, nil
	})

	req := phoneproto.NewRequest("test.method", nil)
	resp, err := fn.SendRequest(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, called)
	assert.Equal(t, req.ID, resp.ID)
}

func TestSenderFunc_ReturnsError(t *testing.T) {
	expectedErr := errors.New("sender error")
	fn := SenderFunc(func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
		return nil, expectedErr
	})

	req := phoneproto.NewRequest("test.method", nil)
	resp, err := fn.SendRequest(context.Background(), req)
	assert.ErrorIs(t, err, expectedErr)
	assert.Nil(t, resp)
}
