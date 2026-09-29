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

//go:build azurekv

package azurekv

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGetImportParameters verifies wrapping-key material generation and
// wrapping-algorithm validation, since a caller that reaches ImportKey with
// an unsupported algorithm or a nil key spec would silently fail Azure's
// import contract.
func TestGetImportParameters(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		wantErr   bool
	}{
		{
			name: "RSA OAEP SHA256 with explicit key size",
			attrs: &types.KeyAttributes{
				CN:            "import-rsa",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 3072},
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		},
		{
			name: "RSA default key spec",
			attrs: &types.KeyAttributes{
				CN:           "import-rsa-default",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		},
		{
			name: "ECDSA with explicit curve",
			attrs: &types.KeyAttributes{
				CN:            "import-ecdsa",
				KeyAlgorithm:  x509.ECDSA,
				ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
			},
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		},
		{
			name: "ECDSA default key spec",
			attrs: &types.KeyAttributes{
				CN:           "import-ecdsa-default",
				KeyAlgorithm: x509.ECDSA,
			},
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		},
		{
			name:    "nil attributes",
			attrs:   nil,
			wantErr: true,
		},
		{
			name: "unsupported wrapping algorithm",
			attrs: &types.KeyAttributes{
				CN:           "import-bad-alg",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: types.KeyWrapAlgorithm("unsupported"),
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, _ := testBackend(t)

			params, err := b.GetImportParameters(context.Background(), tt.attrs, tt.algorithm)
			if tt.wantErr {
				if err == nil {
					t.Fatal("GetImportParameters() expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("GetImportParameters() unexpected error = %v", err)
			}
			if params.WrappingPublicKey == nil {
				t.Error("GetImportParameters() WrappingPublicKey is nil")
			}
			if len(params.ImportToken) == 0 {
				t.Error("GetImportParameters() ImportToken is empty")
			}
			if params.KeySpec == "" {
				t.Error("GetImportParameters() KeySpec is empty")
			}
			if params.ExpiresAt == nil {
				t.Error("GetImportParameters() ExpiresAt is nil")
			}
		})
	}
}

// TestWrapUnwrapKeyRoundTrip verifies that key material wrapped with
// WrapKey can be recovered with UnwrapKey for every supported algorithm,
// pinning the local (non-Azure) wrapping contract WrapKey/UnwrapKey promise.
func TestWrapUnwrapKeyRoundTrip(t *testing.T) {
	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSAES_OAEP_SHA_1,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			b, _ := testBackend(t)

			params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
				CN:           "wrap-key",
				KeyAlgorithm: x509.RSA,
			}, alg)
			if err != nil {
				t.Fatalf("GetImportParameters() error = %v", err)
			}

			keyMaterial := []byte("super-secret-key-material-1234567890")
			wrapped, err := b.WrapKey(context.Background(), keyMaterial, params)
			if err != nil {
				t.Fatalf("WrapKey() error = %v", err)
			}
			if len(wrapped.WrappedKey) == 0 {
				t.Fatal("WrapKey() returned empty wrapped key")
			}

			unwrapped, err := b.UnwrapKey(context.Background(), wrapped, params)
			if err != nil {
				t.Fatalf("UnwrapKey() error = %v", err)
			}
			if string(unwrapped) != string(keyMaterial) {
				t.Errorf("UnwrapKey() = %q, want %q", unwrapped, keyMaterial)
			}
		})
	}
}

// TestWrapKey_InvalidInput verifies WrapKey rejects malformed callers before
// touching any cryptographic material.
func TestWrapKey_InvalidInput(t *testing.T) {
	b, _ := testBackend(t)

	validParams, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN:           "wrap-invalid",
		KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	tests := []struct {
		name        string
		keyMaterial []byte
		params      *backend.ImportParameters
	}{
		{name: "empty key material", keyMaterial: nil, params: validParams},
		{name: "nil params", keyMaterial: []byte("data"), params: nil},
		{
			name:        "nil wrapping public key",
			keyMaterial: []byte("data"),
			params:      &backend.ImportParameters{WrappingPublicKey: nil},
		},
		{
			name:        "non-RSA wrapping public key",
			keyMaterial: []byte("data"),
			params: &backend.ImportParameters{
				WrappingPublicKey: &ecdsa.PublicKey{Curve: elliptic.P256()},
			},
		},
		{
			name:        "unsupported wrapping algorithm",
			keyMaterial: []byte("data"),
			params: &backend.ImportParameters{
				WrappingPublicKey: validParams.WrappingPublicKey,
				Algorithm:         types.KeyWrapAlgorithm("unsupported"),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := b.WrapKey(context.Background(), tt.keyMaterial, tt.params); err == nil {
				t.Error("WrapKey() expected error, got nil")
			}
		})
	}
}

// TestUnwrapKey_InvalidInput verifies UnwrapKey rejects malformed callers
// and corrupt import tokens.
func TestUnwrapKey_InvalidInput(t *testing.T) {
	b, _ := testBackend(t)

	tests := []struct {
		name    string
		wrapped *backend.WrappedKeyMaterial
		params  *backend.ImportParameters
	}{
		{name: "nil wrapped", wrapped: nil, params: &backend.ImportParameters{}},
		{name: "nil params", wrapped: &backend.WrappedKeyMaterial{ImportToken: []byte("x")}, params: nil},
		{
			name:    "missing import token",
			wrapped: &backend.WrappedKeyMaterial{},
			params:  &backend.ImportParameters{},
		},
		{
			name:    "corrupt import token",
			wrapped: &backend.WrappedKeyMaterial{ImportToken: []byte("not-a-key"), WrappedKey: []byte("x")},
			params:  &backend.ImportParameters{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := b.UnwrapKey(context.Background(), tt.wrapped, tt.params); err == nil {
				t.Error("UnwrapKey() expected error, got nil")
			}
		})
	}

	// Valid token, unsupported wrapping algorithm.
	params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN: "unwrap-bad-alg", KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}
	wrapped := &backend.WrappedKeyMaterial{
		ImportToken: params.ImportToken,
		WrappedKey:  []byte("irrelevant"),
		Algorithm:   types.KeyWrapAlgorithm("unsupported"),
	}
	if _, err := b.UnwrapKey(context.Background(), wrapped, params); err == nil {
		t.Error("UnwrapKey() expected error for unsupported algorithm, got nil")
	}
}

// TestImportKey_RSA verifies the full local-wrap -> ImportKey round trip for
// an RSA private key, exercising importRSAKey end to end against the mock
// Key Vault client.
func TestImportKey_RSA(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "imported-rsa-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

	// RSA private-key material (PKCS#8) exceeds plain RSA-OAEP's payload
	// limit for a 2048-bit wrapping key, so the hybrid RSA+AES-KWP
	// algorithm is required here, exactly as the production doc comment
	// on WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 states.
	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}

	wrapped, err := b.WrapKey(context.Background(), keyBytes, params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	if err := b.ImportKey(context.Background(), attrs, wrapped); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if _, exists := mockClient.keys[attrs.CN]; !exists {
		t.Error("ImportKey() did not create key in mock vault")
	}

	hasMetadata, err := storage.KeyExists(context.Background(), b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	_, peekErr := b.importTokens.Peek("import-token-" + attrs.CN)
	hasImportToken := peekErr == nil
	if !hasMetadata {
		t.Error("ImportKey() did not store metadata")
	}
	if hasImportToken {
		t.Error("ImportKey() did not clean up the temporary import token")
	}
}

// TestImportKey_ECDSA mirrors TestImportKey_RSA for the ECDSA branch
// (importECDSAKey), which uses a different private-key parser and JWK shape.
func TestImportKey_ECDSA(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "imported-ecdsa-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.ECDSA,
	}

	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ecdsa.GenerateKey() error = %v", err)
	}
	keyBytes, err := x509.MarshalECPrivateKey(ecKey)
	if err != nil {
		t.Fatalf("MarshalECPrivateKey() error = %v", err)
	}

	wrapped, err := b.WrapKey(context.Background(), keyBytes, params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	if err := b.ImportKey(context.Background(), attrs, wrapped); err != nil {
		t.Fatalf("ImportKey() error = %v", err)
	}

	if _, exists := mockClient.keys[attrs.CN]; !exists {
		t.Error("ImportKey() did not create key in mock vault")
	}
}

// TestImportKey_InvalidInput verifies ImportKey's guard clauses and its
// rejection of an unsupported key algorithm after a successful unwrap.
func TestImportKey_InvalidInput(t *testing.T) {
	b, _ := testBackend(t)

	validAttrs := &types.KeyAttributes{CN: "import-invalid", KeyAlgorithm: x509.RSA}
	params, err := b.GetImportParameters(context.Background(), validAttrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey() error = %v", err)
	}
	keyBytes, err := x509.MarshalPKCS8PrivateKey(rsaKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey() error = %v", err)
	}
	wrapped, err := b.WrapKey(context.Background(), keyBytes, params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	tests := []struct {
		name    string
		attrs   *types.KeyAttributes
		wrapped *backend.WrappedKeyMaterial
	}{
		{name: "nil attrs", attrs: nil, wrapped: wrapped},
		{name: "nil wrapped", attrs: validAttrs, wrapped: nil},
		{name: "missing import token", attrs: validAttrs, wrapped: &backend.WrappedKeyMaterial{WrappedKey: wrapped.WrappedKey}},
		{name: "empty wrapped key", attrs: validAttrs, wrapped: &backend.WrappedKeyMaterial{ImportToken: wrapped.ImportToken}},
		{
			name:    "unsupported key algorithm",
			attrs:   &types.KeyAttributes{CN: "import-invalid-alg", KeyAlgorithm: x509.Ed25519},
			wrapped: wrapped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := b.ImportKey(context.Background(), tt.attrs, tt.wrapped); err == nil {
				t.Error("ImportKey() expected error, got nil")
			}
		})
	}
}

// TestImportRSAKey_ParseFailure verifies importRSAKey surfaces a parse
// error instead of silently importing garbage key material.
func TestImportRSAKey_ParseFailure(t *testing.T) {
	b, _ := testBackend(t)

	params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN: "bad-rsa", KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	wrapped, err := b.WrapKey(context.Background(), []byte("not a valid private key"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "bad-rsa", KeyAlgorithm: x509.RSA}
	if err := b.ImportKey(context.Background(), attrs, wrapped); err == nil {
		t.Error("ImportKey() expected parse error, got nil")
	}
}

// TestImportECDSAKey_ParseFailure mirrors TestImportRSAKey_ParseFailure for
// the ECDSA import path.
func TestImportECDSAKey_ParseFailure(t *testing.T) {
	b, _ := testBackend(t)

	params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN: "bad-ecdsa", KeyAlgorithm: x509.ECDSA,
	}, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	wrapped, err := b.WrapKey(context.Background(), []byte("not a valid private key"), params)
	if err != nil {
		t.Fatalf("WrapKey() error = %v", err)
	}

	attrs := &types.KeyAttributes{CN: "bad-ecdsa", KeyAlgorithm: x509.ECDSA}
	if err := b.ImportKey(context.Background(), attrs, wrapped); err == nil {
		t.Error("ImportKey() expected parse error, got nil")
	}
}

// TestExportKey verifies Azure Key Vault reports export as unsupported
// (Capabilities().Export is always false), rather than silently succeeding.
func TestExportKey(t *testing.T) {
	b, _ := testBackend(t)

	if _, err := b.ExportKey(context.Background(), nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKey(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}

	attrs := &types.KeyAttributes{CN: "export-key", KeyAlgorithm: x509.RSA}
	if _, err := b.ExportKey(context.Background(), attrs, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ExportKey() error = %v, want ErrNotSupported", err)
	}
}

// TestExportKeyTo verifies ExportKeyTo's guard clauses and its unconditional
// ErrExportToUnsupported result.
func TestExportKeyTo(t *testing.T) {
	b, _ := testBackend(t)

	if _, err := b.ExportKeyTo(context.Background(), nil, &backend.ImportParameters{}); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}

	attrs := &types.KeyAttributes{CN: "export-to-key", KeyAlgorithm: x509.RSA}
	if _, err := b.ExportKeyTo(context.Background(), attrs, nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyTo(nil dstParams) error = %v, want ErrInvalidAttributes", err)
	}

	if _, err := b.ExportKeyTo(context.Background(), attrs, &backend.ImportParameters{}); !errors.Is(err, backend.ErrExportToUnsupported) {
		t.Errorf("ExportKeyTo() error = %v, want ErrExportToUnsupported", err)
	}
}

// TestExportKeyMaterial verifies ExportKeyMaterial's guard clause and its
// unconditional ErrNotSupported result (Azure Key Vault never releases raw
// key material).
func TestExportKeyMaterial(t *testing.T) {
	b, _ := testBackend(t)

	if _, err := b.ExportKeyMaterial(context.Background(), nil); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKeyMaterial(nil attrs) error = %v, want ErrInvalidAttributes", err)
	}

	attrs := &types.KeyAttributes{CN: "export-material-key", KeyAlgorithm: x509.RSA}
	if _, err := b.ExportKeyMaterial(context.Background(), attrs); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ExportKeyMaterial() error = %v, want ErrNotSupported", err)
	}
}
