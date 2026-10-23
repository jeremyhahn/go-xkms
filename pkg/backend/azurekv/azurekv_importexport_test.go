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
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/Azure/azure-sdk-for-go/sdk/security/keyvault/azkeys"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/importtoken"
	"github.com/jeremyhahn/go-xkms/pkg/crypto/wrapping"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/testing/fipstest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGetImportParameters verifies the BYOK key-encryption key is
// provisioned and its public half returned, and that only the hybrid
// RSA+AES-KWP algorithms Azure Key Vault's key_hsm format requires are
// accepted.
func TestGetImportParameters(t *testing.T) {
	tests := []struct {
		name      string
		attrs     *types.KeyAttributes
		algorithm backend.WrappingAlgorithm
		wantErr   bool
	}{
		{
			name: "RSA with explicit key size",
			attrs: &types.KeyAttributes{
				CN:            "import-rsa",
				KeyAlgorithm:  x509.RSA,
				RSAAttributes: &types.RSAAttributes{KeySize: 3072},
			},
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
		},
		{
			name: "RSA default key spec",
			attrs: &types.KeyAttributes{
				CN:           "import-rsa-default",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
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
		{
			name: "plain RSA-OAEP refused: not a valid Azure key_hsm encoding",
			attrs: &types.KeyAttributes{
				CN:           "import-plain-oaep",
				KeyAlgorithm: x509.RSA,
			},
			algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
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
			rsaPub, ok := params.WrappingPublicKey.(*rsa.PublicKey)
			if !ok {
				t.Fatalf("GetImportParameters() WrappingPublicKey = %T, want *rsa.PublicKey", params.WrappingPublicKey)
			}
			if rsaPub.N == nil {
				t.Error("GetImportParameters() WrappingPublicKey has nil modulus")
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

// TestGetImportParameters_KEKCreatedAndReused verifies the BYOK
// key-encryption key is created on first use and reused -- not recreated --
// on every subsequent GetImportParameters call, including across different
// wrapping algorithms and target key attributes (go-xkms#1342).
func TestGetImportParameters_KEKCreatedAndReused(t *testing.T) {
	b, mockClient := testBackend(t)

	first, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN: "kek-reuse-1", KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() [1] error = %v", err)
	}

	second, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN: "kek-reuse-2", KeyAlgorithm: x509.ECDSA,
	}, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1)
	if err != nil {
		t.Fatalf("GetImportParameters() [2] error = %v", err)
	}

	if got := mockClient.CreateKeyCallCount(azureBYOKKEKName); got != 1 {
		t.Errorf("CreateKey(%s) called %d times, want exactly 1", azureBYOKKEKName, got)
	}

	firstPub, ok := first.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("first WrappingPublicKey = %T, want *rsa.PublicKey", first.WrappingPublicKey)
	}
	secondPub, ok := second.WrappingPublicKey.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("second WrappingPublicKey = %T, want *rsa.PublicKey", second.WrappingPublicKey)
	}
	if firstPub.N.Cmp(secondPub.N) != 0 {
		t.Error("GetImportParameters() returned different KEK public keys across calls, want the same reused KEK")
	}

	if _, exists := mockClient.keys[azureBYOKKEKName]; !exists {
		t.Errorf("mock vault does not contain the BYOK key-encryption key %q", azureBYOKKEKName)
	}
}

// TestWrapKey_InvalidInput verifies WrapKey rejects malformed callers and
// every wrapping algorithm other than the two hybrid RSA+AES-KWP algorithms
// Azure Key Vault's key_hsm format requires.
func TestWrapKey_InvalidInput(t *testing.T) {
	b, _ := testBackend(t)

	validParams, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
		CN:           "wrap-invalid",
		KeyAlgorithm: x509.RSA,
	}, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
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
		{
			name:        "plain RSA-OAEP refused",
			keyMaterial: []byte("data"),
			params: &backend.ImportParameters{
				WrappingPublicKey: validParams.WrappingPublicKey,
				Algorithm:         backend.WrappingAlgorithmRSAES_OAEP_SHA_256,
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

// TestWrapKey_RoundTripsAgainstKEK verifies WrapKey's output can be
// recovered with the shared wrapping package's UnwrapRSAAES using the mock
// KEK's private half -- standing in for Azure Key Vault's own HSM-side
// unwrap, which this backend never performs itself (UnwrapKey is
// unsupported; see TestUnwrapKey_Unsupported).
func TestWrapKey_RoundTripsAgainstKEK(t *testing.T) {
	b, mockClient := testBackend(t)

	algorithms := []backend.WrappingAlgorithm{
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256,
	}

	for _, alg := range algorithms {
		t.Run(string(alg), func(t *testing.T) {
			params, err := b.GetImportParameters(context.Background(), &types.KeyAttributes{
				CN: "wrap-roundtrip", KeyAlgorithm: x509.RSA,
			}, alg)
			if err != nil {
				t.Fatalf("GetImportParameters() error = %v", err)
			}

			keyMaterial := []byte("super-secret-key-material-1234567890")
			wrapped, err := b.WrapKey(context.Background(), keyMaterial, params)
			// The stdlib refuses SHA-1 in RSA-OAEP under fips140=only.
			if alg == backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1 && !fipstest.OutsideFIPSAfterRefusal(t, err, nil) {
				return
			}
			if err != nil {
				t.Fatalf("WrapKey() error = %v", err)
			}
			if len(wrapped.WrappedKey) == 0 {
				t.Fatal("WrapKey() returned empty wrapped key")
			}
			if bytes.Contains(wrapped.WrappedKey, keyMaterial) {
				t.Error("WrapKey() output contains the plaintext key material")
			}

			kekPriv, ok := mockClient.keys[azureBYOKKEKName].privateKey.(*rsa.PrivateKey)
			if !ok {
				t.Fatalf("mock KEK private key = %T, want *rsa.PrivateKey", mockClient.keys[azureBYOKKEKName].privateKey)
			}
			unwrapped, err := wrapping.UnwrapRSAAES(wrapped.WrappedKey, kekPriv, alg)
			if err != nil {
				t.Fatalf("unwrap against mock KEK private key failed: %v", err)
			}
			if !bytes.Equal(unwrapped, keyMaterial) {
				t.Errorf("unwrapped = %q, want %q", unwrapped, keyMaterial)
			}
		})
	}
}

// TestUnwrapKey_Unsupported verifies UnwrapKey always reports
// backend.ErrNotSupported: Azure Key Vault's HSM performs the unwrap
// itself, using the key-encryption key's private half, which never leaves
// the HSM boundary (go-xkms#1342).
func TestUnwrapKey_Unsupported(t *testing.T) {
	b, _ := testBackend(t)

	_, err := b.UnwrapKey(context.Background(), &backend.WrappedKeyMaterial{WrappedKey: []byte("x")}, &backend.ImportParameters{})
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("UnwrapKey() error = %v, want ErrNotSupported", err)
	}
}

// TestImportKey_RSA verifies the full native-BYOK round trip for an RSA
// private key: the wrapped blob -- never the plaintext key -- is sent to
// Azure Key Vault as the JWK key_hsm (T) field, alongside the KEK's kid
// implicitly (via HSM: true) and no plaintext key component.
func TestImportKey_RSA(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:           "imported-rsa-key",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
	}

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

	importedName, importedParams := mockClient.LastImportKey()
	if importedName != attrs.CN {
		t.Errorf("ImportKey() imported under name %q, want %q", importedName, attrs.CN)
	}
	if importedParams.HSM == nil || !*importedParams.HSM {
		t.Error("ImportKey() did not set HSM: true")
	}
	jwk := importedParams.Key
	if jwk == nil {
		t.Fatal("ImportKey() sent a nil JWK")
	}
	if jwk.Kty == nil || *jwk.Kty != azkeys.KeyTypeRSAHSM {
		t.Errorf("ImportKey() JWK Kty = %v, want RSA-HSM", jwk.Kty)
	}
	if len(jwk.T) == 0 {
		t.Error("ImportKey() JWK key_hsm (T) is empty")
	}
	if !bytes.Equal(jwk.T, wrapped.WrappedKey) {
		t.Error("ImportKey() JWK key_hsm (T) does not match the wrapped blob")
	}
	if bytes.Contains(jwk.T, keyBytes) {
		t.Error("ImportKey() key_hsm blob contains the plaintext key material")
	}
	if jwk.N != nil || jwk.D != nil || jwk.P != nil || jwk.Q != nil {
		t.Error("ImportKey() set a plaintext RSA key component on the JWK")
	}

	hasMetadata, err := storage.KeyExists(context.Background(), b.config.KeyStorage, attrs.CN)
	if err != nil {
		t.Fatalf("storage.KeyExists() error = %v", err)
	}
	if !hasMetadata {
		t.Error("ImportKey() did not store metadata")
	}

	if _, peekErr := b.importTokens.Peek(string(params.ImportToken)); peekErr == nil {
		t.Error("ImportKey() did not consume the single-use import token")
	}
}

// TestImportKey_ECDSA mirrors TestImportKey_RSA for the ECDSA branch, which
// uses a different Kty (EC-HSM) and requires Crv to be set since Azure
// cannot recover the curve from an opaque key_hsm blob.
func TestImportKey_ECDSA(t *testing.T) {
	b, mockClient := testBackend(t)

	attrs := &types.KeyAttributes{
		CN:            "imported-ecdsa-key",
		KeyType:       backend.KEY_TYPE_SIGNING,
		StoreType:     backend.STORE_AZUREKV,
		KeyAlgorithm:  x509.ECDSA,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P384()},
	}

	params, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("GetImportParameters() error = %v", err)
	}

	ecKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
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

	_, importedParams := mockClient.LastImportKey()
	jwk := importedParams.Key
	if jwk == nil {
		t.Fatal("ImportKey() sent a nil JWK")
	}
	if jwk.Crv == nil || *jwk.Crv != azkeys.CurveNameP384 {
		t.Errorf("ImportKey() JWK Crv = %v, want P-384", jwk.Crv)
	}
	if jwk.D != nil || jwk.X != nil || jwk.Y != nil {
		t.Error("ImportKey() set a plaintext EC key component on the JWK")
	}
}

// TestImportKey_WrongAlgorithmRefused verifies ImportKey refuses key
// material presented under a different wrapping algorithm than the one the
// token was issued for, before ever touching the vault (go-xkms#1342).
func TestImportKey_WrongAlgorithmRefused(t *testing.T) {
	b, _ := testBackend(t)

	attrs := &types.KeyAttributes{CN: "wrong-alg", KeyAlgorithm: x509.RSA}
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

	// Claim a different algorithm than the token was issued for.
	wrapped.Algorithm = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1

	err = b.ImportKey(context.Background(), attrs, wrapped)
	if err == nil {
		t.Fatal("ImportKey() expected error for mismatched algorithm, got nil")
	}
	var mismatch *importtoken.AlgorithmMismatchError
	if !errors.As(err, &mismatch) {
		t.Errorf("ImportKey() error = %v (%T), want *importtoken.AlgorithmMismatchError", err, err)
	}
	if !errors.Is(err, backend.ErrInvalidAlgorithm) {
		t.Errorf("ImportKey() error does not satisfy errors.Is(err, backend.ErrInvalidAlgorithm): %v", err)
	}
}

// TestImportKey_TokenSingleUse verifies a second ImportKey call against the
// same wrapped key material and token is refused once the first call has
// consumed it -- whether the first call succeeded or not.
func TestImportKey_TokenSingleUse(t *testing.T) {
	b, _ := testBackend(t)

	attrs := &types.KeyAttributes{CN: "single-use", KeyAlgorithm: x509.RSA}
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
		t.Fatalf("ImportKey() [1] error = %v", err)
	}

	attrs2 := &types.KeyAttributes{CN: "single-use-replay", KeyAlgorithm: x509.RSA}
	err = b.ImportKey(context.Background(), attrs2, wrapped)
	if !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("ImportKey() [2, replay] error = %v, want ErrKeyNotFound", err)
	}
}

// TestImportKey_InvalidInput verifies ImportKey's guard clauses: an unknown
// or missing import token, and an unsupported key algorithm, are all
// refused. Both a missing/expired token and an unsupported algorithm are
// exercised: the former never reaches the vault, the latter is caught after
// the (now-consumed) token is validated, matching UnwrapKey's replacement
// by native binding checks (go-xkms#1342).
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
			name:    "unknown import token",
			attrs:   validAttrs,
			wrapped: &backend.WrappedKeyMaterial{ImportToken: []byte("not-a-handle"), WrappedKey: []byte("x"), Algorithm: backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := b.ImportKey(context.Background(), tt.attrs, tt.wrapped); err == nil {
				t.Error("ImportKey() expected error, got nil")
			}
		})
	}

	// Unsupported key algorithm, exercised last since it consumes the
	// token.
	t.Run("unsupported key algorithm", func(t *testing.T) {
		badAttrs := &types.KeyAttributes{CN: "import-invalid-alg", KeyAlgorithm: x509.Ed25519}
		if err := b.ImportKey(context.Background(), badAttrs, wrapped); err == nil {
			t.Error("ImportKey() expected error, got nil")
		}
	})
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
