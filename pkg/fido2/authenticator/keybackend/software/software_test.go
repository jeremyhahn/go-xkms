// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package software

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/jeremyhahn/go-keychain/pkg/fido2/authenticator/keybackend"
)

// toInt converts various integer types from CBOR decoding to int.
// CBOR decodes positive integers as uint64 and negative as int64.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int8:
		return int(n), true
	case int16:
		return int(n), true
	case int32:
		return int(n), true
	case int64:
		return int(n), true
	case uint:
		return int(n), true
	case uint8:
		return int(n), true
	case uint16:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	default:
		return 0, false
	}
}

// TestNewSoftwareKeyBackend tests creating a new software key backend.
func TestNewSoftwareKeyBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	if backend == nil {
		t.Fatal("NewSoftwareKeyBackend returned nil")
	}

	if backend.keys == nil {
		t.Error("keys map is nil")
	}

	if backend.closed.Load() {
		t.Error("backend should not be closed on creation")
	}
}

// TestSoftwareKeyBackend_Type tests the Type method.
func TestSoftwareKeyBackend_Type(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	backendType := backend.Type()
	if backendType != keybackend.BackendTypeSoftware {
		t.Errorf("Type() = %q, want %q", backendType, keybackend.BackendTypeSoftware)
	}
}

// TestSoftwareKeyBackend_Capabilities tests the Capabilities method.
func TestSoftwareKeyBackend_Capabilities(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	caps := backend.Capabilities()

	// Check supported algorithms
	expectedAlgs := []int{COSEAlgES256, COSEAlgES384, COSEAlgES512, COSEAlgEdDSA}
	if len(caps.SupportedAlgorithms) != len(expectedAlgs) {
		t.Errorf("SupportedAlgorithms len = %d, want %d",
			len(caps.SupportedAlgorithms), len(expectedAlgs))
	}

	algSet := make(map[int]bool)
	for _, alg := range caps.SupportedAlgorithms {
		algSet[alg] = true
	}

	for _, alg := range expectedAlgs {
		if !algSet[alg] {
			t.Errorf("missing supported algorithm %d", alg)
		}
	}

	if !caps.SupportsExport {
		t.Error("SupportsExport = false, want true")
	}

	if !caps.SupportsImport {
		t.Error("SupportsImport = false, want true")
	}

	if caps.SupportsAttestation {
		t.Error("SupportsAttestation = true, want false")
	}

	if caps.HardwareBacked {
		t.Error("HardwareBacked = true, want false")
	}
}

// TestSoftwareKeyBackend_GenerateCredentialKey tests key generation for
// all supported algorithms.
func TestSoftwareKeyBackend_GenerateCredentialKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
		keyType   int
		curve     int
	}{
		{
			name:      "ES256",
			algorithm: COSEAlgES256,
			keyType:   COSEKeyTypeEC2,
			curve:     COSECurveP256,
		},
		{
			name:      "ES384",
			algorithm: COSEAlgES384,
			keyType:   COSEKeyTypeEC2,
			curve:     COSECurveP384,
		},
		{
			name:      "ES512",
			algorithm: COSEAlgES512,
			keyType:   COSEKeyTypeEC2,
			curve:     COSECurveP521,
		},
		{
			name:      "EdDSA",
			algorithm: COSEAlgEdDSA,
			keyType:   COSEKeyTypeOKP,
			curve:     COSECurveEd25519,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := NewSoftwareKeyBackend()
			defer func() { _ = backend.Close() }()

			credentialID := make([]byte, 32)
			if _, err := rand.Read(credentialID); err != nil {
				t.Fatalf("rand.Read failed: %v", err)
			}

			handle, publicKeyCOSE, err := backend.GenerateCredentialKey(tt.algorithm, credentialID)
			if err != nil {
				t.Fatalf("GenerateCredentialKey failed: %v", err)
			}

			if handle == nil {
				t.Fatal("handle is nil")
			}

			if len(publicKeyCOSE) == 0 {
				t.Fatal("publicKeyCOSE is empty")
			}

			// Verify credential ID
			if !bytes.Equal(handle.CredentialID(), credentialID) {
				t.Error("credential ID mismatch")
			}

			// Verify algorithm
			if handle.Algorithm() != tt.algorithm {
				t.Errorf("Algorithm() = %d, want %d", handle.Algorithm(), tt.algorithm)
			}

			// Verify COSE key structure
			var coseKey map[int]interface{}
			if err := cbor.Unmarshal(publicKeyCOSE, &coseKey); err != nil {
				t.Fatalf("failed to unmarshal COSE key: %v", err)
			}

			// Verify key type (kty)
			ktyVal, ok := coseKey[1]
			if !ok {
				t.Fatal("COSE key missing kty (1)")
			}
			kty, ok := toInt(ktyVal)
			if !ok {
				t.Fatalf("kty is not an integer: %T", ktyVal)
			}
			if kty != tt.keyType {
				t.Errorf("kty = %d, want %d", kty, tt.keyType)
			}

			// Verify algorithm
			algVal, ok := coseKey[3]
			if !ok {
				t.Fatal("COSE key missing alg (3)")
			}
			alg, ok := toInt(algVal)
			if !ok {
				t.Fatalf("alg is not an integer: %T", algVal)
			}
			if alg != tt.algorithm {
				t.Errorf("alg = %d, want %d", alg, tt.algorithm)
			}

			// Verify curve
			crvVal, ok := coseKey[-1]
			if !ok {
				t.Fatal("COSE key missing crv (-1)")
			}
			crv, ok := toInt(crvVal)
			if !ok {
				t.Fatalf("crv is not an integer: %T", crvVal)
			}
			if crv != tt.curve {
				t.Errorf("crv = %d, want %d", crv, tt.curve)
			}

			// Verify x coordinate present
			x, ok := coseKey[-2]
			if !ok {
				t.Fatal("COSE key missing x (-2)")
			}
			if len(x.([]byte)) == 0 {
				t.Error("x coordinate is empty")
			}
		})
	}
}

// TestSoftwareKeyBackend_GenerateCredentialKey_UnsupportedAlgorithm tests
// that unsupported algorithms return an error.
func TestSoftwareKeyBackend_GenerateCredentialKey_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	// Test with unsupported algorithm
	handle, publicKey, err := backend.GenerateCredentialKey(-999, credentialID)

	if err != keybackend.ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}

	if publicKey != nil {
		t.Error("expected nil publicKey")
	}
}

// TestSoftwareKeyBackend_GenerateCredentialKey_EmptyCredentialID tests
// that empty credential ID returns an error.
func TestSoftwareKeyBackend_GenerateCredentialKey_EmptyCredentialID(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	handle, publicKey, err := backend.GenerateCredentialKey(COSEAlgES256, []byte{})

	if err != keybackend.ErrInvalidCredentialID {
		t.Errorf("expected ErrInvalidCredentialID, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}

	if publicKey != nil {
		t.Error("expected nil publicKey")
	}

	// Test with nil credential ID
	_, _, err = backend.GenerateCredentialKey(COSEAlgES256, nil)

	if err != keybackend.ErrInvalidCredentialID {
		t.Errorf("expected ErrInvalidCredentialID for nil, got %v", err)
	}
}

// TestSoftwareKeyBackend_GenerateCredentialKey_ClosedBackend tests
// that operations on a closed backend return an error.
func TestSoftwareKeyBackend_GenerateCredentialKey_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	_ = backend.Close()

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	handle, publicKey, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}

	if publicKey != nil {
		t.Error("expected nil publicKey")
	}
}

// TestSoftwareKeyBackend_Sign tests signing operations for all algorithms.
func TestSoftwareKeyBackend_Sign(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
	}{
		{name: "ES256", algorithm: COSEAlgES256},
		{name: "ES384", algorithm: COSEAlgES384},
		{name: "ES512", algorithm: COSEAlgES512},
		{name: "EdDSA", algorithm: COSEAlgEdDSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := NewSoftwareKeyBackend()
			defer func() { _ = backend.Close() }()

			credentialID := make([]byte, 32)
			if _, err := rand.Read(credentialID); err != nil {
				t.Fatalf("rand.Read failed: %v", err)
			}

			handle, _, err := backend.GenerateCredentialKey(tt.algorithm, credentialID)
			if err != nil {
				t.Fatalf("GenerateCredentialKey failed: %v", err)
			}

			data := []byte("test data to sign")

			signature, err := backend.Sign(handle, tt.algorithm, data)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if len(signature) == 0 {
				t.Error("signature is empty")
			}

			// Verify signature is valid by re-signing and checking format
			signature2, err := backend.Sign(handle, tt.algorithm, data)
			if err != nil {
				t.Fatalf("second Sign failed: %v", err)
			}

			// ECDSA signatures are non-deterministic, so they should differ
			// EdDSA signatures are deterministic, so they should match
			if tt.algorithm == COSEAlgEdDSA {
				if !bytes.Equal(signature, signature2) {
					t.Error("EdDSA signatures should be deterministic")
				}
			}
		})
	}
}

// TestSoftwareKeyBackend_Sign_UnsupportedAlgorithm tests signing with
// an unsupported algorithm.
func TestSoftwareKeyBackend_Sign_UnsupportedAlgorithm(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("rand.Read failed: %v", err)
	}

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	signature, err := backend.Sign(handle, -999, []byte("data"))

	if err != keybackend.ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}

	if signature != nil {
		t.Error("expected nil signature")
	}
}

// TestSoftwareKeyBackend_Sign_InvalidHandle tests signing with an invalid handle.
func TestSoftwareKeyBackend_Sign_InvalidHandle(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	// Create a fake handle that doesn't implement the internal type
	fakeHandle := &fakeKeyHandle{credID: []byte("fake"), alg: COSEAlgES256}

	signature, err := backend.Sign(fakeHandle, COSEAlgES256, []byte("data"))

	if err != keybackend.ErrInvalidKeyHandle {
		t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
	}

	if signature != nil {
		t.Error("expected nil signature")
	}
}

// TestSoftwareKeyBackend_Sign_ClosedBackend tests signing on a closed backend.
func TestSoftwareKeyBackend_Sign_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	_ = backend.Close()

	signature, err := backend.Sign(handle, COSEAlgES256, []byte("data"))

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}

	if signature != nil {
		t.Error("expected nil signature")
	}
}

// TestSoftwareKeyBackend_LoadKey tests loading a key by credential ID.
func TestSoftwareKeyBackend_LoadKey(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	originalHandle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	loadedHandle, err := backend.LoadKey(credentialID, COSEAlgES256)
	if err != nil {
		t.Fatalf("LoadKey failed: %v", err)
	}

	if loadedHandle == nil {
		t.Fatal("loadedHandle is nil")
	}

	if !bytes.Equal(loadedHandle.CredentialID(), originalHandle.CredentialID()) {
		t.Error("credential ID mismatch")
	}

	if loadedHandle.Algorithm() != originalHandle.Algorithm() {
		t.Error("algorithm mismatch")
	}
}

// TestSoftwareKeyBackend_LoadKey_NotFound tests loading a non-existent key.
func TestSoftwareKeyBackend_LoadKey_NotFound(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, err := backend.LoadKey(credentialID, COSEAlgES256)

	if err != keybackend.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}
}

// TestSoftwareKeyBackend_LoadKey_WrongAlgorithm tests loading a key with
// the wrong algorithm.
func TestSoftwareKeyBackend_LoadKey_WrongAlgorithm(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	_, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	// Try to load with wrong algorithm
	handle, err := backend.LoadKey(credentialID, COSEAlgEdDSA)

	if err != keybackend.ErrUnsupportedAlgorithm {
		t.Errorf("expected ErrUnsupportedAlgorithm, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}
}

// TestSoftwareKeyBackend_LoadKey_ClosedBackend tests loading on a closed backend.
func TestSoftwareKeyBackend_LoadKey_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	_, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	_ = backend.Close()

	handle, err := backend.LoadKey(credentialID, COSEAlgES256)

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}
}

// TestSoftwareKeyBackend_DeleteKey tests deleting a key.
func TestSoftwareKeyBackend_DeleteKey(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	err = backend.DeleteKey(handle)
	if err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	// Verify key is deleted
	_, err = backend.LoadKey(credentialID, COSEAlgES256)
	if err != keybackend.ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound after delete, got %v", err)
	}
}

// TestSoftwareKeyBackend_DeleteKey_InvalidHandle tests deleting with an
// invalid handle.
func TestSoftwareKeyBackend_DeleteKey_InvalidHandle(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	fakeHandle := &fakeKeyHandle{credID: []byte("fake"), alg: COSEAlgES256}

	err := backend.DeleteKey(fakeHandle)

	if err != keybackend.ErrInvalidKeyHandle {
		t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
	}
}

// TestSoftwareKeyBackend_DeleteKey_ClosedBackend tests deleting on a
// closed backend.
func TestSoftwareKeyBackend_DeleteKey_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	_ = backend.Close()

	err = backend.DeleteKey(handle)

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

// TestSoftwareKeyBackend_ExportPrivateKey tests exporting a private key.
func TestSoftwareKeyBackend_ExportPrivateKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
	}{
		{name: "ES256", algorithm: COSEAlgES256},
		{name: "ES384", algorithm: COSEAlgES384},
		{name: "ES512", algorithm: COSEAlgES512},
		{name: "EdDSA", algorithm: COSEAlgEdDSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := NewSoftwareKeyBackend()
			defer func() { _ = backend.Close() }()

			credentialID := make([]byte, 32)
			if _, err := rand.Read(credentialID); err != nil {
				t.Fatalf("rand.Read failed: %v", err)
			}

			handle, _, err := backend.GenerateCredentialKey(tt.algorithm, credentialID)
			if err != nil {
				t.Fatalf("GenerateCredentialKey failed: %v", err)
			}

			pkcs8Key, err := backend.ExportPrivateKey(handle)
			if err != nil {
				t.Fatalf("ExportPrivateKey failed: %v", err)
			}

			if len(pkcs8Key) == 0 {
				t.Error("pkcs8Key is empty")
			}

			// Verify PKCS#8 format by parsing
			parsedKey, err := x509.ParsePKCS8PrivateKey(pkcs8Key)
			if err != nil {
				t.Fatalf("failed to parse PKCS#8 key: %v", err)
			}

			switch tt.algorithm {
			case COSEAlgES256, COSEAlgES384, COSEAlgES512:
				if _, ok := parsedKey.(*ecdsa.PrivateKey); !ok {
					t.Error("expected ECDSA private key")
				}
			case COSEAlgEdDSA:
				if _, ok := parsedKey.(ed25519.PrivateKey); !ok {
					t.Error("expected Ed25519 private key")
				}
			}
		})
	}
}

// TestSoftwareKeyBackend_ExportPrivateKey_InvalidHandle tests exporting with
// an invalid handle.
func TestSoftwareKeyBackend_ExportPrivateKey_InvalidHandle(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	fakeHandle := &fakeKeyHandle{credID: []byte("fake"), alg: COSEAlgES256}

	pkcs8Key, err := backend.ExportPrivateKey(fakeHandle)

	if err != keybackend.ErrInvalidKeyHandle {
		t.Errorf("expected ErrInvalidKeyHandle, got %v", err)
	}

	if pkcs8Key != nil {
		t.Error("expected nil pkcs8Key")
	}
}

// TestSoftwareKeyBackend_ExportPrivateKey_ClosedBackend tests exporting on
// a closed backend.
func TestSoftwareKeyBackend_ExportPrivateKey_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	_ = backend.Close()

	pkcs8Key, err := backend.ExportPrivateKey(handle)

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}

	if pkcs8Key != nil {
		t.Error("expected nil pkcs8Key")
	}
}

// TestSoftwareKeyBackend_ImportPrivateKey tests importing a private key.
func TestSoftwareKeyBackend_ImportPrivateKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
		genKey    func() ([]byte, error)
	}{
		{
			name:      "ES256",
			algorithm: COSEAlgES256,
			genKey: func() ([]byte, error) {
				key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return x509.MarshalPKCS8PrivateKey(key)
			},
		},
		{
			name:      "ES384",
			algorithm: COSEAlgES384,
			genKey: func() ([]byte, error) {
				key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return x509.MarshalPKCS8PrivateKey(key)
			},
		},
		{
			name:      "ES512",
			algorithm: COSEAlgES512,
			genKey: func() ([]byte, error) {
				key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
				if err != nil {
					return nil, err
				}
				return x509.MarshalPKCS8PrivateKey(key)
			},
		},
		{
			name:      "EdDSA",
			algorithm: COSEAlgEdDSA,
			genKey: func() ([]byte, error) {
				_, priv, err := ed25519.GenerateKey(rand.Reader)
				if err != nil {
					return nil, err
				}
				return x509.MarshalPKCS8PrivateKey(priv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := NewSoftwareKeyBackend()
			defer func() { _ = backend.Close() }()

			pkcs8Key, err := tt.genKey()
			if err != nil {
				t.Fatalf("failed to generate key: %v", err)
			}

			credentialID := make([]byte, 32)
			_, _ = rand.Read(credentialID)

			handle, err := backend.ImportPrivateKey(credentialID, tt.algorithm, pkcs8Key)
			if err != nil {
				t.Fatalf("ImportPrivateKey failed: %v", err)
			}

			if handle == nil {
				t.Fatal("handle is nil")
			}

			if !bytes.Equal(handle.CredentialID(), credentialID) {
				t.Error("credential ID mismatch")
			}

			if handle.Algorithm() != tt.algorithm {
				t.Errorf("Algorithm() = %d, want %d", handle.Algorithm(), tt.algorithm)
			}

			// Verify key can be loaded
			loadedHandle, err := backend.LoadKey(credentialID, tt.algorithm)
			if err != nil {
				t.Fatalf("LoadKey failed: %v", err)
			}

			if loadedHandle == nil {
				t.Error("loadedHandle is nil")
			}

			// Verify signing works with imported key
			signature, err := backend.Sign(handle, tt.algorithm, []byte("test data"))
			if err != nil {
				t.Fatalf("Sign failed with imported key: %v", err)
			}

			if len(signature) == 0 {
				t.Error("signature is empty")
			}
		})
	}
}

// TestSoftwareKeyBackend_ImportPrivateKey_EmptyCredentialID tests importing
// with an empty credential ID.
func TestSoftwareKeyBackend_ImportPrivateKey_EmptyCredentialID(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(key)

	handle, err := backend.ImportPrivateKey([]byte{}, COSEAlgES256, pkcs8Key)

	if err != keybackend.ErrInvalidCredentialID {
		t.Errorf("expected ErrInvalidCredentialID, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}

	// Test with nil
	_, err = backend.ImportPrivateKey(nil, COSEAlgES256, pkcs8Key)

	if err != keybackend.ErrInvalidCredentialID {
		t.Errorf("expected ErrInvalidCredentialID for nil, got %v", err)
	}
}

// TestSoftwareKeyBackend_ImportPrivateKey_InvalidPKCS8 tests importing an
// invalid PKCS#8 key.
func TestSoftwareKeyBackend_ImportPrivateKey_InvalidPKCS8(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, err := backend.ImportPrivateKey(credentialID, COSEAlgES256, []byte("invalid"))

	if err != keybackend.ErrInvalidPKCS8Key {
		t.Errorf("expected ErrInvalidPKCS8Key, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}
}

// TestSoftwareKeyBackend_ImportPrivateKey_ClosedBackend tests importing on
// a closed backend.
func TestSoftwareKeyBackend_ImportPrivateKey_ClosedBackend(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	_ = backend.Close()

	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pkcs8Key, _ := x509.MarshalPKCS8PrivateKey(key)

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, err := backend.ImportPrivateKey(credentialID, COSEAlgES256, pkcs8Key)

	if err != keybackend.ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}

	if handle != nil {
		t.Error("expected nil handle")
	}
}

// TestSoftwareKeyBackend_Close tests closing the backend.
func TestSoftwareKeyBackend_Close(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()

	// Generate a key first
	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)
	_, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	// Close should succeed
	err = backend.Close()
	if err != nil {
		t.Errorf("Close failed: %v", err)
	}

	// Backend should be closed
	if !backend.closed.Load() {
		t.Error("backend should be closed")
	}

	// Keys should be nil
	if backend.keys != nil {
		t.Error("keys should be nil after close")
	}

	// Multiple closes should be safe
	err = backend.Close()
	if err != nil {
		t.Errorf("second Close failed: %v", err)
	}
}

// TestSoftwareKeyBackend_ExportImportRoundTrip tests that keys can be
// exported and re-imported correctly.
func TestSoftwareKeyBackend_ExportImportRoundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
	}{
		{name: "ES256", algorithm: COSEAlgES256},
		{name: "ES384", algorithm: COSEAlgES384},
		{name: "ES512", algorithm: COSEAlgES512},
		{name: "EdDSA", algorithm: COSEAlgEdDSA},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend1 := NewSoftwareKeyBackend()
			defer func() { _ = backend1.Close() }()

			credentialID := make([]byte, 32)
			_, _ = rand.Read(credentialID)

			// Generate key in first backend
			handle1, _, err := backend1.GenerateCredentialKey(tt.algorithm, credentialID)
			if err != nil {
				t.Fatalf("GenerateCredentialKey failed: %v", err)
			}

			// Sign with original key
			data := []byte("test data for round trip")
			signature1, err := backend1.Sign(handle1, tt.algorithm, data)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			// Export key
			pkcs8Key, err := backend1.ExportPrivateKey(handle1)
			if err != nil {
				t.Fatalf("ExportPrivateKey failed: %v", err)
			}

			// Import into second backend
			backend2 := NewSoftwareKeyBackend()
			defer func() { _ = backend2.Close() }()

			newCredentialID := make([]byte, 32)
			_, _ = rand.Read(newCredentialID)

			handle2, err := backend2.ImportPrivateKey(newCredentialID, tt.algorithm, pkcs8Key)
			if err != nil {
				t.Fatalf("ImportPrivateKey failed: %v", err)
			}

			// Sign with imported key
			signature2, err := backend2.Sign(handle2, tt.algorithm, data)
			if err != nil {
				t.Fatalf("Sign with imported key failed: %v", err)
			}

			// For EdDSA, signatures should match (deterministic)
			if tt.algorithm == COSEAlgEdDSA {
				if !bytes.Equal(signature1, signature2) {
					t.Error("EdDSA signatures should match after round trip")
				}
			}

			// Both signatures should be valid (non-empty)
			if len(signature1) == 0 || len(signature2) == 0 {
				t.Error("signatures should not be empty")
			}
		})
	}
}

// TestSoftwareKeyBackend_ConcurrentAccess tests thread safety of the backend.
func TestSoftwareKeyBackend_ConcurrentAccess(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	var wg sync.WaitGroup
	workers := 50
	iterations := 10

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()

			for j := 0; j < iterations; j++ {
				credentialID := make([]byte, 32)
				_, _ = rand.Read(credentialID)

				// Generate key
				handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
				if err != nil {
					t.Errorf("worker %d: GenerateCredentialKey failed: %v", id, err)
					return
				}

				// Sign
				_, err = backend.Sign(handle, COSEAlgES256, []byte("data"))
				if err != nil {
					t.Errorf("worker %d: Sign failed: %v", id, err)
					return
				}

				// Load key
				_, err = backend.LoadKey(credentialID, COSEAlgES256)
				if err != nil {
					t.Errorf("worker %d: LoadKey failed: %v", id, err)
					return
				}

				// Export key
				_, err = backend.ExportPrivateKey(handle)
				if err != nil {
					t.Errorf("worker %d: ExportPrivateKey failed: %v", id, err)
					return
				}

				// Delete key
				err = backend.DeleteKey(handle)
				if err != nil {
					t.Errorf("worker %d: DeleteKey failed: %v", id, err)
					return
				}
			}
		}(i)
	}

	wg.Wait()
}

// TestSoftwareKeyBackend_ImplementsInterface verifies the backend implements
// the FIDO2KeyBackend interface.
func TestSoftwareKeyBackend_ImplementsInterface(t *testing.T) {
	t.Parallel()

	var _ keybackend.FIDO2KeyBackend = NewSoftwareKeyBackend()
}

// TestSoftwareKeyHandle tests the key handle methods.
func TestSoftwareKeyHandle(t *testing.T) {
	t.Parallel()

	backend := NewSoftwareKeyBackend()
	defer func() { _ = backend.Close() }()

	credentialID := make([]byte, 32)
	_, _ = rand.Read(credentialID)

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, credentialID)
	if err != nil {
		t.Fatalf("GenerateCredentialKey failed: %v", err)
	}

	// Test CredentialID
	if !bytes.Equal(handle.CredentialID(), credentialID) {
		t.Error("CredentialID mismatch")
	}

	// Test Algorithm
	if handle.Algorithm() != COSEAlgES256 {
		t.Errorf("Algorithm() = %d, want %d", handle.Algorithm(), COSEAlgES256)
	}
}

// TestCOSEConstants tests that COSE constants are correctly defined.
func TestCOSEConstants(t *testing.T) {
	t.Parallel()

	// Algorithm constants
	if COSEAlgES256 != -7 {
		t.Errorf("COSEAlgES256 = %d, want -7", COSEAlgES256)
	}
	if COSEAlgES384 != -35 {
		t.Errorf("COSEAlgES384 = %d, want -35", COSEAlgES384)
	}
	if COSEAlgES512 != -36 {
		t.Errorf("COSEAlgES512 = %d, want -36", COSEAlgES512)
	}
	if COSEAlgEdDSA != -8 {
		t.Errorf("COSEAlgEdDSA = %d, want -8", COSEAlgEdDSA)
	}

	// Key type constants
	if COSEKeyTypeEC2 != 2 {
		t.Errorf("COSEKeyTypeEC2 = %d, want 2", COSEKeyTypeEC2)
	}
	if COSEKeyTypeOKP != 1 {
		t.Errorf("COSEKeyTypeOKP = %d, want 1", COSEKeyTypeOKP)
	}

	// Curve constants
	if COSECurveP256 != 1 {
		t.Errorf("COSECurveP256 = %d, want 1", COSECurveP256)
	}
	if COSECurveP384 != 2 {
		t.Errorf("COSECurveP384 = %d, want 2", COSECurveP384)
	}
	if COSECurveP521 != 3 {
		t.Errorf("COSECurveP521 = %d, want 3", COSECurveP521)
	}
	if COSECurveEd25519 != 6 {
		t.Errorf("COSECurveEd25519 = %d, want 6", COSECurveEd25519)
	}
}

// TestSignatureVerification tests that signatures produced can be verified.
func TestSignatureVerification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		algorithm int
		verify    func(publicKey interface{}, data, signature []byte) bool
	}{
		{
			name:      "ES256",
			algorithm: COSEAlgES256,
			verify: func(publicKey interface{}, data, signature []byte) bool {
				ecKey := publicKey.(*ecdsa.PublicKey)
				hash := sha256.Sum256(data)
				return ecdsa.VerifyASN1(ecKey, hash[:], signature)
			},
		},
		{
			name:      "EdDSA",
			algorithm: COSEAlgEdDSA,
			verify: func(publicKey interface{}, data, signature []byte) bool {
				edKey := publicKey.(ed25519.PublicKey)
				return ed25519.Verify(edKey, data, signature)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			backend := NewSoftwareKeyBackend()
			defer func() { _ = backend.Close() }()

			credentialID := make([]byte, 32)
			if _, err := rand.Read(credentialID); err != nil {
				t.Fatalf("rand.Read failed: %v", err)
			}

			handle, _, err := backend.GenerateCredentialKey(tt.algorithm, credentialID)
			if err != nil {
				t.Fatalf("GenerateCredentialKey failed: %v", err)
			}

			// Get the internal handle to access public key
			softHandle := handle.(*softwareKeyHandle)

			data := []byte("test data for verification")

			signature, err := backend.Sign(handle, tt.algorithm, data)
			if err != nil {
				t.Fatalf("Sign failed: %v", err)
			}

			if !tt.verify(softHandle.publicKey, data, signature) {
				t.Error("signature verification failed")
			}
		})
	}
}

// fakeKeyHandle is a fake implementation for testing error handling.
type fakeKeyHandle struct {
	credID []byte
	alg    int
}

func (f *fakeKeyHandle) CredentialID() []byte {
	return f.credID
}

func (f *fakeKeyHandle) Algorithm() int {
	return f.alg
}
