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

//go:build azurekv

package azurekv

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGenerateSymmetricKey_NilAttributes proves GenerateSymmetricKey
// rejects nil attributes before ever contacting Azure.
func TestGenerateSymmetricKey_NilAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	if _, err := b.GenerateSymmetricKey(context.Background(), nil); err == nil {
		t.Error("GenerateSymmetricKey(nil) expected error, got nil")
	}
}

// TestGenerateSymmetricKey_InvalidAttributes proves GenerateSymmetricKey
// surfaces a types.KeyAttributes.Validate failure (an empty CN) before
// generating any key material.
func TestGenerateSymmetricKey_InvalidAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_AZUREKV,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GenerateSymmetricKey() expected a Validate() error for missing CN, got nil")
	}
}

// TestGenerateSymmetricKey_AsymmetricRejected proves GenerateSymmetricKey
// refuses well-formed asymmetric key attributes.
func TestGenerateSymmetricKey_AsymmetricRejected(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:           "generate-symmetric-asymmetric-attrs",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
		RSAAttributes: &types.RSAAttributes{
			KeySize: 2048,
		},
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GenerateSymmetricKey() expected error for asymmetric attributes, got nil")
	}
}

// TestGetSymmetricKey_NilAttributes proves GetSymmetricKey rejects nil
// attributes before any metadata lookup.
func TestGetSymmetricKey_NilAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	if _, err := b.GetSymmetricKey(context.Background(), nil); err == nil {
		t.Error("GetSymmetricKey(nil) expected error, got nil")
	}
}

// TestGetSymmetricKey_CorruptMetadata proves a metadata record that is not
// valid JSON is reported as an unmarshal failure rather than a silent zero
// value. This exercises the persisted metadata path directly
// (Config.KeyStorage), which does not require contacting Azure.
func TestGetSymmetricKey_CorruptMetadata(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{CN: "get-symmetric-corrupt-metadata", StoreType: backend.STORE_AZUREKV}
	if err := storage.SaveKey(context.Background(), b.config.KeyStorage, attrs.CN, []byte("not json")); err != nil {
		t.Fatalf("storage.SaveKey() error = %v", err)
	}

	if _, err := b.GetSymmetricKey(context.Background(), attrs); err == nil {
		t.Error("GetSymmetricKey() expected an unmarshal error for corrupt metadata, got nil")
	}
}

// TestSymmetricEncrypter_NilAttributes proves SymmetricEncrypter rejects
// nil attributes before delegating to GetSymmetricKey.
func TestSymmetricEncrypter_NilAttributes(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	if _, err := b.SymmetricEncrypter(context.Background(), nil); err == nil {
		t.Error("SymmetricEncrypter(nil) expected error, got nil")
	}
}

// TestSymmetricEncrypter_KeyNotFound proves SymmetricEncrypter surfaces
// GetSymmetricKey's ErrKeyNotFound for a key that was never generated,
// wrapped rather than swallowed.
func TestSymmetricEncrypter_KeyNotFound(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{CN: "symmetric-encrypter-not-found", StoreType: backend.STORE_AZUREKV}
	if _, err := b.SymmetricEncrypter(context.Background(), attrs); !errors.Is(err, backend.ErrKeyNotFound) {
		t.Errorf("SymmetricEncrypter() error = %v, want it to wrap ErrKeyNotFound", err)
	}
}

// TestAzureSymmetricKey_Raw proves Raw returns the exact locally held key
// material as a defensive copy: Azure Key Vault's symmetric keys are
// generated locally (Azure has no native oct/symmetric Keys API on the
// standard tier), so unlike every other cloud backend in this project this
// one genuinely holds the bytes and must not let a caller mutate its
// internal copy through the returned slice.
func TestAzureSymmetricKey_Raw(t *testing.T) {
	b, _ := testBackend(t)
	defer func() { _ = b.Close() }()

	attrs := &types.KeyAttributes{
		CN:                 "raw-test-key",
		SymmetricAlgorithm: types.SymmetricAES256GCM,
	}
	key := newLocalSymmetricKey(t, b, attrs)

	raw, err := key.Raw()
	if err != nil {
		t.Fatalf("Raw() error = %v", err)
	}
	if !bytes.Equal(raw, key.keyData) {
		t.Errorf("Raw() = %x, want %x", raw, key.keyData)
	}

	// Mutating the returned slice must not affect the key's internal copy.
	raw[0] ^= 0xFF
	if bytes.Equal(raw, key.keyData) {
		t.Error("Raw() did not return a defensive copy: mutating it changed the key's internal state")
	}
}

// TestPtrBoolAndPtrString proves the ptrBool/ptrString helpers return a
// pointer that dereferences to the exact input, the property
// storeSymmetricKeySecret's Tags construction relies on.
func TestPtrBoolAndPtrString(t *testing.T) {
	if got := ptrBool(true); got == nil || *got != true {
		t.Errorf("ptrBool(true) = %v, want pointer to true", got)
	}
	if got := ptrBool(false); got == nil || *got != false {
		t.Errorf("ptrBool(false) = %v, want pointer to false", got)
	}
	if got := ptrString("symmetric-key"); got == nil || *got != "symmetric-key" {
		t.Errorf("ptrString(%q) = %v, want pointer to input", "symmetric-key", got)
	}
}
