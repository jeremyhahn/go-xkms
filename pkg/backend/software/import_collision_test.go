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

package software

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// wrapForImport produces the wrapped material an ImportKey call needs for
// attrs, using a freshly minted import token.
func wrapForImport(t *testing.T, be types.SymmetricKeyProvider, attrs *types.KeyAttributes,
	algorithm backend.WrappingAlgorithm, keyMaterial []byte) *backend.WrappedKeyMaterial {

	t.Helper()

	ie, ok := be.(backend.ImportExportBackend)
	if !ok {
		t.Fatal("backend does not implement ImportExportBackend")
	}

	params, err := ie.GetImportParameters(context.Background(), attrs, algorithm)
	if err != nil {
		t.Fatalf("GetImportParameters failed: %v", err)
	}

	wrapped, err := ie.WrapKey(context.Background(), keyMaterial, params)
	if err != nil {
		t.Fatalf("WrapKey failed: %v", err)
	}

	return wrapped
}

// TestImportKey_RefusesToOverwriteExistingAsymmetricKey is the regression for
// go-xkms#165. Importing over an existing asymmetric key destroyed it
// silently: importAsymmetricKey used storage.SaveKey, a plain Put, while
// generation used storage.SaveKeyIfAbsent and refused the same collision.
//
// For an asymmetric key the loss is unrecoverable -- every certificate issued
// against the old public key is orphaned -- so the import must refuse and the
// stored key must still be the original.
func TestImportKey_RefusesToOverwriteExistingAsymmetricKey(t *testing.T) {
	be, store := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := createRSAAttrs("collide.example", 2048)

	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	original, err := storage.GetKey(ctx, store, attrs.ID())
	if err != nil {
		t.Fatalf("reading the generated key failed: %v", err)
	}

	replacement, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating replacement material failed: %v", err)
	}
	replacementDER, err := x509.MarshalPKCS8PrivateKey(replacement)
	if err != nil {
		t.Fatalf("marshalling replacement material failed: %v", err)
	}

	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, replacementDER)

	err = be.(backend.ImportExportBackend).ImportKey(ctx, attrs, wrapped)
	if err == nil {
		t.Fatal("ImportKey accepted material over an existing key; it must refuse the collision")
	}
	if !errors.Is(err, backend.ErrKeyAlreadyExists) {
		t.Errorf("ImportKey error = %v, want it to wrap backend.ErrKeyAlreadyExists", err)
	}

	stored, err := storage.GetKey(ctx, store, attrs.ID())
	if err != nil {
		t.Fatalf("reading the key after the refused import failed: %v", err)
	}
	if !bytes.Equal(stored, original) {
		t.Error("the stored key changed: a refused import must not modify the existing key")
	}
}

// TestImportKey_RefusesToOverwriteExistingSymmetricKey is the symmetric half of
// go-xkms#165. importSymmetricKey had the same plain-Put shape, and the
// symmetric key provider's own ImportKey already refuses this collision with
// backend.ErrKeyAlreadyExists -- the software backend bypassed it.
func TestImportKey_RefusesToOverwriteExistingSymmetricKey(t *testing.T) {
	be, store := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := createAESAttrs("collide-aes", 256, types.SymmetricAES256GCM)

	if _, err := be.GenerateSymmetricKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey failed: %v", err)
	}

	original, err := storage.GetKey(ctx, store, attrs.ID())
	if err != nil {
		t.Fatalf("reading the generated key failed: %v", err)
	}

	replacement := make([]byte, 32)
	if _, err := rand.Read(replacement); err != nil {
		t.Fatalf("generating replacement material failed: %v", err)
	}

	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSAES_OAEP_SHA_256, replacement)

	err = be.(backend.ImportExportBackend).ImportKey(ctx, attrs, wrapped)
	if err == nil {
		t.Fatal("ImportKey accepted material over an existing key; it must refuse the collision")
	}
	if !errors.Is(err, backend.ErrKeyAlreadyExists) {
		t.Errorf("ImportKey error = %v, want it to wrap backend.ErrKeyAlreadyExists", err)
	}

	stored, err := storage.GetKey(ctx, store, attrs.ID())
	if err != nil {
		t.Fatalf("reading the key after the refused import failed: %v", err)
	}
	if !bytes.Equal(stored, original) {
		t.Error("the stored key changed: a refused import must not modify the existing key")
	}
}

// TestImportKey_StillAcceptsAFreshKeyID guards the fix from overshooting: the
// collision check must reject only a genuine collision, never an ordinary
// import onto an unused identifier.
func TestImportKey_StillAcceptsAFreshKeyID(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := createRSAAttrs("fresh.example", 2048)

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generating material failed: %v", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshalling material failed: %v", err)
	}

	wrapped := wrapForImport(t, be, attrs,
		backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256, der)

	if err := be.(backend.ImportExportBackend).ImportKey(ctx, attrs, wrapped); err != nil {
		t.Fatalf("ImportKey onto an unused key ID must succeed, got: %v", err)
	}

	if _, err := be.GetKey(ctx, attrs); err != nil {
		t.Errorf("retrieving the imported key failed: %v", err)
	}
}
