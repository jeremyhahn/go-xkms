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

//go:build vault

package vault

import (
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestGetImportParameters_NilAttributes proves GetImportParameters rejects
// nil attributes before reaching any Vault call.
func TestGetImportParameters_NilAttributes(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	if _, err := b.GetImportParameters(context.Background(), nil, backend.WrappingAlgorithmVaultTransitBYOK); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("GetImportParameters(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestGetImportParameters_AsymmetricRejected proves GetImportParameters
// refuses an asymmetric key: Vault Transit BYOK import in this backend is
// symmetric-only.
func TestGetImportParameters_AsymmetricRejected(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	attrs := &types.KeyAttributes{
		CN:           "import-params-asymmetric",
		KeyAlgorithm: x509.RSA,
	}
	if _, err := b.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmVaultTransitBYOK); !errors.Is(err, ErrAsymmetricImportNotSupported) {
		t.Errorf("GetImportParameters() error = %v, want ErrAsymmetricImportNotSupported", err)
	}
}

// TestWrapKey_ValidationErrors proves WrapKey's guards against empty key
// material, nil parameters, the wrong wrapping algorithm, and a wrapping
// public key of the wrong concrete type, none of which should ever reach
// the ephemeral-key ceremony.
func TestWrapKey_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("empty key material", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), nil, &backend.ImportParameters{Algorithm: backend.WrappingAlgorithmVaultTransitBYOK})
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("nil params", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), []byte("key-material"), nil)
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("wrong algorithm", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), []byte("key-material"), &backend.ImportParameters{Algorithm: backend.WrappingAlgorithmRSAES_OAEP_SHA_256})
		if !errors.Is(err, backend.ErrInvalidAlgorithm) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidAlgorithm", err)
		}
	})

	t.Run("wrapping key not RSA", func(t *testing.T) {
		_, err := b.WrapKey(context.Background(), []byte("key-material"), &backend.ImportParameters{
			Algorithm:         backend.WrappingAlgorithmVaultTransitBYOK,
			WrappingPublicKey: "not-an-rsa-key",
		})
		if !errors.Is(err, backend.ErrInvalidKeyType) {
			t.Errorf("WrapKey() error = %v, want ErrInvalidKeyType", err)
		}
	})
}

// TestImportKey_ValidationErrors proves ImportKey's guards against nil
// attributes, nil wrapped material, empty wrapped key bytes, and an
// asymmetric key, none of which should reach the Vault import call.
func TestImportKey_ValidationErrors(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	t.Run("nil attrs", func(t *testing.T) {
		err := b.ImportKey(context.Background(), nil, &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped")})
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("ImportKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("nil wrapped", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "import-key-nil-wrapped", SymmetricAlgorithm: types.SymmetricAES256GCM}
		err := b.ImportKey(context.Background(), attrs, nil)
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("ImportKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("empty wrapped key", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "import-key-empty-wrapped", SymmetricAlgorithm: types.SymmetricAES256GCM}
		err := b.ImportKey(context.Background(), attrs, &backend.WrappedKeyMaterial{})
		if !errors.Is(err, backend.ErrInvalidAttributes) {
			t.Errorf("ImportKey() error = %v, want ErrInvalidAttributes", err)
		}
	})

	t.Run("asymmetric attrs rejected", func(t *testing.T) {
		attrs := &types.KeyAttributes{CN: "import-key-asymmetric", KeyAlgorithm: x509.RSA}
		err := b.ImportKey(context.Background(), attrs, &backend.WrappedKeyMaterial{WrappedKey: []byte("wrapped")})
		if !errors.Is(err, ErrAsymmetricImportNotSupported) {
			t.Errorf("ImportKey() error = %v, want ErrAsymmetricImportNotSupported", err)
		}
	})
}

// TestExportKey_NilAttributes proves ExportKey rejects nil attributes
// before reaching the always-refuse "no native equivalent" response.
func TestExportKey_NilAttributes(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double
	if _, err := b.ExportKey(context.Background(), nil, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("ExportKey(nil) error = %v, want ErrInvalidAttributes", err)
	}
}

// TestExportKeyMaterial_Success proves ExportKeyMaterial returns the raw
// AES-256 key material for a symmetric key created with Exportable=true,
// through the full path: metadata marks it exportable, Transit's export
// endpoint returns it, and the base64 response decodes to exactly 32 bytes.
func TestExportKeyMaterial_Success(t *testing.T) {
	b, double := newVaultTestBackend(t)
	_ = double

	attrs := &types.KeyAttributes{
		CN:                 "export-material-success",
		KeyType:            backend.KEY_TYPE_SECRET,
		StoreType:          backend.STORE_VAULT,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	}
	if _, err := b.GenerateSymmetricKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateSymmetricKey() error = %v", err)
	}

	material, err := b.ExportKeyMaterial(context.Background(), attrs)
	if err != nil {
		t.Fatalf("ExportKeyMaterial() error = %v", err)
	}
	if len(material) != 32 {
		t.Errorf("ExportKeyMaterial() returned %d bytes, want 32 (AES-256)", len(material))
	}
}
