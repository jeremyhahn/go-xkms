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
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	phoneproto "github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// --- ExportPublicKey ---

func TestBackend_ExportPublicKey_Success(t *testing.T) {
	expectedPubKey := generateTestECDSAPublicKeyDER(t)

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			if req.Method != phoneproto.MethodLocalGetPublicKey {
				t.Errorf("expected method %s, got %s", phoneproto.MethodLocalGetPublicKey, req.Method)
			}
			return mockSuccessResponse(phoneproto.LocalGetPublicKeyResult{
				PublicKey: expectedPubKey,
				Format:    "der",
				Algorithm: "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)
	attrs := ecdsaP256Attrs("test-key")

	pubKey, err := b.ExportPublicKey(attrs, "der")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(pubKey) != string(expectedPubKey) {
		t.Error("exported public key does not match expected")
	}
}

func TestBackend_ExportPublicKey_PEMFormat(t *testing.T) {
	pemData := []byte("-----BEGIN PUBLIC KEY-----\nMFkw...\n-----END PUBLIC KEY-----\n")

	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockSuccessResponse(phoneproto.LocalGetPublicKeyResult{
				PublicKey: pemData,
				Format:    "pem",
				Algorithm: "ES256",
			}), nil
		},
	}

	b := newTestBackend(t, sender)

	pubKey, err := b.ExportPublicKey(ecdsaP256Attrs("test-key"), "pem")
	if err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
	if string(pubKey) != string(pemData) {
		t.Error("exported PEM data does not match")
	}
}

func TestBackend_ExportPublicKey_Closed(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)
	_ = b.Close()

	_, err := b.ExportPublicKey(ecdsaP256Attrs("test-key"), "der")
	if err != ErrBackendClosed {
		t.Errorf("expected ErrBackendClosed, got %v", err)
	}
}

func TestBackend_ExportPublicKey_RPCError(t *testing.T) {
	sender := &mockSender{
		sendFunc: func(ctx context.Context, req *phoneproto.Request) (*phoneproto.Response, error) {
			return mockErrorResponse(phoneproto.ErrorCodeKeyNotFound, "not found"), nil
		},
	}

	b := newTestBackend(t, sender)

	_, err := b.ExportPublicKey(ecdsaP256Attrs("missing"), "der")
	if err != ErrKeyNotFound {
		t.Errorf("expected ErrKeyNotFound, got %v", err)
	}
}

// --- GetImportParameters ---

func TestBackend_GetImportParameters_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GetImportParameters(ecdsaP256Attrs("test-key"), backend.WrappingAlgorithm("RSA-OAEP"))
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported, got %v", err)
	}
}

func TestBackend_GetImportParameters_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.GetImportParameters(nil, backend.WrappingAlgorithm("RSA-OAEP"))
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported regardless of attrs, got %v", err)
	}
}

// --- WrapKey ---

func TestBackend_WrapKey_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.WrapKey([]byte("key-material"), &backend.ImportParameters{})
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported, got %v", err)
	}
}

func TestBackend_WrapKey_NilParams(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.WrapKey([]byte("key-material"), nil)
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported regardless of params, got %v", err)
	}
}

// --- UnwrapKey ---

func TestBackend_UnwrapKey_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.UnwrapKey(&backend.WrappedKeyMaterial{}, &backend.ImportParameters{})
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported, got %v", err)
	}
}

func TestBackend_UnwrapKey_NilInputs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.UnwrapKey(nil, nil)
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported regardless of nil inputs, got %v", err)
	}
}

// --- ImportKey ---

func TestBackend_ImportKey_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err := b.ImportKey(ecdsaP256Attrs("test-key"), &backend.WrappedKeyMaterial{})
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported, got %v", err)
	}
}

func TestBackend_ImportKey_NilInputs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	err := b.ImportKey(nil, nil)
	if err != ErrImportNotSupported {
		t.Errorf("expected ErrImportNotSupported regardless of nil inputs, got %v", err)
	}
}

// --- ExportKey ---

func TestBackend_ExportKey_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.ExportKey(ecdsaP256Attrs("test-key"), backend.WrappingAlgorithm("RSA-OAEP"))
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported, got %v", err)
	}
}

func TestBackend_ExportKey_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.ExportKey(nil, backend.WrappingAlgorithm(""))
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported regardless of nil attrs, got %v", err)
	}
}

// --- ExportKeyMaterial ---

func TestBackend_ExportKeyMaterial_NotSupported(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.ExportKeyMaterial(ecdsaP256Attrs("test-key"))
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported, got %v", err)
	}
}

func TestBackend_ExportKeyMaterial_NilAttrs(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	_, err := b.ExportKeyMaterial(nil)
	if err != ErrExportNotSupported {
		t.Errorf("expected ErrExportNotSupported regardless of nil attrs, got %v", err)
	}
}

// --- Interface compliance ---

func TestBackend_ImplementsImportExportBackend(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	var _ backend.ImportExportBackend = b
}

func TestBackend_ImplementsTypesBackend(t *testing.T) {
	sender := &mockSender{}
	b := newTestBackend(t, sender)

	var _ types.KeyProvider = b
}
