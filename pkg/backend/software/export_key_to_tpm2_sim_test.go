//go:build tpm_simulator

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
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmblobtest"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestExportKeyTo_WrapsForTPM2DuplicationParameters proves an exportable
// software key wraps under the TPM2_DUPLICATE parameters a real TPM2 backend
// (on the simulator) hands out, and that the TPM2 backend imports the blob.
func TestExportKeyTo_WrapsForTPM2DuplicationParameters(t *testing.T) {
	ctx := context.Background()
	src, _ := createTestBackend(t)
	defer func() { _ = src.Close() }()

	dst, err := tpm2backend.NewBackend(&tpm2backend.Config{
		UseSimulator: true,
		Keys:         tpmblobtest.New(t),
		CN:           "software-export-to-tpm2",
	})
	if err != nil {
		t.Fatalf("tpm2 NewBackend on simulator: %v", err)
	}
	defer func() { _ = dst.Close() }()

	dstAttrs := &types.KeyAttributes{CN: "export-to-tpm2-copy", KeyType: types.KeyTypeStorage, StoreType: types.StoreTPM2}
	params, err := dst.GetImportParameters(ctx, dstAttrs, backend.WrappingAlgorithmTPM2Duplicate)
	if err != nil {
		t.Fatalf("tpm2 GetImportParameters: %v", err)
	}

	// A symmetric key is refused: the TPM2 backend cannot yet encrypt or
	// decrypt with an imported sealed object.
	symAttrs := createAESAttrs("export-to-tpm2-sym.example", 256, types.SymmetricAES256GCM)
	symAttrs.Exportable = true
	if _, err := src.GenerateSymmetricKey(ctx, symAttrs); err != nil {
		t.Fatalf("GenerateSymmetricKey: %v", err)
	}
	if _, err := src.(backend.ImportExportBackend).ExportKeyTo(ctx, symAttrs, params); !errors.Is(err, backend.ErrExportToUnsupported) {
		t.Fatalf("ExportKeyTo of a symmetric key with TPM2_DUPLICATE parameters: err = %v, want backend.ErrExportToUnsupported", err)
	}

	// A TPM sealed object holds at most 128 bytes; an Ed25519 PKCS#8 key fits.
	attrs := &types.KeyAttributes{
		CN:           "export-to-tpm2.example",
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.Ed25519,
		Exportable:   true,
	}
	if _, err := src.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	wrapped, err := src.(backend.ImportExportBackend).ExportKeyTo(ctx, attrs, params)
	if err != nil {
		t.Fatalf("ExportKeyTo with TPM2_DUPLICATE parameters: %v", err)
	}
	if wrapped.Algorithm != backend.WrappingAlgorithmTPM2Duplicate {
		t.Fatalf("wrapped algorithm = %q, want %q", wrapped.Algorithm, backend.WrappingAlgorithmTPM2Duplicate)
	}

	if err := dst.ImportKey(ctx, dstAttrs, wrapped); err != nil {
		t.Fatalf("tpm2 ImportKey of the software blob: %v", err)
	}
}
