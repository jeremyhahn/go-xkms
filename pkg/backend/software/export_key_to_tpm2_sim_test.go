//go:build tpm_simulator

package software

import (
	"context"
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

	attrs := createRSAAttrs("export-to-tpm2.example", 2048)
	attrs.Exportable = true
	if _, err := src.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	dstAttrs := &types.KeyAttributes{CN: "export-to-tpm2-copy", KeyType: types.KeyTypeStorage, StoreType: types.StoreTPM2}
	params, err := dst.GetImportParameters(ctx, dstAttrs, backend.WrappingAlgorithmTPM2Duplicate)
	if err != nil {
		t.Fatalf("tpm2 GetImportParameters: %v", err)
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
