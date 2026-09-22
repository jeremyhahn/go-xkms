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

package software

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

// TestExportKeyTo_WrapsForAGenuinelyDifferentDestination proves ExportKeyTo
// wraps under the CALLER-SUPPLIED destination parameters, not a wrapping key
// this backend mints for itself: it stands up two independent
// SoftwareBackend instances (as CopyKey does for two distinct registered
// backends), asks the destination for its own import parameters, and shows
// the source's ExportKeyTo output only unwraps under the destination's own
// private key (go-xkms#154).
func TestExportKeyTo_WrapsForAGenuinelyDifferentDestination(t *testing.T) {
	src, _ := createTestBackend(t)
	defer func() { _ = src.Close() }()
	dst, _ := createTestBackend(t)
	defer func() { _ = dst.Close() }()

	srcIE := src.(backend.ImportExportBackend)
	dstIE := dst.(backend.ImportExportBackend)

	attrs := createRSAAttrs("export-to-dest.example", 2048)
	attrs.Exportable = true
	priv, err := src.GenerateKey(context.Background(), attrs)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	sourceKey := priv.(*rsa.PrivateKey)

	dstParams, err := dstIE.GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("destination GetImportParameters failed: %v", err)
	}

	wrapped, err := srcIE.ExportKeyTo(context.Background(), attrs, dstParams)
	if err != nil {
		t.Fatalf("ExportKeyTo failed: %v", err)
	}
	if wrapped.Algorithm != dstParams.Algorithm {
		t.Errorf("algorithm mismatch: got %s, want %s", wrapped.Algorithm, dstParams.Algorithm)
	}
	if !bytes.Equal(wrapped.ImportToken, dstParams.ImportToken) {
		t.Error("ExportKeyTo must tag the material with the DESTINATION's own import token")
	}

	// Only the destination's own private key can recover this material -- the
	// canonical proof that ExportKeyTo wrapped for dstParams and not for a key
	// the source minted for itself.
	recoveredDER, err := dstIE.UnwrapKey(context.Background(), wrapped, dstParams)
	if err != nil {
		t.Fatalf("the destination must be able to unwrap material ExportKeyTo produced for it: %v", err)
	}
	recovered, err := x509.ParsePKCS8PrivateKey(recoveredDER)
	if err != nil {
		t.Fatalf("recovered material must parse as the original PKCS#8 key: %v", err)
	}
	recoveredKey, ok := recovered.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("recovered key has the wrong type: %T", recovered)
	}
	if recoveredKey.N.Cmp(sourceKey.N) != 0 {
		t.Error("the destination's copy must hold the source's key material")
	}
}

// TestExportKeyTo_NilDestinationParameters proves ExportKeyTo refuses a nil
// destination-parameters argument rather than dereferencing it.
func TestExportKeyTo_NilDestinationParameters(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	attrs := createRSAAttrs("export-to-nil-params.example", 2048)
	attrs.Exportable = true
	if _, err := be.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	_, err := be.(backend.ImportExportBackend).ExportKeyTo(context.Background(), attrs, nil)
	if err == nil {
		t.Fatal("expected an error for nil destination import parameters, got nil")
	}
	if !errors.Is(err, backend.ErrInvalidAttributes) {
		t.Errorf("expected ErrInvalidAttributes, got %v", err)
	}
}

// TestExportKeyTo_NotExportable proves ExportKeyTo enforces the same
// Exportable policy gate as ExportKey: a key created without Exportable=true
// must refuse even when a genuine destination has already minted parameters.
func TestExportKeyTo_NotExportable(t *testing.T) {
	src, _ := createTestBackend(t)
	defer func() { _ = src.Close() }()
	dst, _ := createTestBackend(t)
	defer func() { _ = dst.Close() }()

	attrs := createRSAAttrs("export-to-not-exportable.example", 2048)
	attrs.Exportable = false
	if _, err := src.GenerateKey(context.Background(), attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	dstParams, err := dst.(backend.ImportExportBackend).GetImportParameters(context.Background(), attrs, backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256)
	if err != nil {
		t.Fatalf("destination GetImportParameters failed: %v", err)
	}

	_, err = src.(backend.ImportExportBackend).ExportKeyTo(context.Background(), attrs, dstParams)
	if err == nil {
		t.Fatal("expected an error for a non-exportable key, got nil")
	}
	if !errors.Is(err, backend.ErrKeyNotExportable) {
		t.Errorf("expected ErrKeyNotExportable, got %v", err)
	}
}
