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
	"context"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_ReportsExportableFalseAndSensitiveTrue is the success case
// for go-xkms#932: a key created with Exportable: true must round-trip
// through ListKeys as Exportable=false, and Sensitive must read true.
// Capabilities().Export is false unconditionally (azurekv.go), and
// ExportKey/ExportKeyMaterial (azurekv_importexport.go) refuse every key
// this backend can create or import regardless of policy: Azure Key Vault
// exposes no API to release private key material. Before this fix, ListKeys
// left both fields at the types.KeyAttributes zero value, which happened to
// read Exportable as false by coincidence but always misreported Sensitive
// as false.
func TestListKeys_ReportsExportableFalseAndSensitiveTrue(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}

	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	attrs := &types.KeyAttributes{
		CN:           "listkeys-exportable-rsa",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
	}
	if _, err := b.CreateKey(attrs); err != nil {
		t.Fatalf("CreateKey() error = %v", err)
	}

	listed, err := b.ListKeys(context.Background())
	if err != nil {
		t.Fatalf("ListKeys() error = %v", err)
	}

	var found *types.KeyAttributes
	for _, ka := range listed {
		if ka.CN == attrs.CN {
			found = ka
			break
		}
	}
	if found == nil {
		t.Fatalf("ListKeys did not report %q", attrs.CN)
	}
	if found.Exportable {
		t.Error("Exportable: expected false (Azure Key Vault never releases key material), got true")
	}
	if !found.Sensitive {
		t.Error("Sensitive: expected true (Azure Key Vault never releases plaintext), got false")
	}

	if _, err := b.ExportKey(context.Background(), found, backend.WrappingAlgorithmRSAES_OAEP_SHA_256); !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ExportKey with the round-tripped attributes: expected backend.ErrNotSupported, got %v", err)
	}
}

// TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable is the error
// path: even a caller who bypasses ListKeys and hands ExportKey
// attrs.Exportable = true directly is refused, because Capabilities().Export
// is false unconditionally for this backend. This is the defence-in-depth
// half of go-xkms#932's "never silently accept it and then misreport".
func TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable(t *testing.T) {
	mockClient := NewMockKeyVaultClient()
	config := &Config{
		VaultURL:    "https://test-vault.vault.azure.net/",
		KeyStorage:  storage.New(),
		CertStorage: storage.New(),
	}
	b, err := NewBackendWithClient(config, mockClient)
	if err != nil {
		t.Fatalf("NewBackendWithClient() error = %v", err)
	}

	forged := &types.KeyAttributes{
		CN:           "listkeys-exportable-defense-in-depth",
		KeyType:      backend.KEY_TYPE_SIGNING,
		StoreType:    backend.STORE_AZUREKV,
		KeyAlgorithm: x509.RSA,
		Exportable:   true,
	}

	_, err = b.ExportKey(context.Background(), forged, backend.WrappingAlgorithmRSAES_OAEP_SHA_256)
	if !errors.Is(err, backend.ErrNotSupported) {
		t.Errorf("ExportKey: expected backend.ErrNotSupported, got %v", err)
	}
}
