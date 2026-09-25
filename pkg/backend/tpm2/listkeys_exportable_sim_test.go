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

//go:build tpm_simulator

package tpm2

import (
	"context"
	"crypto/elliptic"
	"crypto/x509"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_ReportsGeneratedKeyAsSealed is the success case for
// go-xkms#932 against a real (simulated) TPM: a key generated with
// Exportable: true must round-trip through ListKeys as Exportable=false and
// Sensitive=true, because KeyTemplateSpec.Template (pkg/tpm2/template.go)
// unconditionally sets FixedTPM=true and FixedParent=true on every key this
// backend generates -- the caller's requested policy has no hardware path to
// honour. Before this fix ListKeys left Exportable and Sensitive at the
// types.KeyAttributes zero value without ever consulting what the key
// actually is, which happened to read as Exportable=false by coincidence but
// always misreported Sensitive=false for a key whose plaintext this backend
// can never release.
func TestListKeys_ReportsGeneratedKeyAsSealed(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "listkeys-exportable-generated",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
		Exportable:    true,
	}
	if _, err := b.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	listed, err := b.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
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
		t.Error("Exportable: expected false (the token can never honour Exportable=true for a generated key), got true")
	}
	if !found.Sensitive {
		t.Error("Sensitive: expected true (this backend never releases plaintext for any key), got false")
	}

	// The round-tripped attributes must be refused by the policy check itself,
	// the same way findKeyAttrs/loadStoredKeyAttrs (pkg/xkms) would refuse them.
	if _, err := b.ExportKey(ctx, found, importExportAlgorithm); !errors.Is(err, backend.ErrKeyNotExportable) {
		t.Errorf("ExportKey with the round-tripped attributes: expected backend.ErrKeyNotExportable, got %v", err)
	}
}

// TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable is the error
// path: even a caller who bypasses ListKeys and hands ExportKey attrs.Exportable
// = true directly (as though some other source of truth had approved it) is
// refused, because this backend's ExportKey has no working export path for any
// key it manages -- generated or imported (see the ExportKey doc comment,
// importexport.go). This is the defence-in-depth half of go-xkms#932's "never
// silently accept it and then misreport": accepting the flag at the API
// boundary must never translate into actually releasing the key.
func TestListKeys_ExportKeyRefusesEvenWhenCallerAssertsExportable(t *testing.T) {
	b := newSimBackend(t)
	ctx := context.Background()

	attrs := &types.KeyAttributes{
		CN:            "listkeys-exportable-defense-in-depth",
		KeyAlgorithm:  x509.ECDSA,
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		ECCAttributes: &types.ECCAttributes{Curve: elliptic.P256()},
	}
	if _, err := b.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	// Simulate a caller who never went through ListKeys and instead asserts
	// Exportable directly.
	forged := *attrs
	forged.Exportable = true

	_, err := b.ExportKey(ctx, &forged, importExportAlgorithm)
	if !errors.Is(err, backend.ErrExportNotSupported) {
		t.Errorf("ExportKey: expected backend.ErrExportNotSupported, got %v", err)
	}
}
