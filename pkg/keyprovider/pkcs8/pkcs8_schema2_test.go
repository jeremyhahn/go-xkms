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

package pkcs8

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestListKeys_SchemaTwoRecordKeepsOwnershipAndIsBound covers a key written
// before records were bound to their blob: its schema-2 record still gives
// the key its tenant and policy, and the first read migrates it to a record
// bound to the blob stored now.
func TestListKeys_SchemaTwoRecordKeepsOwnershipAndIsBound(t *testing.T) {
	b, keyStorage := createTestBackend(t)
	defer func() { _ = b.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-legacy", "schema-two.com")
	attrs.Exportable = true
	attrs.KeyOrigin = types.KeyOriginImported
	if _, err := b.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	keyID := attrs.ID()

	// Rewrite the record in the schema-2 shape: no blob binding.
	legacy := newKeyMetadata(attrs)
	legacy.SchemaVersion = legacyKeyMetadataSchemaVersion
	encoded, err := json.Marshal(legacy)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	delete(fields, "blob_sha256")
	encoded, err = json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := keyStorage.Put(ctx, metadataPath(keyID), encoded); err != nil {
		t.Fatalf("Put schema-2 record: %v", err)
	}

	for pass := 0; pass < 2; pass++ {
		listed, err := b.ListKeys(ctx)
		if err != nil {
			t.Fatalf("ListKeys failed: %v", err)
		}
		got := findByCN(t, listed, "schema-two.com")
		if got.TenantID != "tenant-legacy" || !got.Exportable || got.KeyOrigin != types.KeyOriginImported {
			t.Fatalf("pass %d: key read as tenant=%q exportable=%v origin=%q, want tenant-legacy/true/%q",
				pass, got.TenantID, got.Exportable, got.KeyOrigin, types.KeyOriginImported)
		}
	}

	stored, err := keyStorage.Get(ctx, metadataPath(keyID))
	if err != nil {
		t.Fatalf("Get record: %v", err)
	}
	blob, err := storage.GetKey(ctx, keyStorage, keyID)
	if err != nil {
		t.Fatalf("GetKey: %v", err)
	}
	if !recordBindsBlob(stored, blob) {
		t.Fatalf("migrated record is not bound to the stored key")
	}
	var record keyMetadata
	if err := json.Unmarshal(stored, &record); err != nil {
		t.Fatalf("unmarshal stored record: %v", err)
	}
	if record.SchemaVersion != keyMetadataSchemaVersion || record.BlobSHA256 == "" {
		t.Fatalf("stored record not migrated: schema=%d binding=%q", record.SchemaVersion, record.BlobSHA256)
	}
	if record.TenantID != "tenant-legacy" || !record.Exportable {
		t.Fatalf("migrated record lost ownership: tenant=%q exportable=%v", record.TenantID, record.Exportable)
	}
}
