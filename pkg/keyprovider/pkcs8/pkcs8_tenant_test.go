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
	"crypto"
	"crypto/rsa"
	"encoding/json"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// tenantRSAAttrs builds RSA attributes for cn owned by tenantID.
func tenantRSAAttrs(tenantID, cn string) *types.KeyAttributes {
	attrs := createRSAAttrs(cn, 2048)
	attrs.TenantID = tenantID
	return attrs
}

// publicKeyOf returns the public half of a generated private key so two keys
// can be compared for identity.
func publicKeyOf(t *testing.T, key crypto.PrivateKey) *rsa.PublicKey {
	t.Helper()
	rsaKey, ok := key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("expected *rsa.PrivateKey, got %T", key)
	}
	return &rsaKey.PublicKey
}

// findByCN returns the single listed attribute whose common name is cn,
// mirroring how the service layer resolves a key ID against a listing.
func findByCN(t *testing.T, attrs []*types.KeyAttributes, cn string) *types.KeyAttributes {
	t.Helper()
	var found *types.KeyAttributes
	for _, attr := range attrs {
		if attr.CN != cn {
			continue
		}
		if found != nil {
			t.Fatalf("common name %q resolves to more than one listed key", cn)
		}
		found = attr
	}
	if found == nil {
		t.Fatalf("common name %q is not in the listing", cn)
	}
	return found
}

// TestListKeys_CrossTenantKeyIdentity is the decisive test for tenant
// scoping. Two tenants generate a key under the identical common name; the
// backend must hold two distinct keys, report each one's owner, and hand each
// tenant back its own key material.
//
// Visibility alone is not the oracle. A listing that reported every key as
// belonging to the asking tenant would also "show" a tenant its key, so the
// assertions are on identity: two stored keys, two owners, two different
// public keys, and each tenant's own material coming back from GetKey.
func TestListKeys_CrossTenantKeyIdentity(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	const sharedCN = "shared-name.com"

	attrsA := tenantRSAAttrs("tenant-a", sharedCN)
	keyA, err := be.GenerateKey(ctx, attrsA)
	if err != nil {
		t.Fatalf("GenerateKey (tenant-a) failed: %v", err)
	}

	attrsB := tenantRSAAttrs("tenant-b", sharedCN)
	keyB, err := be.GenerateKey(ctx, attrsB)
	if err != nil {
		t.Fatalf("GenerateKey (tenant-b) failed: %v", err)
	}

	pubA, pubB := publicKeyOf(t, keyA), publicKeyOf(t, keyB)
	if pubA.Equal(pubB) {
		t.Fatal("the same common name under two tenants produced one key; the tenant is not part of the stored identity")
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected two stored keys, got %d", len(listed))
	}

	owners := map[string]*types.KeyAttributes{}
	for _, attr := range listed {
		if attr.CN != sharedCN {
			t.Fatalf("unexpected common name %q in listing", attr.CN)
		}
		if _, duplicate := owners[attr.TenantID]; duplicate {
			t.Fatalf("two listed keys report the same owner %q", attr.TenantID)
		}
		owners[attr.TenantID] = attr
	}

	listedA, ok := owners["tenant-a"]
	if !ok {
		t.Fatalf("tenant-a's key is not reported as tenant-a's; owners seen: %v", owners)
	}
	listedB, ok := owners["tenant-b"]
	if !ok {
		t.Fatalf("tenant-b's key is not reported as tenant-b's; owners seen: %v", owners)
	}

	// The listed attributes must address the stored keys, which means each one
	// must resolve to its own tenant's material and not the other's.
	gotA, err := be.GetKey(ctx, listedA)
	if err != nil {
		t.Fatalf("GetKey for the listed tenant-a key failed: %v", err)
	}
	if !publicKeyOf(t, gotA).Equal(pubA) {
		t.Error("tenant-a's listed attributes resolved to another tenant's key")
	}

	gotB, err := be.GetKey(ctx, listedB)
	if err != nil {
		t.Fatalf("GetKey for the listed tenant-b key failed: %v", err)
	}
	if !publicKeyOf(t, gotB).Equal(pubB) {
		t.Error("tenant-b's listed attributes resolved to another tenant's key")
	}
}

// TestListKeys_TenantedAndUntenantedSameNameAreDistinct covers the boundary
// between a tenant-scoped key and an untenanted one of the same name: they are
// two keys, and the untenanted one must not be reported as owned.
func TestListKeys_TenantedAndUntenantedSameNameAreDistinct(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	const sharedCN = "tenant-vs-shared.com"

	if _, err := be.GenerateKey(ctx, createRSAAttrs(sharedCN, 2048)); err != nil {
		t.Fatalf("GenerateKey (untenanted) failed: %v", err)
	}
	if _, err := be.GenerateKey(ctx, tenantRSAAttrs("tenant-a", sharedCN)); err != nil {
		t.Fatalf("GenerateKey (tenant-a) failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 2 {
		t.Fatalf("expected two stored keys, got %d", len(listed))
	}

	tenants := map[string]int{}
	for _, attr := range listed {
		tenants[attr.TenantID]++
	}
	if tenants[""] != 1 {
		t.Errorf("expected exactly one untenanted key, got %d", tenants[""])
	}
	if tenants["tenant-a"] != 1 {
		t.Errorf("expected exactly one key owned by tenant-a, got %d", tenants["tenant-a"])
	}
}

// TestListKeys_PartitionSurvivesReconstruction proves the partition is
// recovered too. It shares the leading identifier segment with the tenant, so
// a fix that recovered the tenant by assuming the segment is always a tenant
// would silently reassign every partitioned key to a tenant of that name.
func TestListKeys_PartitionSurvivesReconstruction(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := createRSAAttrs("partitioned.com", 2048)
	attrs.Partition = types.Partition("slot-1")
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one key, got %d", len(listed))
	}
	if got := listed[0].TenantID; got != "" {
		t.Errorf("a partitioned key must report no tenant, got %q", got)
	}
	if got := listed[0].Partition; got != types.Partition("slot-1") {
		t.Errorf("expected partition slot-1, got %q", got)
	}
	if listed[0].ID() != attrs.ID() {
		t.Errorf("reconstructed identifier %q does not address the stored key %q", listed[0].ID(), attrs.ID())
	}
}

// TestListKeys_TenantAndPartitionTogether covers the six-segment identifier,
// where both a tenant and a partition are present and the reading is
// unambiguous even without a metadata record.
func TestListKeys_TenantAndPartitionTogether(t *testing.T) {
	be, _ := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "both.com")
	attrs.Partition = types.Partition("slot-2")
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one key, got %d", len(listed))
	}
	if listed[0].TenantID != "tenant-a" || listed[0].Partition != types.Partition("slot-2") {
		t.Fatalf("expected tenant-a/slot-2, got %q/%q", listed[0].TenantID, listed[0].Partition)
	}
	if listed[0].ID() != attrs.ID() {
		t.Errorf("reconstructed identifier %q does not address the stored key %q", listed[0].ID(), attrs.ID())
	}
}

// TestListKeys_NoMetadataRecordFallsBackToIdentifier covers a key written
// without a metadata record -- every key stored before this package persisted
// one. It must still be listed, and its leading segment must be read the way
// it was read before tenants existed: as a partition.
func TestListKeys_NoMetadataRecordFallsBackToIdentifier(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	if err := storage.SaveKey(ctx, keyStorage, "legacy-slot:sw:tls:legacy.com:rsa", []byte("dummy")); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one key, got %d", len(listed))
	}
	if got := listed[0].TenantID; got != "" {
		t.Errorf("a record-less key must not be attributed to a tenant, got %q", got)
	}
	if got := listed[0].Partition; got != types.Partition("legacy-slot") {
		t.Errorf("expected the leading segment to read as partition legacy-slot, got %q", got)
	}
	if got := listed[0].CN; got != "legacy.com" {
		t.Errorf("expected common name legacy.com, got %q", got)
	}
}

// TestListKeys_OldSchemaMetadataRecordIsRefused proves a record stamped
// with any schema version other than the single one this package supports
// -- including a pre-tenant record with SchemaVersion omitted, which decodes
// as 0 -- is discarded exactly like a corrupt record: there is no
// version-gated interpretation of an old shape. The identifier's own
// reading of the partition stands, and Exportable falls back to its safe
// default rather than trusting the discarded record's claim.
func TestListKeys_OldSchemaMetadataRecordIsRefused(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	const keyID = "legacy-slot:sw:tls:legacy-meta.com:rsa"
	if err := storage.SaveKey(ctx, keyStorage, keyID, []byte("dummy")); err != nil {
		t.Fatalf("SaveKey failed: %v", err)
	}
	oldSchema, err := json.Marshal(map[string]interface{}{
		"cn":            "legacy-meta.com",
		"key_type":      "TLS",
		"store_type":    "sw",
		"key_algorithm": "RSA",
		"exportable":    true,
	})
	if err != nil {
		t.Fatalf("marshal old-schema metadata: %v", err)
	}
	if err := keyStorage.Put(ctx, metadataPath(keyID), oldSchema); err != nil {
		t.Fatalf("Put old-schema metadata failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected one key, got %d", len(listed))
	}
	if got := listed[0].Partition; got != types.Partition("legacy-slot") {
		t.Errorf("a discarded old-schema record must not erase the identifier's partition, got %q", got)
	}
	if listed[0].Exportable {
		t.Error("a discarded old-schema record's exportable claim must not be honored")
	}
	if listed[0].KeyOrigin != types.KeyOriginUnknown {
		t.Errorf("a discarded old-schema record must resolve KeyOrigin to unknown, got %q", listed[0].KeyOrigin)
	}
}

// TestListKeys_CorruptMetadataRecordFallsBackToIdentifier proves a record that
// cannot be parsed does not fail or hide the key, and does not fabricate an
// owner for it.
func TestListKeys_CorruptMetadataRecordFallsBackToIdentifier(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "corrupt-meta.com")
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := keyStorage.Put(ctx, metadataPath(attrs.ID()), []byte("{not json")); err != nil {
		t.Fatalf("Put corrupt metadata failed: %v", err)
	}

	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys must not fail on an unreadable metadata record: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("expected the key to remain listed, got %d entries", len(listed))
	}
	if listed[0].Exportable {
		t.Error("an unreadable record must fall back to the non-exportable default")
	}
	if got := findByCN(t, listed, "corrupt-meta.com").Partition; got != types.Partition("tenant-a") {
		// The identifier alone cannot tell a tenant from a partition, which is
		// exactly why the record exists; losing it degrades to the pre-tenant
		// reading rather than to a wrong tenant.
		t.Errorf("expected the fallback reading to treat the leading segment as a partition, got %q", got)
	}
}

// TestDeleteKey_RemovesMetadataRecord proves a deleted key leaves no record
// behind for a later key of the same identifier to inherit an owner or an
// exportable flag from.
func TestDeleteKey_RemovesMetadataRecord(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "deleted.com")
	attrs.Exportable = true
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}
	if err := be.DeleteKey(ctx, attrs); err != nil {
		t.Fatalf("DeleteKey failed: %v", err)
	}

	if _, err := keyStorage.Get(ctx, metadataPath(attrs.ID())); err == nil {
		t.Fatal("the metadata record outlived the key it describes")
	}

	// A new key under the identical identifier must start from the default,
	// not from the deleted key's record.
	replacement := tenantRSAAttrs("tenant-a", "deleted.com")
	if _, err := be.GenerateKey(ctx, replacement); err != nil {
		t.Fatalf("GenerateKey (replacement) failed: %v", err)
	}
	listed, err := be.ListKeys(ctx)
	if err != nil {
		t.Fatalf("ListKeys failed: %v", err)
	}
	if findByCN(t, listed, "deleted.com").Exportable {
		t.Error("the replacement key inherited the deleted key's exportable flag")
	}
}

// TestDeleteKey_MetadataDeleteFailurePropagates proves a storage failure while
// removing the record is reported rather than swallowed.
func TestDeleteKey_MetadataDeleteFailurePropagates(t *testing.T) {
	keyStorage := storage.New()
	real, err := NewBackend(&Config{KeyStorage: keyStorage, AllowPlaintextKeys: true})
	if err != nil {
		t.Fatalf("NewBackend failed: %v", err)
	}
	be := real.(*PKCS8Backend)
	defer func() { _ = be.Close() }()

	ctx := context.Background()
	attrs := tenantRSAAttrs("tenant-a", "meta-delete-fails.com")
	if _, err := be.GenerateKey(ctx, attrs); err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	// Fail only the metadata delete: the key blob is removed first, so failing
	// every delete would abort before the record is reached.
	be.storage = &metaDeleteFailStorage{Backend: keyStorage}

	if err := be.DeleteKey(ctx, attrs); err == nil {
		t.Fatal("DeleteKey must report a failure to remove the metadata record")
	}
}

// metaDeleteFailStorage fails deletes of metadata records only.
type metaDeleteFailStorage struct {
	storage.Backend
}

// Delete rejects metadata paths and delegates everything else.
func (s *metaDeleteFailStorage) Delete(ctx context.Context, key string) error {
	if strings.HasPrefix(key, "meta/") {
		return &errs.Message{Msg: "injected metadata delete failure"}
	}
	return s.Backend.Delete(ctx, key)
}

// TestParseStorageKeyID covers every segment count the stored identifier
// format produces, including the shapes that are not valid identifiers.
func TestParseStorageKeyID(t *testing.T) {
	tests := []struct {
		name string
		id   string
		want storageKeyID
	}{
		{
			name: "four segments carry neither tenant nor partition",
			id:   "sw:tls:example.com:rsa",
			want: storageKeyID{StoreType: "sw", KeyType: "tls", CN: "example.com", Algorithm: "rsa"},
		},
		{
			name: "five segments read the leading segment as a partition",
			id:   "slot-1:sw:tls:example.com:rsa",
			want: storageKeyID{Partition: "slot-1", StoreType: "sw", KeyType: "tls", CN: "example.com", Algorithm: "rsa"},
		},
		{
			name: "six segments carry tenant then partition",
			id:   "tenant-a:slot-1:sw:tls:example.com:rsa",
			want: storageKeyID{TenantID: "tenant-a", Partition: "slot-1", StoreType: "sw", KeyType: "tls", CN: "example.com", Algorithm: "rsa"},
		},
		{
			name: "extra segments belong to the common name",
			id:   "tenant-a:slot-1:sw:tls:host:8443:rsa",
			want: storageKeyID{TenantID: "tenant-a", Partition: "slot-1", StoreType: "sw", KeyType: "tls", CN: "host:8443", Algorithm: "rsa"},
		},
		{
			name: "a bare name is a common name with defaults",
			id:   "just-a-name",
			want: storageKeyID{StoreType: "pkcs8", KeyType: "tls", CN: "just-a-name", Algorithm: "rsa"},
		},
		{
			name: "too few segments are not an identifier",
			id:   "sw:tls:example.com",
			want: storageKeyID{StoreType: "pkcs8", KeyType: "tls", CN: "sw:tls:example.com", Algorithm: "rsa"},
		},
		{
			name: "the empty string is a common name with defaults",
			id:   "",
			want: storageKeyID{StoreType: "pkcs8", KeyType: "tls", CN: "", Algorithm: "rsa"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseStorageKeyID(tt.id); got != tt.want {
				t.Errorf("parseStorageKeyID(%q) = %+v, want %+v", tt.id, got, tt.want)
			}
		})
	}
}

// TestParseStorageKeyID_RoundTripsGeneratedIdentifiers proves the parser and
// types.KeyAttributes.ID() agree on the six-segment form, so a reconstructed
// attribute set addresses the key it came from.
func TestParseStorageKeyID_RoundTripsGeneratedIdentifiers(t *testing.T) {
	attrs := createRSAAttrs("round-trip.com", 2048)
	attrs.TenantID = "tenant-a"
	attrs.Partition = types.Partition("slot-1")

	parsed := parseStorageKeyID(attrs.ID())
	if parsed.TenantID != "tenant-a" {
		t.Errorf("expected tenant-a, got %q", parsed.TenantID)
	}
	if parsed.Partition != "slot-1" {
		t.Errorf("expected slot-1, got %q", parsed.Partition)
	}
	if parsed.CN != "round-trip.com" {
		t.Errorf("expected round-trip.com, got %q", parsed.CN)
	}
}
