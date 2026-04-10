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

package services

import (
	"context"
	"encoding/base64"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testBlob creates a sealedBlobStorage with the given ID for testing.
func testBlob(id string) *sealedBlobStorage {
	return &sealedBlobStorage{
		ID:         id,
		Label:      "test-label-" + id,
		SizeBytes:  42,
		PolicyType: string(PolicyTypeNone),
		Category:   "user",
		BackendID:  string(types.BackendTypeTPM2),
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("ciphertext-" + id),
			TPMPublic:  []byte("tpm-public-" + id),
			TPMPrivate: []byte("tpm-private-" + id),
		},
		CreatedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
}

// ---------------------------------------------------------------------------
// SetBackend / Backend getter/setter
// ---------------------------------------------------------------------------

func TestSealService_SetBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	assert.Nil(t, svc.Backend())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")
	assert.Equal(t, backend, svc.Backend())
}

func TestSealService_SetBackend_Nil(t *testing.T) {
	svc := NewSealService(t.TempDir())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")
	require.NotNil(t, svc.Backend())

	svc.SetBackend(nil, "")
	assert.Nil(t, svc.Backend())
}

// ---------------------------------------------------------------------------
// SealData StorageType field
// ---------------------------------------------------------------------------

func TestSealService_SealData_DefaultStorageType(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, string(StorageTypeDisk), entry.StorageType)
}

func TestSealService_SealData_ExplicitDiskStorageType(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	req.StorageType = string(StorageTypeDisk)
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, string(StorageTypeDisk), entry.StorageType)
}

func TestSealService_SealData_NVRAMStorageType(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	req.StorageType = string(StorageTypeNVRAM)
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.Equal(t, string(StorageTypeNVRAM), entry.StorageType)
}

// ---------------------------------------------------------------------------
// SealData + backend routing
// ---------------------------------------------------------------------------

func TestSealService_SealData_RoutesThroughBackend(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)

	// Verify the blob was saved through the backend.
	loaded, loadErr := svc.loadBlobByID(entry.ID)
	require.NoError(t, loadErr)
	require.NotNil(t, loaded)
	assert.Equal(t, entry.ID, loaded.ID)
	assert.Equal(t, entry.Label, loaded.Label)
}

func TestSealService_SealData_StorageTypePersisted(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := validSealRequest()
	req.StorageType = string(StorageTypeNVRAM)
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	loaded, loadErr := svc.loadBlobByID(entry.ID)
	require.NoError(t, loadErr)
	assert.Equal(t, string(StorageTypeNVRAM), loaded.StorageType)
}

// ---------------------------------------------------------------------------
// ListBlobs + backend routing
// ---------------------------------------------------------------------------

func TestSealService_ListBlobs_RoutesThroughBackend(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req1 := validSealRequest()
	req1.Label = "blob-1"
	_, err := svc.SealData(req1)
	require.NoError(t, err)

	req2 := validSealRequest()
	req2.Label = "blob-2"
	_, err = svc.SealData(req2)
	require.NoError(t, err)

	entries, listErr := svc.ListBlobs()
	require.NoError(t, listErr)
	assert.Len(t, entries, 2)
}

func TestSealService_ListBlobs_StorageTypeInEntries(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := validSealRequest()
	req.StorageType = string(StorageTypeNVRAM)
	_, err := svc.SealData(req)
	require.NoError(t, err)

	entries, listErr := svc.ListBlobs()
	require.NoError(t, listErr)
	require.Len(t, entries, 1)
	assert.Equal(t, string(StorageTypeNVRAM), entries[0].StorageType)
}

func TestSealService_ListBlobs_EmptyBackend(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	svc.SetBackend(storage.NewMemory(), "sealed/")

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.NotNil(t, entries)
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// DeleteBlob + backend routing
// ---------------------------------------------------------------------------

func TestSealService_DeleteBlob_RoutesThroughBackend(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	require.NoError(t, svc.DeleteBlob(entry.ID))

	_, loadErr := svc.loadBlobByID(entry.ID)
	assert.ErrorIs(t, loadErr, ErrSealBlobNotFound)
}

func TestSealService_DeleteBlob_BackendNotFound(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	svc.SetBackend(storage.NewMemory(), "sealed/")

	err := svc.DeleteBlob("nonexistent")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// ---------------------------------------------------------------------------
// UnsealData + backend routing
// ---------------------------------------------------------------------------

func TestSealService_UnsealData_RoutesThroughBackend(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	result, unsealErr := svc.UnsealData(entry.ID, "")
	require.NoError(t, unsealErr)

	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.NotEmpty(t, decoded)
}

func TestSealService_UnsealData_BackendNotFound(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	svc.SetBackend(storage.NewMemory(), "sealed/")

	_, err := svc.UnsealData("nonexistent", "")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// ---------------------------------------------------------------------------
// blobToEntry helper tests
// ---------------------------------------------------------------------------

func TestBlobToEntry_DefaultStorageType(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:        "test-id",
		Label:     "test-label",
		SizeBytes: 100,
		CreatedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, string(StorageTypeDisk), entry.StorageType)
}

func TestBlobToEntry_ExplicitStorageType(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:          "test-id",
		Label:       "test-label",
		StorageType: string(StorageTypeNVRAM),
		CreatedAt:   time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, string(StorageTypeNVRAM), entry.StorageType)
}

func TestBlobToEntry_DefaultPolicyType(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:        "test-id",
		Label:     "test-label",
		CreatedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, string(PolicyTypeNone), entry.PolicyType)
}

func TestBlobToEntry_DefaultCategory(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:        "test-id",
		Label:     "barrier_password",
		CreatedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, "system", entry.Category)
}

func TestBlobToEntry_AllFieldsMapped(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:          "id-123",
		Label:       "my-secret",
		SizeBytes:   256,
		PCRBound:    true,
		PolicyType:  string(PolicyTypeCustomPCR),
		Category:    "user",
		BackendID:   string(types.BackendTypeTPM2),
		StorageType: string(StorageTypeNVRAM),
		CreatedAt:   time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, "id-123", entry.ID)
	assert.Equal(t, "my-secret", entry.Label)
	assert.Equal(t, 256, entry.SizeBytes)
	assert.True(t, entry.PCRBound)
	assert.Equal(t, string(PolicyTypeCustomPCR), entry.PolicyType)
	assert.Equal(t, "user", entry.Category)
	assert.Equal(t, string(types.BackendTypeTPM2), entry.BackendID)
	assert.Equal(t, string(StorageTypeNVRAM), entry.StorageType)
	assert.Equal(t, "2025-06-15T12:00:00Z", entry.CreatedAt)
}

// ---------------------------------------------------------------------------
// sortAndCollectEntries helper tests
// ---------------------------------------------------------------------------

func TestSortAndCollectEntries_SortsByNewestFirst(t *testing.T) {
	items := []blobWithTime{
		{
			entry:     SealedBlobEntry{ID: "old"},
			createdAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			entry:     SealedBlobEntry{ID: "new"},
			createdAt: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		},
		{
			entry:     SealedBlobEntry{ID: "mid"},
			createdAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	result := sortAndCollectEntries(items)
	require.Len(t, result, 3)
	assert.Equal(t, "new", result[0].ID)
	assert.Equal(t, "mid", result[1].ID)
	assert.Equal(t, "old", result[2].ID)
}

func TestSortAndCollectEntries_Empty(t *testing.T) {
	result := sortAndCollectEntries(nil)
	assert.NotNil(t, result)
	assert.Empty(t, result)
}

// ---------------------------------------------------------------------------
// Backward compatibility: no backend set (direct disk fallback)
// ---------------------------------------------------------------------------

func TestSealService_SealData_NoBackend_DirectDisk(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)

	blob, loadErr := svc.loadBlobByID(entry.ID)
	require.NoError(t, loadErr)
	assert.Equal(t, entry.ID, blob.ID)
}

func TestSealService_ListBlobs_NoBackend_DirectDisk(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	_, err := svc.SealData(req)
	require.NoError(t, err)

	entries, listErr := svc.ListBlobs()
	require.NoError(t, listErr)
	assert.Len(t, entries, 1)
}

func TestSealService_DeleteBlob_NoBackend_DirectDisk(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	require.NoError(t, svc.DeleteBlob(entry.ID))

	_, loadErr := svc.loadBlobByID(entry.ID)
	assert.ErrorIs(t, loadErr, ErrSealBlobNotFound)
}

// ---------------------------------------------------------------------------
// SealRequest / SealedBlobEntry StorageType field
// ---------------------------------------------------------------------------

func TestSealRequest_StorageType_Field(t *testing.T) {
	req := &SealRequest{
		Label:       "test",
		Data:        base64.StdEncoding.EncodeToString([]byte("data")),
		StorageType: string(StorageTypeNVRAM),
	}
	assert.Equal(t, string(StorageTypeNVRAM), req.StorageType)
}

func TestSealedBlobEntry_StorageType_Field(t *testing.T) {
	entry := SealedBlobEntry{
		ID:          "test",
		StorageType: string(StorageTypeNVRAM),
	}
	assert.Equal(t, string(StorageTypeNVRAM), entry.StorageType)
}

// ---------------------------------------------------------------------------
// Nil context paths
// ---------------------------------------------------------------------------

func TestSealService_SaveBlob_Backend_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := testBlob("nil-ctx-save")
	require.NoError(t, svc.saveBlob(blob))

	loaded, err := svc.loadBlobByID("nil-ctx-save")
	require.NoError(t, err)
	assert.Equal(t, "nil-ctx-save", loaded.ID)
}

func TestSealService_LoadBlobByID_Backend_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := testBlob("nil-ctx-load")
	require.NoError(t, svc.saveBlob(blob))

	loaded, err := svc.loadBlobByID("nil-ctx-load")
	require.NoError(t, err)
	assert.Equal(t, "nil-ctx-load", loaded.ID)
}

func TestSealService_DeleteBlob_Backend_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := testBlob("nil-ctx-del")
	require.NoError(t, svc.saveBlob(blob))

	require.NoError(t, svc.DeleteBlob("nil-ctx-del"))

	_, err := svc.loadBlobByID("nil-ctx-del")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_ListBlobs_Backend_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := testBlob("nil-ctx-list")
	require.NoError(t, svc.saveBlob(blob))

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "nil-ctx-list", entries[0].ID)
}

// ---------------------------------------------------------------------------
// Full round-trip with backend
// ---------------------------------------------------------------------------

func TestSealService_FullRoundTrip_Backend(t *testing.T) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: req.Data,
				TPMPublic:  []byte("pub"),
				TPMPrivate: []byte("priv"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			return &transport.UnsealResponse{
				Plaintext: req.Ciphertext,
			}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	svc := newSealServiceWithMockClient(t, mc)
	svc.SetBackend(storage.NewMemory(), "sealed/")

	// Seal.
	req := &SealRequest{
		Label:       "round-trip",
		Data:        base64.StdEncoding.EncodeToString([]byte("secret-data")),
		StorageType: string(StorageTypeNVRAM),
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, string(StorageTypeNVRAM), entry.StorageType)

	// List.
	entries, listErr := svc.ListBlobs()
	require.NoError(t, listErr)
	require.Len(t, entries, 1)
	assert.Equal(t, entry.ID, entries[0].ID)
	assert.Equal(t, string(StorageTypeNVRAM), entries[0].StorageType)

	// Unseal.
	result, unsealErr := svc.UnsealData(entry.ID, "")
	require.NoError(t, unsealErr)
	decoded, decErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decErr)
	assert.Equal(t, []byte("secret-data"), decoded)

	// Delete.
	require.NoError(t, svc.DeleteBlob(entry.ID))

	// Verify deleted.
	entries, listErr = svc.ListBlobs()
	require.NoError(t, listErr)
	assert.Empty(t, entries)
}
