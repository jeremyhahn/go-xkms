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
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/google/go-tpm/tpm2"
	tpm2pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sealMockClient embeds mockClient and overrides Seal, Unseal, CanSeal
// with configurable behavior for SealService tests.
type sealMockClient struct {
	mockClient
	sealFn    func(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error)
	unsealFn  func(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error)
	canSealFn func(ctx context.Context, backend string) (*transport.CanSealResponse, error)
}

func (m *sealMockClient) Seal(ctx context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
	if m.sealFn != nil {
		return m.sealFn(ctx, req)
	}
	return nil, ErrSealNotSupported
}

func (m *sealMockClient) Unseal(ctx context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
	if m.unsealFn != nil {
		return m.unsealFn(ctx, req)
	}
	return nil, ErrSealNotSupported
}

func (m *sealMockClient) CanSeal(ctx context.Context, backend string) (*transport.CanSealResponse, error) {
	if m.canSealFn != nil {
		return m.canSealFn(ctx, backend)
	}
	return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
}

// defaultSealMockClient returns a sealMockClient that echoes data through
// Seal/Unseal and reports CanSeal=true for the tpm2 backend.
func defaultSealMockClient() *sealMockClient {
	return &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: req.Data,
				TPMPublic:  []byte("tpm-public"),
				TPMPrivate: []byte("tpm-private"),
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			return &transport.UnsealResponse{
				Plaintext: req.Ciphertext,
			}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			if backend == string(types.BackendTypeTPM2) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
}

// newSealServiceWithMockClient creates a SealService wired to the given sealMockClient.
func newSealServiceWithMockClient(t *testing.T, mc *sealMockClient) *SealService {
	t.Helper()
	svc := NewSealService(t.TempDir())
	svc.SetClientFunc(func() xkms.Client { return mc })
	svc.SetContext(context.Background())
	return svc
}

// validSealRequest returns a SealRequest with valid base64-encoded data.
func validSealRequest() *SealRequest {
	return &SealRequest{
		Label: "test-secret",
		Data:  base64.StdEncoding.EncodeToString([]byte("hello world")),
	}
}

// ---------------------------------------------------------------------------
// Constructor & lifecycle
// ---------------------------------------------------------------------------

func TestNewSealService(t *testing.T) {
	svc := NewSealService("/tmp/test-seal")
	require.NotNil(t, svc)
	assert.NotNil(t, svc.log)
	assert.Equal(t, "/tmp/test-seal", svc.storageDir)
	assert.Equal(t, string(types.BackendTypeTPM2), svc.defaultBackend)
}

func TestSealService_SetContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestSealService_SetTPMAccessor(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetTPMAccessor(nil)
	assert.Nil(t, svc.tpmAccessor)
}

func TestSealService_SetPlatformPolicyService(t *testing.T) {
	svc := NewSealService(t.TempDir())
	policySvc := NewPlatformPolicyService("/tmp/policy")
	svc.SetPlatformPolicyService(policySvc)
	assert.Equal(t, policySvc, svc.policyService)
}

func TestSealService_SetClientFunc(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	client, err := svc.getClient()
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestSealService_getClient_NilFunc(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.getClient()
	assert.ErrorIs(t, err, ErrSealNoClient)
}

func TestSealService_getClient_ReturnsNil(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetClientFunc(func() xkms.Client { return nil })
	_, err := svc.getClient()
	assert.ErrorIs(t, err, ErrSealNoClient)
}

// ---------------------------------------------------------------------------
// SetDefaultBackend
// ---------------------------------------------------------------------------

func TestSealService_SetDefaultBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	assert.Equal(t, string(types.BackendTypeTPM2), svc.defaultBackend)

	svc.SetDefaultBackend("software")
	assert.Equal(t, "software", svc.defaultBackend)
}

// ---------------------------------------------------------------------------
// SetStorageDir & StorageDir
// ---------------------------------------------------------------------------

func TestSealService_SetStorageDir_Success(t *testing.T) {
	svc := NewSealService(t.TempDir())
	newDir := filepath.Join(t.TempDir(), "new-sealed")

	err := svc.SetStorageDir(newDir)
	require.NoError(t, err)
	assert.Equal(t, newDir, svc.StorageDir())

	// Directory should have been created.
	info, statErr := os.Stat(newDir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

func TestSealService_SetStorageDir_EmptyDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	err := svc.SetStorageDir("")
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

func TestSealService_SetStorageDir_RelativeDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	err := svc.SetStorageDir("relative/path")
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

func TestSealService_SetStorageDir_WorksAfterRelocation(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Seal a blob in the original directory.
	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Relocate storage.
	newDir := filepath.Join(t.TempDir(), "relocated")
	require.NoError(t, svc.SetStorageDir(newDir))

	// The old blob should not be findable (it's in the old dir).
	_, err = svc.UnsealData(entry.ID, "")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)

	// New blobs should go to the new directory.
	req2 := validSealRequest()
	req2.Label = "new-blob"
	entry2, err := svc.SealData(req2)
	require.NoError(t, err)

	// Verify file exists in new directory.
	path := filepath.Join(newDir, entry2.ID+".sealed.json")
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

func TestSealService_StorageDir(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	assert.Equal(t, dir, svc.StorageDir())
}

// ---------------------------------------------------------------------------
// MigrateFrom
// ---------------------------------------------------------------------------

func TestSealService_MigrateFrom_Success(t *testing.T) {
	// Create a source directory with sealed blobs.
	srcDir := filepath.Join(t.TempDir(), "legacy-sealed")
	require.NoError(t, os.MkdirAll(srcDir, 0700))

	blob1 := &sealedBlobStorage{
		ID:    "blob-001",
		Label: "legacy-secret-1",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data-1"),
		},
		CreatedAt: time.Now(),
	}
	blob2 := &sealedBlobStorage{
		ID:    "blob-002",
		Label: "legacy-secret-2",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("data-2"),
		},
		CreatedAt: time.Now(),
	}

	for _, blob := range []*sealedBlobStorage{blob1, blob2} {
		data, err := json.Marshal(blob)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(
			filepath.Join(srcDir, blob.ID+".sealed.json"), data, 0600))
	}

	// Create seal service with a different destination directory.
	dstDir := filepath.Join(t.TempDir(), "new-sealed")
	svc := NewSealService(dstDir)

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 2, migrated)

	// Verify blobs exist in destination.
	for _, id := range []string{"blob-001", "blob-002"} {
		path := filepath.Join(dstDir, id+".sealed.json")
		_, statErr := os.Stat(path)
		assert.NoError(t, statErr, "blob %s should exist in destination", id)
	}

	// Verify source blobs were NOT deleted (non-destructive).
	for _, id := range []string{"blob-001", "blob-002"} {
		path := filepath.Join(srcDir, id+".sealed.json")
		_, statErr := os.Stat(path)
		assert.NoError(t, statErr, "blob %s should still exist in source", id)
	}
}

func TestSealService_MigrateFrom_SkipsExistingFiles(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "legacy")
	dstDir := filepath.Join(t.TempDir(), "new")
	require.NoError(t, os.MkdirAll(srcDir, 0700))
	require.NoError(t, os.MkdirAll(dstDir, 0700))

	// Create a blob in source.
	srcContent := []byte(`{"id":"dup-001","label":"source","sealed_data":{"backend":"tpm2"}}`)
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "dup-001.sealed.json"), srcContent, 0600))

	// Create a blob with the same name but different content in destination.
	dstContent := []byte(`{"id":"dup-001","label":"destination","sealed_data":{"backend":"tpm2"}}`)
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "dup-001.sealed.json"), dstContent, 0600))

	svc := NewSealService(dstDir)
	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)

	// Verify destination content was NOT overwritten.
	data, readErr := os.ReadFile(filepath.Join(dstDir, "dup-001.sealed.json"))
	require.NoError(t, readErr)
	var blob sealedBlobStorage
	require.NoError(t, json.Unmarshal(data, &blob))
	assert.Equal(t, "destination", blob.Label)
}

func TestSealService_MigrateFrom_EmptySrcDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.MigrateFrom("")
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

func TestSealService_MigrateFrom_RelativeSrcDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.MigrateFrom("relative/path")
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

func TestSealService_MigrateFrom_SameSrcAndDst(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	migrated, err := svc.MigrateFrom(dir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_MigrateFrom_NonExistentSrcDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	migrated, err := svc.MigrateFrom(filepath.Join(t.TempDir(), "does-not-exist"))
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_MigrateFrom_EmptySrcDirectory(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "empty")
	require.NoError(t, os.MkdirAll(srcDir, 0700))

	svc := NewSealService(t.TempDir())
	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_MigrateFrom_SkipsNonJSONFiles(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "legacy")
	require.NoError(t, os.MkdirAll(srcDir, 0700))

	// Create non-JSON files.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "readme.txt"), []byte("text"), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "backup.bak"), []byte("bak"), 0600))

	svc := NewSealService(filepath.Join(t.TempDir(), "dst"))
	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_MigrateFrom_SkipsDirectories(t *testing.T) {
	srcDir := filepath.Join(t.TempDir(), "legacy")
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0700))

	// Also add a real blob to verify it still works.
	blobData := []byte(`{"id":"real-001","label":"real","sealed_data":{"backend":"tpm2"}}`)
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "real-001.sealed.json"), blobData, 0600))

	svc := NewSealService(filepath.Join(t.TempDir(), "dst"))
	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 1, migrated)
}

// ---------------------------------------------------------------------------
// CanSeal
// ---------------------------------------------------------------------------

func TestSealService_CanSeal_NoClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	result, err := svc.CanSeal()
	require.NoError(t, err)
	assert.False(t, result)
}

func TestSealService_CanSeal_BackendAvailable(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	result, err := svc.CanSeal()
	require.NoError(t, err)
	assert.True(t, result)
}

func TestSealService_CanSeal_BackendNotAvailable(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: false}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	result, err := svc.CanSeal()
	require.NoError(t, err)
	assert.False(t, result)
}

func TestSealService_CanSeal_ClientError(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return nil, ErrSealNotSupported
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	result, err := svc.CanSeal()
	require.NoError(t, err)
	assert.False(t, result)
}

// ---------------------------------------------------------------------------
// ListBlobs
// ---------------------------------------------------------------------------

func TestSealService_ListBlobs_EmptyDirectory(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSealService_ListBlobs_NonExistentDirectory(t *testing.T) {
	svc := NewSealService(filepath.Join(t.TempDir(), "nonexistent", "subdir"))
	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSealService_ListBlobs_AfterSealing(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Seal two blobs.
	req1 := validSealRequest()
	req1.Label = "first-secret"
	entry1, err := svc.SealData(req1)
	require.NoError(t, err)
	require.NotNil(t, entry1)

	// Small delay to ensure different timestamps.
	time.Sleep(10 * time.Millisecond)

	req2 := validSealRequest()
	req2.Label = "second-secret"
	entry2, err := svc.SealData(req2)
	require.NoError(t, err)
	require.NotNil(t, entry2)

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, blobs, 2)

	// Newest first.
	assert.Equal(t, "second-secret", blobs[0].Label)
	assert.Equal(t, "first-secret", blobs[1].Label)
	assert.Equal(t, string(types.BackendTypeTPM2), blobs[0].BackendID)
	assert.Equal(t, string(types.BackendTypeTPM2), blobs[1].BackendID)
}

func TestSealService_ListBlobs_SkipsNonJSON(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Create a non-JSON file in the storage directory.
	require.NoError(t, os.MkdirAll(svc.storageDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(svc.storageDir, "readme.txt"),
		[]byte("not a blob"), 0600,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSealService_ListBlobs_SkipsCorruptJSON(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Create a corrupt JSON file.
	require.NoError(t, os.MkdirAll(svc.storageDir, 0700))
	require.NoError(t, os.WriteFile(
		filepath.Join(svc.storageDir, "corrupt.json"),
		[]byte("{invalid json"), 0600,
	))

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

func TestSealService_ListBlobs_ShowsPolicyType(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	req := validSealRequest()
	req.PolicyType = "password"
	req.Password = "test-password"
	_, err := svc.SealData(req)
	require.NoError(t, err)

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Equal(t, "password", blobs[0].PolicyType)
}

func TestSealService_ListBlobs_DefaultPolicyTypeIsNone(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Create a blob with no policy type (legacy/default).
	req := validSealRequest()
	_, err := svc.SealData(req)
	require.NoError(t, err)

	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, blobs, 1)
	assert.Equal(t, "none", blobs[0].PolicyType)
}

// ---------------------------------------------------------------------------
// SealData - basic
// ---------------------------------------------------------------------------

func TestSealService_SealData_Success(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ID)
	assert.Equal(t, "test-secret", entry.Label)
	assert.Equal(t, len("hello world"), entry.SizeBytes)
	assert.False(t, entry.PCRBound)
	assert.NotEmpty(t, entry.CreatedAt)
	assert.Equal(t, "none", entry.PolicyType)
	assert.Equal(t, string(types.BackendTypeTPM2), entry.BackendID)

	// Verify the file was created on disk.
	path := svc.blobPath(entry.ID)
	_, statErr := os.Stat(path)
	assert.NoError(t, statErr)
}

func TestSealService_SealData_NilRequest(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	_, err := svc.SealData(nil)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

func TestSealService_SealData_EmptyLabel(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	req.Label = ""
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealInvalidLabel)
}

func TestSealService_SealData_EmptyData(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := &SealRequest{
		Label: "my-label",
		Data:  "",
	}
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealInvalidData)
}

func TestSealService_SealData_InvalidBase64(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := &SealRequest{
		Label: "my-label",
		Data:  "not!valid!base64!!",
	}
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealDecodeFailed)
}

func TestSealService_SealData_NoClientConfigured(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	// No client func set.
	req := validSealRequest()
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

func TestSealService_SealData_SealError(t *testing.T) {
	mc := defaultSealMockClient()
	mc.sealFn = func(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
		return nil, ErrSealStorageFailed
	}
	svc := newSealServiceWithMockClient(t, mc)
	req := validSealRequest()
	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

func TestSealService_SealData_WithPCRBinding(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := &SealRequest{
		Label:      "pcr-bound-secret",
		Data:       base64.StdEncoding.EncodeToString([]byte("sensitive data")),
		PCRs:       []int{0, 7},
		PCRBank:    "sha256",
		PolicyType: "custom_pcr",
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.True(t, entry.PCRBound)
	assert.Equal(t, "pcr-bound-secret", entry.Label)
	assert.Equal(t, len("sensitive data"), entry.SizeBytes)
	assert.Equal(t, "custom_pcr", entry.PolicyType)
}

func TestSealService_SealData_WithPCRBinding_DefaultBank(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := &SealRequest{
		Label:      "pcr-default-bank",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PCRs:       []int{0},
		PolicyType: "custom_pcr",
		// PCRBank intentionally empty - should default to sha256.
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.True(t, entry.PCRBound)
}

func TestSealService_SealData_NilContext(t *testing.T) {
	mc := defaultSealMockClient()
	svc := NewSealService(t.TempDir())
	svc.SetClientFunc(func() xkms.Client { return mc })
	// Deliberately do NOT call SetContext.
	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
}

func TestSealService_SealData_WithExplicitBackend(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	req := validSealRequest()
	req.Backend = string(types.BackendTypeTPM2)

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, entry)
	assert.NotEmpty(t, entry.ID)
}

// ---------------------------------------------------------------------------
// SealData - policy types
// ---------------------------------------------------------------------------

func TestSealService_SealData_PolicyTypeNone(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	req.PolicyType = "none"

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "none", entry.PolicyType)
	assert.False(t, entry.PCRBound)
}

func TestSealService_SealData_PolicyTypePassword_Success(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	req.PolicyType = "password"
	req.Password = "my-secret-password"

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "password", entry.PolicyType)

	// Verify the password hash was stored on disk.
	blob, loadErr := svc.loadBlobByID(entry.ID)
	require.NoError(t, loadErr)
	assert.NotEmpty(t, blob.Password)
	assert.Contains(t, blob.Password, ":")
}

func TestSealService_SealData_PolicyTypePassword_EmptyPassword(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	req.PolicyType = "password"
	req.Password = ""

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

func TestSealService_SealData_PolicyTypePlatformPolicy_Success(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Set up platform policy service with a configured policy.
	policyMock := defaultPolicyMock()
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	policySvc := NewPlatformPolicyService(policyPath)
	policySvc.SetTPMAccessor(NewTPMAccessor(func() tpm2pkg.TrustedPlatformModule { return policyMock }))

	_, err := policySvc.CreatePolicy([]int{0, 7}, "sha256")
	require.NoError(t, err)

	svc.SetPlatformPolicyService(policySvc)

	req := validSealRequest()
	req.PolicyType = "platform_policy"

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "platform_policy", entry.PolicyType)
	assert.True(t, entry.PCRBound)
}

func TestSealService_SealData_PolicyTypePlatformPolicy_NoPolicyConfigured(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	// No platform policy service set.
	req := validSealRequest()
	req.PolicyType = "platform_policy"

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}

func TestSealService_SealData_PolicyTypePlatformPolicy_PolicyServiceNotConfigured(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Set up a policy service but do NOT create a policy.
	policyPath := filepath.Join(t.TempDir(), "platform.policy")
	policySvc := NewPlatformPolicyService(policyPath)
	svc.SetPlatformPolicyService(policySvc)

	req := validSealRequest()
	req.PolicyType = "platform_policy"

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}

func TestSealService_SealData_PolicyTypeCustomPCR(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := &SealRequest{
		Label:      "custom-pcr-secret",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PCRs:       []int{0, 1, 7},
		PCRBank:    "sha256",
		PolicyType: "custom_pcr",
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "custom_pcr", entry.PolicyType)
	assert.True(t, entry.PCRBound)
}

func TestSealService_SealData_InvalidPolicyType(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	req.PolicyType = "nonexistent_policy"

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealInvalidPolicyType)
}

func TestSealService_SealData_DefaultPolicyTypeIsNone(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	req := validSealRequest()
	// PolicyType intentionally empty.

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "none", entry.PolicyType)
}

func TestSealService_SealData_TPMOnlyPolicyWithNonTPMBackend(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Try to seal with platform_policy using the software backend.
	req := validSealRequest()
	req.PolicyType = "platform_policy"
	req.Backend = "software"

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealPolicyRequiresTPM)
}

func TestSealService_SealData_CustomPCRPolicyWithNonTPMBackend(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Try to seal with custom_pcr using the software backend.
	req := &SealRequest{
		Label:      "test",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PCRs:       []int{0, 7},
		PCRBank:    "sha256",
		PolicyType: "custom_pcr",
		Backend:    "software",
	}

	_, err := svc.SealData(req)
	assert.ErrorIs(t, err, ErrSealPolicyRequiresTPM)
}

// ---------------------------------------------------------------------------
// SealData - SDK transport field verification
// ---------------------------------------------------------------------------

func TestSealService_SealData_SDKRequestReceivesCorrectParams(t *testing.T) {
	var capturedReq *transport.SealRequest
	mc := defaultSealMockClient()
	mc.sealFn = func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
		capturedReq = req
		return &transport.SealResponse{
			Backend:    req.Backend,
			Ciphertext: req.Data,
		}, nil
	}
	svc := newSealServiceWithMockClient(t, mc)

	req := &SealRequest{
		Label:      "param-test",
		Data:       base64.StdEncoding.EncodeToString([]byte("my-data")),
		PCRs:       []int{0, 7},
		PCRBank:    "sha256",
		PolicyType: "custom_pcr",
	}
	_, err := svc.SealData(req)
	require.NoError(t, err)
	require.NotNil(t, capturedReq)

	assert.Equal(t, string(types.BackendTypeTPM2), capturedReq.Backend)
	assert.Equal(t, []byte("my-data"), capturedReq.Data)
	assert.Equal(t, "sha256", capturedReq.PCRHashAlg)
	assert.Contains(t, capturedReq.PCRs, 0)
	assert.Contains(t, capturedReq.PCRs, 7)
}

func TestSealService_SealData_TPMFieldsPreserved(t *testing.T) {
	mc := &sealMockClient{
		sealFn: func(_ context.Context, req *transport.SealRequest) (*transport.SealResponse, error) {
			return &transport.SealResponse{
				Backend:    req.Backend,
				Ciphertext: req.Data,
				Nonce:      []byte("test-nonce"),
				Tag:        []byte("test-tag"),
				TPMPublic:  []byte("tpm-pub-area"),
				TPMPrivate: []byte("tpm-priv-area"),
				WrappedDEK: []byte("wrapped-dek"),
				KeyID:      "srk-001",
				Metadata:   map[string][]byte{"tpm:ticket": []byte("ticket-data")},
			}, nil
		},
		unsealFn: func(_ context.Context, req *transport.UnsealRequest) (*transport.UnsealResponse, error) {
			// Verify all TPM fields were forwarded.
			assert.Equal(t, []byte("test-nonce"), req.Nonce)
			assert.Equal(t, []byte("test-tag"), req.Tag)
			assert.Equal(t, []byte("tpm-pub-area"), req.TPMPublic)
			assert.Equal(t, []byte("tpm-priv-area"), req.TPMPrivate)
			assert.Equal(t, []byte("wrapped-dek"), req.WrappedDEK)
			assert.Equal(t, []byte("ticket-data"), req.Metadata["tpm:ticket"])
			return &transport.UnsealResponse{Plaintext: req.Ciphertext}, nil
		},
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}

	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Verify stored blob has all TPM fields.
	blob, loadErr := svc.loadBlobByID(entry.ID)
	require.NoError(t, loadErr)
	assert.Equal(t, []byte("tpm-pub-area"), blob.SealedData.TPMPublic)
	assert.Equal(t, []byte("tpm-priv-area"), blob.SealedData.TPMPrivate)
	assert.Equal(t, []byte("wrapped-dek"), blob.SealedData.WrappedDEK)
	assert.Equal(t, "srk-001", blob.SealedData.KeyID)
	assert.Equal(t, []byte("ticket-data"), blob.SealedData.Metadata["tpm:ticket"])

	// Unseal verifies the fields round-trip correctly (assertions in unsealFn).
	_, err = svc.UnsealData(entry.ID, "")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// UnsealData - basic
// ---------------------------------------------------------------------------

func TestSealService_UnsealData_Success(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Seal first.
	original := "hello world"
	req := &SealRequest{
		Label: "unseal-test",
		Data:  base64.StdEncoding.EncodeToString([]byte(original)),
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Unseal.
	b64result, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)

	decoded, decErr := base64.StdEncoding.DecodeString(b64result)
	require.NoError(t, decErr)
	assert.Equal(t, original, string(decoded))
}

func TestSealService_UnsealData_EmptyID(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	_, err := svc.UnsealData("", "")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_UnsealData_NonExistentID(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	_, err := svc.UnsealData("does-not-exist", "")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_UnsealData_NoClientConfigured(t *testing.T) {
	// Seal with a client, then remove the client and try to unseal.
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Remove the client.
	svc.SetClientFunc(nil)

	_, err = svc.UnsealData(entry.ID, "")
	assert.ErrorIs(t, err, ErrSealBackendNotFound)
}

func TestSealService_UnsealData_UnsealError(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	// Seal first.
	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Set the unseal error after sealing succeeds.
	mc.unsealFn = func(_ context.Context, _ *transport.UnsealRequest) (*transport.UnsealResponse, error) {
		return nil, ErrSealNotSupported
	}

	_, err = svc.UnsealData(entry.ID, "")
	assert.ErrorIs(t, err, ErrSealNotSupported)
}

func TestSealService_UnsealData_NilContext(t *testing.T) {
	mc := defaultSealMockClient()
	svc := NewSealService(t.TempDir())
	svc.SetClientFunc(func() xkms.Client { return mc })
	// Deliberately do NOT call SetContext.

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	b64result, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)
	assert.NotEmpty(t, b64result)
}

func TestSealService_UnsealData_BackwardCompatEmptyBackend(t *testing.T) {
	mc := defaultSealMockClient()
	svc := newSealServiceWithMockClient(t, mc)

	// Create a blob file manually with empty Backend (simulates pre-Phase 3 blob).
	blob := &sealedBlobStorage{
		ID:    "legacy-blob",
		Label: "legacy",
		SealedData: &types.SealedData{
			Backend:    "", // empty = pre-Phase 3
			Ciphertext: []byte("old-data"),
			TPMPublic:  []byte("pub"),
			TPMPrivate: []byte("priv"),
		},
		CreatedAt: time.Now(),
	}
	require.NoError(t, svc.saveBlob(blob))

	// UnsealData should fall back to the default backend (tpm2).
	b64result, err := svc.UnsealData("legacy-blob", "")
	require.NoError(t, err)

	decoded, decErr := base64.StdEncoding.DecodeString(b64result)
	require.NoError(t, decErr)
	assert.Equal(t, "old-data", string(decoded))
}

// ---------------------------------------------------------------------------
// UnsealData - password policy
// ---------------------------------------------------------------------------

func TestSealService_UnsealData_PasswordCorrect(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	original := "secret payload"
	req := &SealRequest{
		Label:      "password-protected",
		Data:       base64.StdEncoding.EncodeToString([]byte(original)),
		PolicyType: "password",
		Password:   "correct-password",
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	b64result, err := svc.UnsealData(entry.ID, "correct-password")
	require.NoError(t, err)

	decoded, decErr := base64.StdEncoding.DecodeString(b64result)
	require.NoError(t, decErr)
	assert.Equal(t, original, string(decoded))
}

func TestSealService_UnsealData_PasswordIncorrect(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	req := &SealRequest{
		Label:      "password-protected",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PolicyType: "password",
		Password:   "correct-password",
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	_, err = svc.UnsealData(entry.ID, "wrong-password")
	assert.ErrorIs(t, err, ErrSealPolicyMismatch)
}

func TestSealService_UnsealData_PasswordRequired(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	req := &SealRequest{
		Label:      "password-protected",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PolicyType: "password",
		Password:   "my-password",
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	_, err = svc.UnsealData(entry.ID, "")
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

func TestSealService_UnsealData_NonPasswordBlobIgnoresPassword(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Passing a password when blob is not password-protected should work fine.
	b64result, err := svc.UnsealData(entry.ID, "some-password")
	require.NoError(t, err)
	assert.NotEmpty(t, b64result)
}

// ---------------------------------------------------------------------------
// DeleteBlob
// ---------------------------------------------------------------------------

func TestSealService_DeleteBlob_Success(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Seal first.
	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Verify file exists.
	path := svc.blobPath(entry.ID)
	_, statErr := os.Stat(path)
	require.NoError(t, statErr)

	// Delete.
	err = svc.DeleteBlob(entry.ID)
	require.NoError(t, err)

	// Verify file is removed.
	_, statErr = os.Stat(path)
	assert.True(t, os.IsNotExist(statErr))
}

func TestSealService_DeleteBlob_EmptyID(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	err := svc.DeleteBlob("")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_DeleteBlob_NonExistentID(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	err := svc.DeleteBlob("does-not-exist")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_DeleteBlob_VerifyListAfterDelete(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	// Seal.
	req := validSealRequest()
	entry, err := svc.SealData(req)
	require.NoError(t, err)

	// Confirm listed.
	blobs, err := svc.ListBlobs()
	require.NoError(t, err)
	require.Len(t, blobs, 1)

	// Delete.
	err = svc.DeleteBlob(entry.ID)
	require.NoError(t, err)

	// Confirm empty list.
	blobs, err = svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, blobs)
}

// ---------------------------------------------------------------------------
// Storage helpers
// ---------------------------------------------------------------------------

func TestSealService_blobPath(t *testing.T) {
	svc := NewSealService("/tmp/seals")
	assert.Equal(t, "/tmp/seals/abc123.sealed.json", svc.blobPath("abc123"))
}

func TestSealService_saveBlob_And_loadBlob(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	blob := &sealedBlobStorage{
		ID:    "test-blob-001",
		Label: "test-label",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeTPM2,
			Ciphertext: []byte("sealed-data"),
			TPMPublic:  []byte("public"),
			TPMPrivate: []byte("private"),
		},
		CreatedAt: time.Now(),
	}

	// Save.
	require.NoError(t, svc.saveBlob(blob))

	// Load.
	loaded, err := svc.loadBlobByID("test-blob-001")
	require.NoError(t, err)
	assert.Equal(t, blob.ID, loaded.ID)
	assert.Equal(t, blob.Label, loaded.Label)
	assert.Equal(t, blob.SealedData.Ciphertext, loaded.SealedData.Ciphertext)
	assert.Equal(t, blob.SealedData.TPMPublic, loaded.SealedData.TPMPublic)
	assert.Equal(t, blob.SealedData.TPMPrivate, loaded.SealedData.TPMPrivate)
}

func TestSealService_loadBlobByID_NotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.loadBlobByID("nonexistent")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// ---------------------------------------------------------------------------
// AvailableSealers
// ---------------------------------------------------------------------------

func TestSealService_AvailableSealers_AllAvailable(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)

	infos := svc.AvailableSealers()
	require.Len(t, infos, len(knownSealerMeta))

	// All should be available.
	for _, info := range infos {
		assert.True(t, info.Available, "backend %s should be available", info.ID)
	}

	// Sorted alphabetically by label.
	if len(infos) >= 2 {
		assert.LessOrEqual(t, infos[0].Label, infos[1].Label)
	}
}

func TestSealService_AvailableSealers_OnlyTPM(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())

	infos := svc.AvailableSealers()
	// Only TPM2 is available in the default mock, so only 1 entry returned.
	require.Len(t, infos, 1)

	tpmInfo := infos[0]
	assert.Equal(t, string(types.BackendTypeTPM2), tpmInfo.ID)
	assert.True(t, tpmInfo.Available)
	assert.True(t, tpmInfo.IsDefault)
	assert.True(t, tpmInfo.HardwareBacked)
}

func TestSealService_AvailableSealers_NoClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	infos := svc.AvailableSealers()
	// No client means no backends can be checked; empty result.
	require.Empty(t, infos)
}

func TestSealService_AvailableSealers_Details(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	infos := svc.AvailableSealers()

	require.Len(t, infos, len(knownSealerMeta))
	for _, info := range infos {
		assert.NotNil(t, info.Details)
		assert.NotEmpty(t, info.Label)
		assert.NotEmpty(t, info.Description)
	}
}

// ---------------------------------------------------------------------------
// BestSealer
// ---------------------------------------------------------------------------

func TestSealService_BestSealer_ReturnsHighestAvailable(t *testing.T) {
	svc := newSealServiceWithMockClient(t, defaultSealMockClient())
	best := svc.BestSealer()
	require.NotNil(t, best)
	assert.True(t, best.Available)
	assert.Equal(t, string(types.BackendTypeTPM2), best.ID)
}

func TestSealService_BestSealer_NoneAvailable(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: false}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	best := svc.BestSealer()
	assert.Nil(t, best)
}

// ---------------------------------------------------------------------------
// autoSelectDefault
// ---------------------------------------------------------------------------

func TestSealService_AutoSelectDefault_SelectsHighestLevel(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			// Only software is available.
			if backend == string(types.BackendTypeSoftware) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	svc.autoSelectDefault()
	assert.Equal(t, string(types.BackendTypeSoftware), svc.DefaultBackend())
}

func TestSealService_AutoSelectDefault_TPMPreferred(t *testing.T) {
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc := newSealServiceWithMockClient(t, mc)
	svc.autoSelectDefault()
	assert.Equal(t, string(types.BackendTypeTPM2), svc.DefaultBackend())
}

func TestSealService_AutoSelectDefault_NoClient(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// default is tpm2.
	svc.autoSelectDefault()
	// Should not change since there's no client.
	assert.Equal(t, string(types.BackendTypeTPM2), svc.DefaultBackend())
}

// ---------------------------------------------------------------------------
// PCR conversion helpers
// ---------------------------------------------------------------------------

func TestPcrSelectToInts(t *testing.T) {
	// Byte 0 = 0b10000001 = PCR 0 and PCR 7
	sel := []byte{0x81}
	result := pcrSelectToInts(sel)
	assert.Equal(t, []int{0, 7}, result)
}

func TestPcrSelectToInts_Empty(t *testing.T) {
	result := pcrSelectToInts(nil)
	assert.Empty(t, result)
}

func TestPcrSelectToInts_MultipleBits(t *testing.T) {
	// Byte 0 = 0xFF (PCR 0-7), Byte 1 = 0x01 (PCR 8)
	sel := []byte{0xFF, 0x01}
	result := pcrSelectToInts(sel)
	assert.Len(t, result, 9)
	assert.Equal(t, 0, result[0])
	assert.Equal(t, 7, result[7])
	assert.Equal(t, 8, result[8])
}

func TestHashAlgIDToString(t *testing.T) {
	tests := []struct {
		name string
		alg  uint16
		want string
	}{
		{"sha1", 0x0004, "sha1"},
		{"sha256", 0x000B, "sha256"},
		{"sha384", 0x000C, "sha384"},
		{"sha512", 0x000D, "sha512"},
		{"unknown", 0xFFFF, "sha256"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// TPMAlgID is a uint16 type alias.
			result := hashAlgIDToString(tpm2.TPMAlgID(tc.alg))
			assert.Equal(t, tc.want, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Password hashing helpers
// ---------------------------------------------------------------------------

func TestHashPassword(t *testing.T) {
	hash, err := hashPassword("test-password")
	require.NoError(t, err)
	assert.Contains(t, hash, ":")
	assert.True(t, verifyPassword("test-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

func TestVerifyPassword_InvalidFormat(t *testing.T) {
	assert.False(t, verifyPassword("password", "no-colon-here"))
}

func TestVerifyPassword_InvalidSaltHex(t *testing.T) {
	assert.False(t, verifyPassword("password", "not-hex:0000"))
}

func TestVerifyPassword_InvalidHashHex(t *testing.T) {
	assert.False(t, verifyPassword("password", "0000:not-hex"))
}

func TestSplitPasswordHash(t *testing.T) {
	parts := splitPasswordHash("salt:hash")
	require.NotNil(t, parts)
	assert.Equal(t, "salt", parts[0])
	assert.Equal(t, "hash", parts[1])
}

func TestSplitPasswordHash_NoColon(t *testing.T) {
	parts := splitPasswordHash("nocolon")
	assert.Nil(t, parts)
}

// ---------------------------------------------------------------------------
// Category classification
// ---------------------------------------------------------------------------

func TestClassifyCategory_SystemLabels(t *testing.T) {
	assert.Equal(t, "system", classifyCategory("password_master_key"))
	assert.Equal(t, "system", classifyCategory("auto-unseal-passphrase"))
	assert.Equal(t, "system", classifyCategory("barrier_password"))
}

func TestClassifyCategory_UserLabels(t *testing.T) {
	assert.Equal(t, "user", classifyCategory("my-secret"))
	assert.Equal(t, "user", classifyCategory("user_pin"))
}

// ---------------------------------------------------------------------------
// Error sentinel tests
// ---------------------------------------------------------------------------

func TestSealServiceErrors_Distinct(t *testing.T) {
	errs := []error{
		ErrSealTPMNotAvailable,
		ErrSealNotSupported,
		ErrSealInvalidLabel,
		ErrSealInvalidData,
		ErrSealBlobNotFound,
		ErrSealStorageFailed,
		ErrSealDecodeFailed,
		ErrSealMarshalFailed,
		ErrSealUnmarshalFailed,
		ErrSealInvalidPolicyType,
		ErrSealPasswordRequired,
		ErrSealPolicyMismatch,
		ErrSealPolicyNotAvailable,
		ErrSealStorageDirNotSet,
		ErrSealStorageDirRelative,
		ErrSealBackendNotFound,
		ErrSealPolicyRequiresTPM,
		ErrSealMigrationFailed,
		ErrSealNoClient,
	}
	for i := range errs {
		for j := range errs {
			if i == j {
				continue
			}
			assert.NotEqual(t, errs[i], errs[j],
				"errors %d and %d should be distinct", i, j)
		}
	}
}
