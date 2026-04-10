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
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/audit"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// sealCoverageAuditLogger -- audit logger for coverage tests
// ---------------------------------------------------------------------------

type sealCoverageAuditLogger struct {
	entries []audit.Entry
}

func (l *sealCoverageAuditLogger) Log(e audit.Entry) { l.entries = append(l.entries, e) }
func (l *sealCoverageAuditLogger) LogKeyOperation(audit.OperationType, string, string, bool, error, int64) {
}
func (l *sealCoverageAuditLogger) LogCryptoOperation(audit.OperationType, string, string, string, string, bool, error, int64) {
}
func (l *sealCoverageAuditLogger) LogConnectionEvent(audit.OperationType, string, string, map[string]any) {
}
func (l *sealCoverageAuditLogger) LogServiceEvent(audit.OperationType, map[string]any) {}
func (l *sealCoverageAuditLogger) LogPINOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *sealCoverageAuditLogger) LogTPMOperation(audit.OperationType, bool, error, map[string]any) {
}
func (l *sealCoverageAuditLogger) LogPasswordStoreOperation(audit.OperationType, string, bool, error, map[string]any) {
}
func (l *sealCoverageAuditLogger) LogUserPresenceEvent(audit.OperationType, string, bool, map[string]any) {
}

// ---------------------------------------------------------------------------
// SetBackend / Backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SetBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	assert.Nil(t, svc.Backend())

	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	assert.Equal(t, backend, svc.Backend())
	assert.Equal(t, "sealed/", svc.blobPrefix)
}

func TestSealService_Coverage_SetBackend_NilClears(t *testing.T) {
	svc := NewSealService(t.TempDir())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")
	assert.NotNil(t, svc.Backend())

	svc.SetBackend(nil, "")
	assert.Nil(t, svc.Backend())
}

// ---------------------------------------------------------------------------
// SetAuditLogger / logSealEvent
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SetAuditLogger(t *testing.T) {
	svc := NewSealService(t.TempDir())
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	p := svc.auditLog.Load()
	assert.NotNil(t, p)
}

func TestSealService_Coverage_LogSealEvent_WithLogger(t *testing.T) {
	svc := NewSealService(t.TempDir())
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	svc.logSealEvent(audit.OpSealData, true, nil, map[string]any{"label": "test"})
	assert.Len(t, logger.entries, 1)
	assert.True(t, logger.entries[0].Success)
}

func TestSealService_Coverage_LogSealEvent_WithError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	testErr := errors.New("seal failed")
	svc.logSealEvent(audit.OpSealData, false, testErr, map[string]any{"label": "test"})
	assert.Len(t, logger.entries, 1)
	assert.False(t, logger.entries[0].Success)
	assert.Equal(t, "seal failed", logger.entries[0].Error)
}

func TestSealService_Coverage_LogSealEvent_NoLogger(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// Should not panic when no logger is set.
	svc.logSealEvent(audit.OpSealData, true, nil, nil)
}

// ---------------------------------------------------------------------------
// DefaultBackend / SetDefaultBackend / AutoSelectDefault
// ---------------------------------------------------------------------------

func TestSealService_Coverage_DefaultBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	assert.Equal(t, string(types.BackendTypeTPM2), svc.DefaultBackend())
}

func TestSealService_Coverage_SetDefaultBackend_Custom(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetDefaultBackend("pkcs11")
	assert.Equal(t, "pkcs11", svc.DefaultBackend())
}

func TestSealService_Coverage_AutoSelectDefault_NoAvailable(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: false}, nil
		},
	}
	svc.SetLocalClient(mc)

	original := svc.DefaultBackend()
	svc.AutoSelectDefault()
	// Should remain unchanged when no backends are available.
	assert.Equal(t, original, svc.DefaultBackend())
}

func TestSealService_Coverage_AutoSelectDefault_SelectsSoftware(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			if backend == string(types.BackendTypeSoftware) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	svc.AutoSelectDefault()
	assert.Equal(t, string(types.BackendTypeSoftware), svc.DefaultBackend())
}

func TestSealService_Coverage_AutoSelectDefault_PrefersTPM(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	svc.AutoSelectDefault()
	assert.Equal(t, string(types.BackendTypeTPM2), svc.DefaultBackend())
}

// ---------------------------------------------------------------------------
// BestSealer
// ---------------------------------------------------------------------------

func TestSealService_Coverage_BestSealer_SoftwareOnly(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			if backend == string(types.BackendTypeSoftware) {
				return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
			}
			return &transport.CanSealResponse{CanSeal: false, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	best := svc.BestSealer()
	require.NotNil(t, best)
	assert.Equal(t, string(types.BackendTypeSoftware), best.ID)
}

func TestSealService_Coverage_BestSealer_NoneAvailable(t *testing.T) {
	svc := NewSealService(t.TempDir())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: false}, nil
		},
	}
	svc.SetLocalClient(mc)

	best := svc.BestSealer()
	assert.Nil(t, best)
}

// ---------------------------------------------------------------------------
// CanSeal edge cases
// ---------------------------------------------------------------------------

func TestSealService_Coverage_CanSeal_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// ctx is nil by default
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true}, nil
		},
	}
	svc.SetLocalClient(mc)

	canSeal, err := svc.CanSeal()
	require.NoError(t, err)
	assert.True(t, canSeal)
}

func TestSealService_Coverage_CanSeal_ClientError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return nil, errors.New("client error")
		},
	}
	svc.SetLocalClient(mc)

	canSeal, err := svc.CanSeal()
	require.NoError(t, err) // CanSeal swallows errors
	assert.False(t, canSeal)
}

// ---------------------------------------------------------------------------
// sealerDetails
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealerDetails(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)

	t.Run("software", func(t *testing.T) {
		details := svc.sealerDetails(string(types.BackendTypeSoftware))
		assert.Equal(t, dir, details["storage_dir"])
	})

	t.Run("tpm2", func(t *testing.T) {
		details := svc.sealerDetails(string(types.BackendTypeTPM2))
		assert.Equal(t, "0x81000002", details["srk_handle"])
		assert.Equal(t, dir, details["storage_dir"])
	})

	t.Run("pkcs11", func(t *testing.T) {
		details := svc.sealerDetails(string(types.BackendTypePKCS11))
		assert.Empty(t, details, "pkcs11 is not a sealer, no details expected")
	})

	t.Run("unknown", func(t *testing.T) {
		details := svc.sealerDetails("unknown-backend")
		assert.Empty(t, details)
	})
}

// ---------------------------------------------------------------------------
// classifyCategory
// ---------------------------------------------------------------------------

func TestSealService_Coverage_ClassifyCategory(t *testing.T) {
	assert.Equal(t, "system", classifyCategory("password_master_key"))
	assert.Equal(t, "system", classifyCategory("auto-unseal-passphrase"))
	assert.Equal(t, "system", classifyCategory("barrier_password"))
	assert.Equal(t, "user", classifyCategory("my-secret"))
	assert.Equal(t, "user", classifyCategory("user_pin"))
	assert.Equal(t, "user", classifyCategory(""))
}

// ---------------------------------------------------------------------------
// blobToEntry
// ---------------------------------------------------------------------------

func TestSealService_Coverage_BlobToEntry_DefaultValues(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:        "test-id",
		Label:     "test-label",
		SizeBytes: 100,
		CreatedAt: time.Now(),
	}
	entry := blobToEntry(blob)

	assert.Equal(t, "test-id", entry.ID)
	assert.Equal(t, "test-label", entry.Label)
	assert.Equal(t, 100, entry.SizeBytes)
	assert.Equal(t, string(PolicyTypeNone), entry.PolicyType)   // default
	assert.Equal(t, "user", entry.Category)                     // default for non-system label
	assert.Equal(t, string(StorageTypeDisk), entry.StorageType) // default
}

func TestSealService_Coverage_BlobToEntry_AllFields(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:          "full-id",
		Label:       "password_master_key",
		SizeBytes:   256,
		PCRBound:    true,
		PolicyType:  "password",
		Category:    "system",
		BackendID:   "tpm2",
		StorageType: "nvram",
		CreatedAt:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	entry := blobToEntry(blob)

	assert.Equal(t, "full-id", entry.ID)
	assert.Equal(t, "password_master_key", entry.Label)
	assert.Equal(t, 256, entry.SizeBytes)
	assert.True(t, entry.PCRBound)
	assert.Equal(t, "password", entry.PolicyType)
	assert.Equal(t, "system", entry.Category)
	assert.Equal(t, "tpm2", entry.BackendID)
	assert.Equal(t, "nvram", entry.StorageType)
	assert.Equal(t, "2025-01-01T00:00:00Z", entry.CreatedAt)
}

func TestSealService_Coverage_BlobToEntry_SystemCategory(t *testing.T) {
	blob := &sealedBlobStorage{
		ID:        "sys-id",
		Label:     "barrier_password",
		CreatedAt: time.Now(),
	}
	entry := blobToEntry(blob)
	assert.Equal(t, "system", entry.Category)
}

// ---------------------------------------------------------------------------
// sortAndCollectEntries
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SortAndCollectEntries_Empty(t *testing.T) {
	result := sortAndCollectEntries(nil)
	assert.Empty(t, result)
}

func TestSealService_Coverage_SortAndCollectEntries_Sorted(t *testing.T) {
	now := time.Now()
	items := []blobWithTime{
		{entry: SealedBlobEntry{ID: "oldest"}, createdAt: now.Add(-2 * time.Hour)},
		{entry: SealedBlobEntry{ID: "newest"}, createdAt: now},
		{entry: SealedBlobEntry{ID: "middle"}, createdAt: now.Add(-1 * time.Hour)},
	}

	result := sortAndCollectEntries(items)
	require.Len(t, result, 3)
	assert.Equal(t, "newest", result[0].ID)
	assert.Equal(t, "middle", result[1].ID)
	assert.Equal(t, "oldest", result[2].ID)
}

// ---------------------------------------------------------------------------
// pcrSelectToInts
// ---------------------------------------------------------------------------

func TestSealService_Coverage_PcrSelectToInts_SingleByte(t *testing.T) {
	// 0x81 = bit 0 and bit 7 set -> PCR 0 and PCR 7
	result := pcrSelectToInts([]byte{0x81})
	assert.Equal(t, []int{0, 7}, result)
}

func TestSealService_Coverage_PcrSelectToInts_MultiByte(t *testing.T) {
	// byte 0: 0x01 = PCR 0; byte 1: 0x01 = PCR 8; byte 2: 0x80 = PCR 23
	result := pcrSelectToInts([]byte{0x01, 0x01, 0x80})
	assert.Equal(t, []int{0, 8, 23}, result)
}

func TestSealService_Coverage_PcrSelectToInts_Empty(t *testing.T) {
	result := pcrSelectToInts(nil)
	assert.Nil(t, result)
}

func TestSealService_Coverage_PcrSelectToInts_AllZeros(t *testing.T) {
	result := pcrSelectToInts([]byte{0x00, 0x00})
	assert.Nil(t, result)
}

// ---------------------------------------------------------------------------
// hashAlgIDToString
// ---------------------------------------------------------------------------

func TestSealService_Coverage_HashAlgIDToString(t *testing.T) {
	assert.Equal(t, "sha1", hashAlgIDToString(tpm2.TPMAlgSHA1))
	assert.Equal(t, "sha256", hashAlgIDToString(tpm2.TPMAlgSHA256))
	assert.Equal(t, "sha384", hashAlgIDToString(tpm2.TPMAlgSHA384))
	assert.Equal(t, "sha512", hashAlgIDToString(tpm2.TPMAlgSHA512))
	assert.Equal(t, "sha256", hashAlgIDToString(tpm2.TPMAlgID(0xFFFF))) // unknown defaults to sha256
}

// ---------------------------------------------------------------------------
// Policy handlers
// ---------------------------------------------------------------------------

func TestSealService_Coverage_HandlePolicyNone(t *testing.T) {
	err := handlePolicyNone(nil, nil, nil)
	assert.NoError(t, err)
}

func TestSealService_Coverage_HandlePolicyPassword_Empty(t *testing.T) {
	req := &SealRequest{Password: ""}
	err := handlePolicyPassword(nil, req, nil)
	assert.ErrorIs(t, err, ErrSealPasswordRequired)
}

func TestSealService_Coverage_HandlePolicyPassword_Valid(t *testing.T) {
	req := &SealRequest{Password: "mysecret"}
	err := handlePolicyPassword(nil, req, nil)
	assert.NoError(t, err)
}

func TestSealService_Coverage_HandlePolicyCustomPCR_NoPCRs(t *testing.T) {
	req := &SealRequest{}
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, req, opts)
	assert.NoError(t, err)
	assert.Nil(t, opts.TPMPolicy) // No PCRs = no policy set
}

func TestSealService_Coverage_HandlePolicyCustomPCR_WithPCRs(t *testing.T) {
	req := &SealRequest{
		PCRs:    []int{0, 7},
		PCRBank: "sha256",
	}
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, req, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
	assert.Equal(t, tpm2.TPMAlgSHA256, opts.TPMPolicy.HashAlg)
}

func TestSealService_Coverage_HandlePolicyCustomPCR_DefaultBank(t *testing.T) {
	req := &SealRequest{
		PCRs:    []int{0},
		PCRBank: "", // should default to sha256
	}
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, req, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
	assert.Equal(t, tpm2.TPMAlgSHA256, opts.TPMPolicy.HashAlg)
}

func TestSealService_Coverage_HandlePolicyCustomPCR_UnknownBank(t *testing.T) {
	req := &SealRequest{
		PCRs:    []int{0},
		PCRBank: "md5", // not in pcrBankAlgMap
	}
	opts := &types.SealOptions{}
	err := handlePolicyCustomPCR(nil, req, opts)
	assert.NoError(t, err)
	require.NotNil(t, opts.TPMPolicy)
	assert.Equal(t, tpm2.TPMAlgSHA256, opts.TPMPolicy.HashAlg) // defaults to sha256
}

func TestSealService_Coverage_HandlePolicyPlatformPolicy_NilService(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.policyService = nil

	err := handlePolicyPlatformPolicy(svc, &SealRequest{}, &types.SealOptions{})
	assert.ErrorIs(t, err, ErrSealPolicyNotAvailable)
}

// ---------------------------------------------------------------------------
// hashPassword / verifyPassword / splitPasswordHash
// ---------------------------------------------------------------------------

func TestSealService_Coverage_HashPassword_Unique(t *testing.T) {
	hash1, err1 := hashPassword("test-password")
	hash2, err2 := hashPassword("test-password")
	require.NoError(t, err1)
	require.NoError(t, err2)

	// Different salt should produce different hashes.
	assert.NotEqual(t, hash1, hash2)
}

func TestSealService_Coverage_VerifyPassword_Success(t *testing.T) {
	hash, err := hashPassword("correct-password")
	require.NoError(t, err)

	assert.True(t, verifyPassword("correct-password", hash))
	assert.False(t, verifyPassword("wrong-password", hash))
}

func TestSealService_Coverage_VerifyPassword_EmptyStored(t *testing.T) {
	assert.False(t, verifyPassword("test", ""))
}

func TestSealService_Coverage_VerifyPassword_NoColon(t *testing.T) {
	assert.False(t, verifyPassword("test", "nocolonhere"))
}

func TestSealService_Coverage_VerifyPassword_BadSaltHex(t *testing.T) {
	assert.False(t, verifyPassword("test", "zzzz:abcd"))
}

func TestSealService_Coverage_VerifyPassword_BadHashHex(t *testing.T) {
	assert.False(t, verifyPassword("test", "abcd:zzzz"))
}

func TestSealService_Coverage_SplitPasswordHash_Valid(t *testing.T) {
	parts := splitPasswordHash("salt:hash")
	require.NotNil(t, parts)
	assert.Equal(t, "salt", parts[0])
	assert.Equal(t, "hash", parts[1])
}

func TestSealService_Coverage_SplitPasswordHash_NoColon(t *testing.T) {
	assert.Nil(t, splitPasswordHash("nocolon"))
}

func TestSealService_Coverage_SplitPasswordHash_EmptyString(t *testing.T) {
	assert.Nil(t, splitPasswordHash(""))
}

func TestSealService_Coverage_SplitPasswordHash_MultipleColons(t *testing.T) {
	parts := splitPasswordHash("a:b:c")
	require.NotNil(t, parts)
	assert.Equal(t, "a", parts[0])
	assert.Equal(t, "b:c", parts[1])
}

// ---------------------------------------------------------------------------
// StorageDir / SetStorageDir
// ---------------------------------------------------------------------------

func TestSealService_Coverage_StorageDir_ReturnsInitialValue(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	assert.Equal(t, dir, svc.StorageDir())
}

func TestSealService_Coverage_SetStorageDir_CreatesDir(t *testing.T) {
	svc := NewSealService(t.TempDir())
	newDir := filepath.Join(t.TempDir(), "new-seal-dir")

	err := svc.SetStorageDir(newDir)
	require.NoError(t, err)
	assert.Equal(t, newDir, svc.StorageDir())

	info, statErr := os.Stat(newDir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

// ---------------------------------------------------------------------------
// ensureStorageDir
// ---------------------------------------------------------------------------

func TestSealService_Coverage_EnsureStorageDir_Empty(t *testing.T) {
	svc := NewSealService("")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirNotSet)
}

func TestSealService_Coverage_EnsureStorageDir_Relative(t *testing.T) {
	svc := NewSealService("relative/path")
	err := svc.ensureStorageDir()
	assert.ErrorIs(t, err, ErrSealStorageDirRelative)
}

func TestSealService_Coverage_EnsureStorageDir_Valid(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "ensure-test")
	svc := NewSealService(dir)
	err := svc.ensureStorageDir()
	require.NoError(t, err)

	info, statErr := os.Stat(dir)
	require.NoError(t, statErr)
	assert.True(t, info.IsDir())
}

// ---------------------------------------------------------------------------
// blobPath
// ---------------------------------------------------------------------------

func TestSealService_Coverage_BlobPath(t *testing.T) {
	svc := NewSealService("/tmp/sealed")
	path := svc.blobPath("abc123")
	assert.Equal(t, "/tmp/sealed/abc123.sealed.json", path)
}

// ---------------------------------------------------------------------------
// saveBlob / loadBlob / loadBlobByID
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SaveAndLoadBlob_Direct(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:        "test-blob",
		Label:     "test-label",
		SizeBytes: 42,
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeSoftware,
			Ciphertext: []byte("ciphertext"),
		},
		CreatedAt: time.Now(),
	}

	err := svc.saveBlob(blob)
	require.NoError(t, err)

	loaded, loadErr := svc.loadBlob(svc.blobPath("test-blob"))
	require.NoError(t, loadErr)
	assert.Equal(t, "test-blob", loaded.ID)
	assert.Equal(t, "test-label", loaded.Label)
	assert.Equal(t, 42, loaded.SizeBytes)
}

func TestSealService_Coverage_LoadBlob_NotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.loadBlob("/nonexistent/path.json")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_Coverage_LoadBlob_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	badFile := filepath.Join(dir, "bad.json")
	require.NoError(t, os.WriteFile(badFile, []byte("not json"), 0600))

	_, err := svc.loadBlob(badFile)
	assert.ErrorIs(t, err, ErrSealUnmarshalFailed)
}

func TestSealService_Coverage_LoadBlobByID_NotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	_, err := svc.loadBlobByID("nonexistent-id")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

// ---------------------------------------------------------------------------
// saveBlob / loadBlobByID via backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SaveAndLoadBlob_ViaBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := &sealedBlobStorage{
		ID:        "backend-blob",
		Label:     "backend-label",
		SizeBytes: 100,
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeSoftware,
			Ciphertext: []byte("test"),
		},
		CreatedAt: time.Now(),
	}

	err := svc.saveBlob(blob)
	require.NoError(t, err)

	loaded, loadErr := svc.loadBlobByID("backend-blob")
	require.NoError(t, loadErr)
	assert.Equal(t, "backend-blob", loaded.ID)
	assert.Equal(t, "backend-label", loaded.Label)
}

func TestSealService_Coverage_LoadBlobByID_ViaBackend_NotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	_, err := svc.loadBlobByID("nonexistent")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_Coverage_LoadBlobByID_ViaBackend_InvalidJSON(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Write invalid JSON to the backend.
	require.NoError(t, backend.Put(context.Background(), "sealed/bad-json", []byte("not json")))

	_, err := svc.loadBlobByID("bad-json")
	assert.ErrorIs(t, err, ErrSealUnmarshalFailed)
}

// ---------------------------------------------------------------------------
// ListBlobs via backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_ListBlobs_ViaBackend_Empty(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestSealService_Coverage_ListBlobs_ViaBackend_WithBlobs(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Save two blobs.
	for _, id := range []string{"blob-1", "blob-2"} {
		blob := &sealedBlobStorage{
			ID:        id,
			Label:     "label-" + id,
			SizeBytes: 50,
			SealedData: &types.SealedData{
				Backend: types.BackendTypeSoftware,
			},
			CreatedAt: time.Now(),
		}
		require.NoError(t, svc.saveBlob(blob))
	}

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestSealService_Coverage_ListBlobs_ViaBackend_SkipsInvalidJSON(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Write valid blob.
	validBlob := &sealedBlobStorage{
		ID:         "valid",
		Label:      "valid-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}
	validData, marshalErr := json.Marshal(validBlob)
	require.NoError(t, marshalErr)
	require.NoError(t, backend.Put(context.Background(), "sealed/valid", validData))

	// Write invalid JSON.
	require.NoError(t, backend.Put(context.Background(), "sealed/invalid", []byte("not json")))

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Len(t, entries, 1) // Only valid blob
	assert.Equal(t, "valid", entries[0].ID)
}

// ---------------------------------------------------------------------------
// ListBlobs direct (no backend)
// ---------------------------------------------------------------------------

func TestSealService_Coverage_ListBlobs_Direct_NilContext(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	// ctx is nil

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// DeleteBlob via backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_DeleteBlob_ViaBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Save a blob then delete it.
	blob := &sealedBlobStorage{
		ID:         "delete-me",
		Label:      "to-delete",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}
	require.NoError(t, svc.saveBlob(blob))

	err := svc.DeleteBlob("delete-me")
	require.NoError(t, err)

	// Verify it's gone.
	_, loadErr := svc.loadBlobByID("delete-me")
	assert.ErrorIs(t, loadErr, ErrSealBlobNotFound)
}

func TestSealService_Coverage_DeleteBlob_ViaBackend_NotFound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	err := svc.DeleteBlob("nonexistent")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)
}

func TestSealService_Coverage_DeleteBlob_ViaBackend_WithAudit(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	blob := &sealedBlobStorage{
		ID:         "audit-delete",
		Label:      "audit-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}
	require.NoError(t, svc.saveBlob(blob))

	err := svc.DeleteBlob("audit-delete")
	require.NoError(t, err)
	assert.True(t, len(logger.entries) > 0)
}

func TestSealService_Coverage_DeleteBlob_NilContext(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	// ctx is nil
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// Create blob on disk.
	blob := &sealedBlobStorage{
		ID:         "ctx-nil",
		Label:      "ctx-nil-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}
	svc.mu.Lock()
	require.NoError(t, svc.saveBlob(blob))
	svc.mu.Unlock()

	err := svc.DeleteBlob("ctx-nil")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// MigrateFrom
// ---------------------------------------------------------------------------

func TestSealService_Coverage_MigrateFrom_SkipsNonJSON(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	// Create a non-JSON file in source.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "data.txt"), []byte("text"), 0600))

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_Coverage_MigrateFrom_SkipsSubdirs(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	// Create a subdirectory in source.
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0700))

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated)
}

func TestSealService_Coverage_MigrateFrom_CopiesJSON(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := filepath.Join(t.TempDir(), "dest")
	svc := NewSealService(dstDir)

	// Create JSON files in source.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "blob1.json"), []byte(`{"id":"b1"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "blob2.json"), []byte(`{"id":"b2"}`), 0600))

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 2, migrated)

	// Verify files exist in destination.
	_, err1 := os.Stat(filepath.Join(dstDir, "blob1.json"))
	_, err2 := os.Stat(filepath.Join(dstDir, "blob2.json"))
	assert.NoError(t, err1)
	assert.NoError(t, err2)
}

func TestSealService_Coverage_MigrateFrom_DoesNotOverwrite(t *testing.T) {
	srcDir := t.TempDir()
	dstDir := t.TempDir()
	svc := NewSealService(dstDir)

	// Write a file in both source and destination.
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "exist.json"), []byte(`{"from":"src"}`), 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dstDir, "exist.json"), []byte(`{"from":"dst"}`), 0600))

	migrated, err := svc.MigrateFrom(srcDir)
	require.NoError(t, err)
	assert.Equal(t, 0, migrated) // Should not overwrite

	// Verify destination content unchanged.
	data, readErr := os.ReadFile(filepath.Join(dstDir, "exist.json"))
	require.NoError(t, readErr)
	assert.Contains(t, string(data), "dst")
}

// ---------------------------------------------------------------------------
// SealData with audit logging
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_WithAuditLogger(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	entry, err := svc.SealData(validSealRequest())
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.True(t, len(logger.entries) > 0)
	assert.True(t, logger.entries[len(logger.entries)-1].Success)
}

func TestSealService_Coverage_SealData_AuditOnError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
		sealFn: func(_ context.Context, _ *transport.SealRequest) (*transport.SealResponse, error) {
			return nil, errors.New("seal engine failure")
		},
	}
	svc.SetClientFunc(func() xkms.Client { return mc })
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	_, err := svc.SealData(validSealRequest())
	assert.Error(t, err)
	assert.True(t, len(logger.entries) > 0)
	assert.False(t, logger.entries[len(logger.entries)-1].Success)
}

// ---------------------------------------------------------------------------
// SealData with backend (stores blob through backend)
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_WithBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	entry, err := svc.SealData(validSealRequest())
	require.NoError(t, err)
	require.NotNil(t, entry)

	// Verify blob was stored through the backend.
	keys, listErr := backend.List(context.Background(), "sealed/")
	require.NoError(t, listErr)
	assert.Len(t, keys, 1)
}

// ---------------------------------------------------------------------------
// UnsealData edge cases
// ---------------------------------------------------------------------------

func TestSealService_Coverage_UnsealData_NilContext(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// ctx is nil
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// Create and seal data.
	svc.SetContext(context.Background())
	entry, sealErr := svc.SealData(validSealRequest())
	require.NoError(t, sealErr)

	// Reset context to nil for unseal.
	svc.ctx = nil
	result, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestSealService_Coverage_UnsealData_WithAuditLogger(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	// Seal then unseal.
	entry, sealErr := svc.SealData(validSealRequest())
	require.NoError(t, sealErr)

	result, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)

	// Verify unseal was audited.
	foundUnseal := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpUnsealData {
			foundUnseal = true
			break
		}
	}
	assert.True(t, foundUnseal)
}

func TestSealService_Coverage_UnsealData_BackendIDFallback(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// Create a blob directly with empty BackendID.
	blob := &sealedBlobStorage{
		ID:    "no-backend",
		Label: "test",
		SealedData: &types.SealedData{
			Backend:    types.BackendTypeSoftware,
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	svc.mu.Lock()
	require.NoError(t, svc.saveBlob(blob))
	svc.mu.Unlock()

	result, err := svc.UnsealData("no-backend", "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestSealService_Coverage_UnsealData_FullBackendIDFallback(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// Create a blob with empty BackendID and empty SealedData.Backend.
	blob := &sealedBlobStorage{
		ID:    "empty-backend",
		Label: "test",
		SealedData: &types.SealedData{
			Ciphertext: []byte("data"),
		},
		CreatedAt: time.Now(),
	}
	svc.mu.Lock()
	require.NoError(t, svc.saveBlob(blob))
	svc.mu.Unlock()

	result, err := svc.UnsealData("empty-backend", "")
	require.NoError(t, err)
	assert.NotEmpty(t, result)
}

// ---------------------------------------------------------------------------
// DeleteBlob with audit logging
// ---------------------------------------------------------------------------

func TestSealService_Coverage_DeleteBlob_Direct_WithAudit(t *testing.T) {
	dir := t.TempDir()
	svc := NewSealService(dir)
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	// Create a blob on disk.
	entry, sealErr := svc.SealData(validSealRequest())
	require.NoError(t, sealErr)

	err := svc.DeleteBlob(entry.ID)
	require.NoError(t, err)

	foundDelete := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpSealBlobDeleted && e.Success {
			foundDelete = true
			break
		}
	}
	assert.True(t, foundDelete)
}

func TestSealService_Coverage_DeleteBlob_Direct_NotFound_WithAudit(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	logger := &sealCoverageAuditLogger{}
	svc.SetAuditLogger(logger)

	err := svc.DeleteBlob("ghost-id")
	assert.ErrorIs(t, err, ErrSealBlobNotFound)

	foundFailedDelete := false
	for _, e := range logger.entries {
		if e.Operation == audit.OpSealBlobDeleted && !e.Success {
			foundFailedDelete = true
			break
		}
	}
	assert.True(t, foundFailedDelete)
}

// ---------------------------------------------------------------------------
// SealData with storage type
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_ExplicitStorageType(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	req := validSealRequest()
	req.StorageType = "nvram"

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "nvram", entry.StorageType)
}

func TestSealService_Coverage_SealData_DefaultStorageType(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	entry, err := svc.SealData(validSealRequest())
	require.NoError(t, err)
	assert.Equal(t, string(StorageTypeDisk), entry.StorageType)
}

// ---------------------------------------------------------------------------
// SealData system category
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_SystemCategory(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	req := &SealRequest{
		Label: "password_master_key",
		Data:  base64.StdEncoding.EncodeToString([]byte("master-key-data")),
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "system", entry.Category)
}

func TestSealService_Coverage_SealData_UserCategory(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	entry, err := svc.SealData(validSealRequest())
	require.NoError(t, err)
	assert.Equal(t, "user", entry.Category)
}

// ---------------------------------------------------------------------------
// SealData with explicit backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_ExplicitBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	req := validSealRequest()
	req.Backend = string(types.BackendTypeSoftware)

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, string(types.BackendTypeSoftware), entry.BackendID)
}

// ---------------------------------------------------------------------------
// Seal error sentinel uniqueness
// ---------------------------------------------------------------------------

func TestSealService_Coverage_ErrorSentinels(t *testing.T) {
	sentinels := []error{
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

	seen := make(map[string]bool, len(sentinels))
	for _, s := range sentinels {
		msg := s.Error()
		assert.False(t, seen[msg], "duplicate seal error: %s", msg)
		seen[msg] = true
	}
}

// ---------------------------------------------------------------------------
// SealedBlobEntry / SealRequest types
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealedBlobEntry_JSON(t *testing.T) {
	entry := SealedBlobEntry{
		ID:          "test-id",
		Label:       "test-label",
		SizeBytes:   256,
		PCRBound:    true,
		PolicyType:  "password",
		CreatedAt:   "2025-01-01T00:00:00Z",
		Category:    "user",
		BackendID:   "tpm2",
		StorageType: "disk",
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	var decoded SealedBlobEntry
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, entry, decoded)
}

func TestSealService_Coverage_SealRequest_JSON(t *testing.T) {
	req := SealRequest{
		Label:       "my-label",
		Data:        "base64data",
		PCRs:        []int{0, 7},
		PCRBank:     "sha256",
		PolicyType:  "custom_pcr",
		Password:    "secret",
		Backend:     "tpm2",
		StorageType: "disk",
	}

	data, err := json.Marshal(req)
	require.NoError(t, err)

	var decoded SealRequest
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, req, decoded)
}

// ---------------------------------------------------------------------------
// StorageType constants
// ---------------------------------------------------------------------------

func TestSealService_Coverage_StorageTypeConstants(t *testing.T) {
	assert.Equal(t, StorageType("disk"), StorageTypeDisk)
	assert.Equal(t, StorageType("nvram"), StorageTypeNVRAM)
}

// ---------------------------------------------------------------------------
// AvailableSealers ordering
// ---------------------------------------------------------------------------

func TestSealService_Coverage_AvailableSealers_SortedByLabel(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	sealers := svc.AvailableSealers()
	require.True(t, len(sealers) >= 2)

	// Verify sorted alphabetically by label.
	for i := 1; i < len(sealers); i++ {
		assert.True(t, sealers[i-1].Label <= sealers[i].Label,
			"sealers should be sorted alphabetically by label")
	}
}

func TestSealService_Coverage_AvailableSealers_MarksDefault(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	svc.SetDefaultBackend(string(types.BackendTypeSoftware))
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, backend string) (*transport.CanSealResponse, error) {
			return &transport.CanSealResponse{CanSeal: true, Backend: backend}, nil
		},
	}
	svc.SetLocalClient(mc)

	sealers := svc.AvailableSealers()
	foundDefault := false
	for _, s := range sealers {
		if s.ID == string(types.BackendTypeSoftware) {
			assert.True(t, s.IsDefault)
			foundDefault = true
		}
	}
	assert.True(t, foundDefault)
}

func TestSealService_Coverage_AvailableSealers_CanSealError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return nil, errors.New("connection error")
		},
	}
	svc.SetLocalClient(mc)

	sealers := svc.AvailableSealers()
	assert.Empty(t, sealers) // Errors cause backends to be skipped
}

func TestSealService_Coverage_AvailableSealers_NilResponse(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := &sealMockClient{
		canSealFn: func(_ context.Context, _ string) (*transport.CanSealResponse, error) {
			return nil, nil // nil response
		},
	}
	svc.SetLocalClient(mc)

	sealers := svc.AvailableSealers()
	assert.Empty(t, sealers)
}

// ---------------------------------------------------------------------------
// pcrBankAlgMap
// ---------------------------------------------------------------------------

func TestSealService_Coverage_PcrBankAlgMap(t *testing.T) {
	assert.Equal(t, tpm2.TPMAlgSHA1, pcrBankAlgMap["sha1"])
	assert.Equal(t, tpm2.TPMAlgSHA256, pcrBankAlgMap["sha256"])
	assert.Equal(t, tpm2.TPMAlgSHA384, pcrBankAlgMap["sha384"])
	assert.Equal(t, tpm2.TPMAlgSHA512, pcrBankAlgMap["sha512"])

	_, exists := pcrBankAlgMap["md5"]
	assert.False(t, exists)
}

// ---------------------------------------------------------------------------
// knownSealerMeta
// ---------------------------------------------------------------------------

func TestSealService_Coverage_KnownSealerMeta(t *testing.T) {
	tpmMeta, ok := knownSealerMeta[string(types.BackendTypeTPM2)]
	assert.True(t, ok)
	assert.True(t, tpmMeta.HardwareBacked)
	assert.Equal(t, types.SecurityLevelVeryHigh, tpmMeta.SecurityLevel)

	swMeta, ok := knownSealerMeta[string(types.BackendTypeSoftware)]
	assert.True(t, ok)
	assert.False(t, swMeta.HardwareBacked)
	assert.Equal(t, types.SecurityLevelLow, swMeta.SecurityLevel)

	// Only TPM2 and Software are sealers; PKCS11/cloud KMS are not.
	_, hasPKCS11 := knownSealerMeta[string(types.BackendTypePKCS11)]
	assert.False(t, hasPKCS11, "pkcs11 should not be a sealer backend")
}

// ---------------------------------------------------------------------------
// SealerInfo fields
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealerInfo_JSON(t *testing.T) {
	info := SealerInfo{
		ID:             "tpm2",
		Available:      true,
		HardwareBacked: true,
		SecurityLevel:  3,
		Label:          "TPM 2.0",
		Description:    "Hardware-bound sealing",
		IsDefault:      true,
		Details:        map[string]string{"srk_handle": "0x81000002"},
	}

	data, err := json.Marshal(info)
	require.NoError(t, err)

	var decoded SealerInfo
	require.NoError(t, json.Unmarshal(data, &decoded))
	assert.Equal(t, info, decoded)
}

// ---------------------------------------------------------------------------
// SealData with password policy and backend storage
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_PasswordPolicy_ViaBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	req := &SealRequest{
		Label:      "pw-protected",
		Data:       base64.StdEncoding.EncodeToString([]byte("secret data")),
		PolicyType: "password",
		Password:   "my-password",
	}

	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.Equal(t, "password", entry.PolicyType)
}

// ---------------------------------------------------------------------------
// UnsealData via backend
// ---------------------------------------------------------------------------

func TestSealService_Coverage_UnsealData_ViaBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	// Seal.
	entry, sealErr := svc.SealData(validSealRequest())
	require.NoError(t, sealErr)

	// Unseal.
	result, err := svc.UnsealData(entry.ID, "")
	require.NoError(t, err)

	decoded, decodeErr := base64.StdEncoding.DecodeString(result)
	require.NoError(t, decodeErr)
	assert.Equal(t, "hello world", string(decoded))
}

// ---------------------------------------------------------------------------
// saveBlob with backend that returns error
// ---------------------------------------------------------------------------

// errorBackend is a storage.Backend that returns errors for all operations.
type errorBackend struct{}

func (e *errorBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("get error")
}
func (e *errorBackend) Put(_ context.Context, _ string, _ []byte) error {
	return errors.New("put error")
}
func (e *errorBackend) Delete(_ context.Context, _ string) error {
	return errors.New("delete error")
}
func (e *errorBackend) List(_ context.Context, _ string) ([]string, error) {
	return nil, errors.New("list error")
}
func (e *errorBackend) Scan(_ context.Context, _ string, _ func(key string, value []byte) error) error {
	return errors.New("scan error")
}
func (e *errorBackend) Exists(_ context.Context, _ string) (bool, error) {
	return false, errors.New("exists error")
}
func (e *errorBackend) Close() error { return nil }

func TestSealService_Coverage_SaveBlob_BackendPutError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	svc.SetBackend(&errorBackend{}, "sealed/")

	blob := &sealedBlobStorage{
		ID:         "err-blob",
		Label:      "err-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}

	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

// ---------------------------------------------------------------------------
// ListBlobs via backend with list error
// ---------------------------------------------------------------------------

func TestSealService_Coverage_ListBlobs_ViaBackend_ListError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	svc.SetBackend(&errorBackend{}, "sealed/")

	entries, err := svc.ListBlobs()
	require.NoError(t, err) // ListBlobs swallows backend errors
	assert.Empty(t, entries)
}

// ---------------------------------------------------------------------------
// ListBlobs via backend with Get error (skips entry)
// ---------------------------------------------------------------------------

// getErrorBackend returns an error for Get but works for List.
type getErrorBackend struct {
	storage.Backend
}

func (b *getErrorBackend) List(_ context.Context, _ string) ([]string, error) {
	return []string{"sealed/entry1"}, nil
}
func (b *getErrorBackend) Get(_ context.Context, _ string) ([]byte, error) {
	return nil, errors.New("get error")
}
func (b *getErrorBackend) Close() error { return nil }

func TestSealService_Coverage_ListBlobs_ViaBackend_GetError(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	svc.SetBackend(&getErrorBackend{}, "sealed/")

	entries, err := svc.ListBlobs()
	require.NoError(t, err)
	assert.Empty(t, entries) // Entry with get error is skipped
}

// ---------------------------------------------------------------------------
// saveBlob with empty storageDir (direct mode)
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SaveBlob_EmptyStorageDir(t *testing.T) {
	svc := NewSealService("")
	svc.SetContext(context.Background())

	blob := &sealedBlobStorage{
		ID:         "no-dir",
		Label:      "no-dir-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}

	err := svc.saveBlob(blob)
	assert.ErrorIs(t, err, ErrSealStorageFailed)
}

// ---------------------------------------------------------------------------
// saveBlob with NilContext (direct mode)
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SaveBlob_NilContext_ViaBackend(t *testing.T) {
	svc := NewSealService(t.TempDir())
	// ctx is nil
	backend := storage.NewMemory()
	svc.SetBackend(backend, "sealed/")

	blob := &sealedBlobStorage{
		ID:         "nil-ctx",
		Label:      "nil-ctx-label",
		SealedData: &types.SealedData{Backend: types.BackendTypeSoftware},
		CreatedAt:  time.Now(),
	}

	err := svc.saveBlob(blob)
	require.NoError(t, err)

	// Verify saved.
	_, getErr := backend.Get(context.Background(), "sealed/nil-ctx")
	assert.NoError(t, getErr)
}

// ---------------------------------------------------------------------------
// SealData PCR bound flag
// ---------------------------------------------------------------------------

func TestSealService_Coverage_SealData_PCRBoundFlag(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// With PCRs -> PCRBound = true
	req := &SealRequest{
		Label:      "pcr-bound",
		Data:       base64.StdEncoding.EncodeToString([]byte("data")),
		PCRs:       []int{0, 7},
		PolicyType: "custom_pcr",
	}
	entry, err := svc.SealData(req)
	require.NoError(t, err)
	assert.True(t, entry.PCRBound)
}

func TestSealService_Coverage_SealData_NotPCRBound(t *testing.T) {
	svc := NewSealService(t.TempDir())
	svc.SetContext(context.Background())
	mc := defaultSealMockClient()
	svc.SetClientFunc(func() xkms.Client { return mc })

	// No PCRs, no platform policy -> not PCR bound
	entry, err := svc.SealData(validSealRequest())
	require.NoError(t, err)
	assert.False(t, entry.PCRBound)
}
