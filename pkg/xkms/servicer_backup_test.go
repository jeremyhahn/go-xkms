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

package xkms

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeBackupEntry holds one in-memory backup record for fakeBackupClient,
// including the "shard payload" used to compute and later re-verify the
// checksum, so a test can tamper the stored bytes and observe a genuine
// checksum mismatch -- the same failure path RestoreBackup/VerifyBackup
// report on the real go-qrdb node.
type fakeBackupEntry struct {
	info    qrdbtransport.BackupInfo
	payload []byte
}

// fakeBackupClient is an in-memory implementation of
// qrdbtransport.BackupClient used to exercise the XKMSService pass-through
// servicer in isolation from the embedded go-qrdb node. It mirrors just
// enough of the real BackupService's semantics (empty-field refusal, not-
// found, checksum verification) to prove the servicer forwards requests,
// responses and typed errors faithfully.
type fakeBackupClient struct {
	backups map[string]*fakeBackupEntry
	nextID  int
}

func newFakeBackupClient() *fakeBackupClient {
	return &fakeBackupClient{backups: make(map[string]*fakeBackupEntry)}
}

func checksumOf(payload []byte) string {
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func (f *fakeBackupClient) CreateBackup(_ context.Context, req *qrdbtransport.BackupRequest) (*qrdbtransport.BackupInfo, error) {
	if req.Destination == "" {
		return nil, &qrdbtransport.BackupEmptyDestinationError{}
	}
	if req.Encryption != "" && req.Encryption != qrdbtransport.EncryptionNone && len(req.EncryptionKey) == 0 {
		return nil, &qrdbtransport.BackupCreateError{Err: errors.New("encryption key required")}
	}

	// The payload is simulated shard data: the destination bytes, so each
	// distinct destination produces a distinct, reproducible checksum.
	payload := []byte(req.Destination)

	f.nextID++
	id := "bkp-" + hex.EncodeToString([]byte{byte(f.nextID)})
	info := qrdbtransport.BackupInfo{
		ID:          id,
		Timestamp:   time.Now().UTC(),
		Size:        int64(len(payload)),
		ShardCount:  1,
		Status:      qrdbtransport.BackupStatusComplete,
		Checksum:    checksumOf(payload),
		Destination: req.Destination,
		Compression: req.Compression,
		Encryption:  req.Encryption,
		Metadata:    req.Metadata,
	}
	f.backups[id] = &fakeBackupEntry{info: info, payload: payload}
	return &info, nil
}

func (f *fakeBackupClient) ListBackups(_ context.Context) ([]qrdbtransport.BackupInfo, error) {
	out := make([]qrdbtransport.BackupInfo, 0, len(f.backups))
	for _, e := range f.backups {
		out = append(out, e.info)
	}
	return out, nil
}

func (f *fakeBackupClient) GetBackup(_ context.Context, id string) (*qrdbtransport.BackupInfo, error) {
	if id == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	e, ok := f.backups[id]
	if !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: id}
	}
	info := e.info
	return &info, nil
}

func (f *fakeBackupClient) DeleteBackup(_ context.Context, id string) error {
	if id == "" {
		return &qrdbtransport.BackupEmptyIDError{}
	}
	if _, ok := f.backups[id]; !ok {
		return &qrdbtransport.BackupNotFoundError{ID: id}
	}
	delete(f.backups, id)
	return nil
}

func (f *fakeBackupClient) RestoreBackup(_ context.Context, req *qrdbtransport.RestoreRequest) (*qrdbtransport.RestoreResult, error) {
	if req.BackupID == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	e, ok := f.backups[req.BackupID]
	if !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: req.BackupID}
	}
	if req.ValidateFirst {
		actual := checksumOf(e.payload)
		if actual != e.info.Checksum {
			return nil, &qrdbtransport.BackupChecksumMismatchError{Expected: e.info.Checksum, Actual: actual}
		}
	}
	return &qrdbtransport.RestoreResult{
		BackupID:       req.BackupID,
		ShardsRestored: e.info.ShardCount,
		Duration:       time.Millisecond,
	}, nil
}

func (f *fakeBackupClient) VerifyBackup(_ context.Context, id string) (*qrdbtransport.VerifyResult, error) {
	if id == "" {
		return nil, &qrdbtransport.BackupEmptyIDError{}
	}
	e, ok := f.backups[id]
	if !ok {
		return nil, &qrdbtransport.BackupNotFoundError{ID: id}
	}
	actual := checksumOf(e.payload)
	match := actual == e.info.Checksum
	result := &qrdbtransport.VerifyResult{
		Valid:            match,
		ChecksumMatch:    match,
		ExpectedChecksum: e.info.Checksum,
		ActualChecksum:   actual,
	}
	if !match {
		result.Errors = []string{"checksum mismatch"}
	}
	return result, nil
}

// --- ErrNotConfigured guards ---

func TestCreateBackup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.CreateBackup(context.Background(), &transport.BackupRequest{Destination: "/tmp/x"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestListBackups_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.ListBackups(context.Background())
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestGetBackup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.GetBackup(context.Background(), "bkp-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestDeleteBackup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	err = svc.DeleteBackup(context.Background(), "bkp-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestRestoreBackup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.RestoreBackup(context.Background(), &transport.RestoreRequest{BackupID: "bkp-1"})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

func TestVerifyBackup_NotConfigured(t *testing.T) {
	setupService(t)
	svc, err := Get()
	require.NoError(t, err)

	_, err = svc.VerifyBackup(context.Background(), "bkp-1")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNotConfigured))
}

// --- Nil request guards ---

func setupServiceWithBackup(t *testing.T) (*XKMSService, *fakeBackupClient) {
	t.Helper()
	svc, _, _ := setupServiceWithProviders(t)
	fake := newFakeBackupClient()
	svc.SetBackupClient(fake)
	return svc, fake
}

func TestCreateBackup_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	_, err := svc.CreateBackup(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestRestoreBackup_NilRequest(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	_, err := svc.RestoreBackup(context.Background(), nil)
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

// --- Delegation / success tests ---

func TestCreateBackup_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	resp, err := svc.CreateBackup(context.Background(), &transport.BackupRequest{
		Destination: "/backups/daily",
		Compression: transport.CompressionZstd,
	})
	require.NoError(t, err)
	assert.Equal(t, "/backups/daily", resp.Destination)
	assert.Equal(t, transport.BackupStatusComplete, resp.Status)
	assert.NotEmpty(t, resp.Checksum)
}

func TestCreateBackup_EmptyDestination(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	_, err := svc.CreateBackup(context.Background(), &transport.BackupRequest{})
	require.Error(t, err)
	var emptyDest *qrdbtransport.BackupEmptyDestinationError
	assert.True(t, errors.As(err, &emptyDest))
}

func TestListBackups_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)
	ctx := context.Background()

	_, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/a"})
	require.NoError(t, err)
	_, err = svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/b"})
	require.NoError(t, err)

	backups, err := svc.ListBackups(ctx)
	require.NoError(t, err)
	assert.Len(t, backups, 2)
}

func TestGetBackup_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/get-me"})
	require.NoError(t, err)

	resp, err := svc.GetBackup(ctx, created.ID)
	require.NoError(t, err)
	assert.Equal(t, created.ID, resp.ID)
}

func TestGetBackup_NotFound(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	_, err := svc.GetBackup(context.Background(), "nonexistent")
	require.Error(t, err)
	var notFound *qrdbtransport.BackupNotFoundError
	assert.True(t, errors.As(err, &notFound))
}

func TestDeleteBackup_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/delete-me"})
	require.NoError(t, err)

	err = svc.DeleteBackup(ctx, created.ID)
	require.NoError(t, err)

	_, err = svc.GetBackup(ctx, created.ID)
	require.Error(t, err)
}

func TestDeleteBackup_NotFound(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	err := svc.DeleteBackup(context.Background(), "ghost")
	require.Error(t, err)
	var notFound *qrdbtransport.BackupNotFoundError
	assert.True(t, errors.As(err, &notFound))
}

func TestVerifyBackup_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/verify-me"})
	require.NoError(t, err)

	resp, err := svc.VerifyBackup(ctx, created.ID)
	require.NoError(t, err)
	assert.True(t, resp.Valid)
	assert.True(t, resp.ChecksumMatch)
	assert.Equal(t, created.Checksum, resp.ExpectedChecksum)
}

// TestVerifyBackup_TamperedChecksumFails proves a tampered backup is refused
// rather than silently accepted: the stored checksum no longer matches the
// recomputed one once the underlying payload is corrupted after capture.
func TestVerifyBackup_TamperedChecksumFails(t *testing.T) {
	svc, fake := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/tamper-me"})
	require.NoError(t, err)

	// Corrupt the stored payload in place, simulating bit rot or tampering
	// between creation and verification.
	fake.backups[created.ID].payload = []byte("corrupted")

	resp, err := svc.VerifyBackup(ctx, created.ID)
	require.NoError(t, err)
	assert.False(t, resp.Valid)
	assert.False(t, resp.ChecksumMatch)
	assert.NotEqual(t, resp.ExpectedChecksum, resp.ActualChecksum)
}

// TestRestoreBackup_RefusesTamperedSnapshotWhenValidated proves restore
// aborts before touching state when asked to validate first and the backup
// fails integrity verification.
func TestRestoreBackup_RefusesTamperedSnapshotWhenValidated(t *testing.T) {
	svc, fake := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/tamper-restore"})
	require.NoError(t, err)

	fake.backups[created.ID].payload = []byte("corrupted")

	_, err = svc.RestoreBackup(ctx, &transport.RestoreRequest{
		BackupID:      created.ID,
		ValidateFirst: true,
	})
	require.Error(t, err)
	var mismatch *qrdbtransport.BackupChecksumMismatchError
	assert.True(t, errors.As(err, &mismatch))
}

func TestRestoreBackup_Success(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)
	ctx := context.Background()

	created, err := svc.CreateBackup(ctx, &transport.BackupRequest{Destination: "/backups/restore-me"})
	require.NoError(t, err)

	resp, err := svc.RestoreBackup(ctx, &transport.RestoreRequest{
		BackupID:      created.ID,
		ValidateFirst: true,
	})
	require.NoError(t, err)
	assert.Equal(t, created.ID, resp.BackupID)
	assert.Equal(t, 1, resp.ShardsRestored)
}

func TestRestoreBackup_NotFound(t *testing.T) {
	svc, _ := setupServiceWithBackup(t)

	_, err := svc.RestoreBackup(context.Background(), &transport.RestoreRequest{BackupID: "ghost"})
	require.Error(t, err)
	var notFound *qrdbtransport.BackupNotFoundError
	assert.True(t, errors.As(err, &notFound))
}
