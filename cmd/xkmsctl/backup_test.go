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

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// mockBackupClient is a mock client for testing backup operations.
type mockBackupClient struct {
	mockBackendsClient

	connectErr  error
	closeErr    error
	closeCalled bool

	createResp *transport.BackupInfo
	createErr  error

	listResp []transport.BackupInfo
	listErr  error

	getResp *transport.BackupInfo
	getErr  error

	deleteErr error

	restoreResp *transport.RestoreResult
	restoreErr  error

	verifyResp *transport.VerifyResult
	verifyErr  error
}

func (m *mockBackupClient) Connect(ctx context.Context) error { return m.connectErr }

func (m *mockBackupClient) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockBackupClient) CreateBackup(ctx context.Context, req *transport.BackupRequest) (*transport.BackupInfo, error) {
	return m.createResp, m.createErr
}

func (m *mockBackupClient) ListBackups(ctx context.Context) ([]transport.BackupInfo, error) {
	return m.listResp, m.listErr
}

func (m *mockBackupClient) GetBackup(ctx context.Context, id string) (*transport.BackupInfo, error) {
	return m.getResp, m.getErr
}

func (m *mockBackupClient) DeleteBackup(ctx context.Context, id string) error {
	return m.deleteErr
}

func (m *mockBackupClient) RestoreBackup(ctx context.Context, req *transport.RestoreRequest) (*transport.RestoreResult, error) {
	return m.restoreResp, m.restoreErr
}

func (m *mockBackupClient) VerifyBackup(ctx context.Context, id string) (*transport.VerifyResult, error) {
	return m.verifyResp, m.verifyErr
}

// newTestBackupConfig creates a Config wired to the given mock client.
func newTestBackupConfig(mock *mockBackupClient) *Config {
	return &Config{
		OutputFormat: "text",
		ClientFactory: func(cfg *Config) (client.Client, error) {
			return mock, nil
		},
	}
}

func testFixtureBackup() *transport.BackupInfo {
	return &transport.BackupInfo{
		ID:          "bkp-001",
		Timestamp:   time.Date(2026, 9, 30, 3, 0, 0, 0, time.UTC),
		Size:        1024,
		ShardCount:  2,
		Status:      transport.BackupStatusComplete,
		Checksum:    "deadbeef",
		Destination: "/backups/daily",
		Compression: transport.CompressionZstd,
		Encryption:  transport.EncryptionNone,
	}
}

// --- Command existence ---

func TestBackupCmd_Exists(t *testing.T) {
	if backupCmd == nil {
		t.Fatal("backupCmd should not be nil")
	}
}

func TestBackupCmd_Subcommands(t *testing.T) {
	want := map[string]bool{
		"create": false, "list": false, "show": false,
		"delete": false, "restore": false, "verify": false,
	}
	for _, c := range backupCmd.Commands() {
		if _, ok := want[c.Name()]; ok {
			want[c.Name()] = true
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("backupCmd should have subcommand %q", name)
		}
	}
}

// --- createBackupClient ---

func TestCreateBackupClient_Success(t *testing.T) {
	mock := &mockBackupClient{}
	cfg := newTestBackupConfig(mock)

	cl, cleanup, err := createBackupClient(cfg)
	if err != nil {
		t.Fatalf("createBackupClient returned unexpected error: %v", err)
	}
	if cl == nil {
		t.Fatal("createBackupClient returned nil client")
	}
	cleanup()
	if !mock.closeCalled {
		t.Error("cleanup should call client.Close()")
	}
}

func TestCreateBackupClient_ConnectError(t *testing.T) {
	mock := &mockBackupClient{connectErr: errors.New("connect refused")}
	cfg := newTestBackupConfig(mock)

	cl, cleanup, err := createBackupClient(cfg)
	if err == nil {
		t.Fatal("createBackupClient should return error on connect failure")
	}
	if cl != nil || cleanup != nil {
		t.Error("client and cleanup should be nil on error")
	}
	if !strings.Contains(err.Error(), "failed to connect") {
		t.Errorf("error should wrap 'failed to connect', got: %v", err)
	}
}

// --- backupCreate ---

func TestBackupCreate_Success(t *testing.T) {
	mock := &mockBackupClient{createResp: testFixtureBackup()}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupCreate(newTestBackupConfig(mock), printer, "/backups/daily", "zstd", "", "")

	output := buf.String()
	if !strings.Contains(output, "bkp-001") {
		t.Error("output should contain backup ID")
	}
	if !strings.Contains(output, "/backups/daily") {
		t.Error("output should contain destination")
	}
}

func TestBackupCreate_APIError(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{createErr: errors.New("server error")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupCreate(newTestBackupConfig(mock), printer, "/backups/daily", "", "", "")
	// Should not panic; handleError is called.
}

// --- backupList ---

func TestBackupList_Success(t *testing.T) {
	mock := &mockBackupClient{listResp: []transport.BackupInfo{*testFixtureBackup()}}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupList(newTestBackupConfig(mock), printer)

	if !strings.Contains(buf.String(), "bkp-001") {
		t.Error("output should contain backup ID")
	}
}

func TestBackupList_Empty(t *testing.T) {
	mock := &mockBackupClient{}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupList(newTestBackupConfig(mock), printer)

	if !strings.Contains(buf.String(), "No backups found") {
		t.Errorf("expected no-backups message, got: %q", buf.String())
	}
}

func TestBackupList_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{listErr: errors.New("boom")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupList(newTestBackupConfig(mock), printer)
}

// --- backupShow ---

func TestBackupShow_Success(t *testing.T) {
	mock := &mockBackupClient{getResp: testFixtureBackup()}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupShow(newTestBackupConfig(mock), printer, "bkp-001")

	if !strings.Contains(buf.String(), "bkp-001") {
		t.Error("output should contain backup ID")
	}
}

func TestBackupShow_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{getErr: errors.New("not found")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupShow(newTestBackupConfig(mock), printer, "ghost")
}

// --- backupDelete ---

func TestBackupDelete_Success(t *testing.T) {
	mock := &mockBackupClient{}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupDelete(newTestBackupConfig(mock), printer, "bkp-001")

	if !strings.Contains(buf.String(), "deleted") {
		t.Errorf("expected deletion success message, got: %q", buf.String())
	}
}

func TestBackupDelete_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{deleteErr: errors.New("not found")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupDelete(newTestBackupConfig(mock), printer, "ghost")
}

// --- backupRestore ---

func TestBackupRestore_Success(t *testing.T) {
	mock := &mockBackupClient{restoreResp: &transport.RestoreResult{
		BackupID: "bkp-001", ShardsRestored: 2, Duration: time.Second,
	}}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupRestore(newTestBackupConfig(mock), printer, "bkp-001", "", true)

	output := buf.String()
	if !strings.Contains(output, "bkp-001") {
		t.Error("output should contain backup ID")
	}
	if !strings.Contains(output, "2") {
		t.Error("output should contain the shard-restored count")
	}
}

func TestBackupRestore_ChecksumMismatch(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{restoreErr: errors.New("backup checksum mismatch: expected a, got b")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupRestore(newTestBackupConfig(mock), printer, "bkp-001", "", true)
	// Should not panic; handleError is called and no restore result is printed.
	if strings.Contains(buf.String(), "Restore complete") {
		t.Error("a failed restore must not report success")
	}
}

// --- backupVerify ---

func TestBackupVerify_Success(t *testing.T) {
	mock := &mockBackupClient{verifyResp: &transport.VerifyResult{
		Valid: true, ChecksumMatch: true,
		ExpectedChecksum: "deadbeef", ActualChecksum: "deadbeef",
	}}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupVerify(newTestBackupConfig(mock), printer, "bkp-001")

	output := buf.String()
	if !strings.Contains(output, "true") {
		t.Error("output should report the backup as valid")
	}
}

func TestBackupVerify_Invalid(t *testing.T) {
	mock := &mockBackupClient{verifyResp: &transport.VerifyResult{
		Valid: false, ChecksumMatch: false,
		ExpectedChecksum: "deadbeef", ActualChecksum: "corrupted",
		Errors: []string{"checksum mismatch"},
	}}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupVerify(newTestBackupConfig(mock), printer, "bkp-001")

	output := buf.String()
	if !strings.Contains(output, "false") {
		t.Error("output should report the backup as invalid")
	}
	if !strings.Contains(output, "checksum mismatch") {
		t.Error("output should contain the verification error")
	}
}

func TestBackupVerify_Error(t *testing.T) {
	originalExitFunc := exitFunc
	exitFunc = func(code int) {}
	defer func() { exitFunc = originalExitFunc }()

	mock := &mockBackupClient{verifyErr: errors.New("not found")}
	buf := new(bytes.Buffer)
	printer := NewPrinter("text", buf)

	backupVerify(newTestBackupConfig(mock), printer, "ghost")
}
