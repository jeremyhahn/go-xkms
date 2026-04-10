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

package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/sharestore"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// --- Mock ShareService ---

type mockShareService struct {
	connectErr        error
	closeErr          error
	closeCalled       bool
	listSharesResp    *transport.ListSharesResponse
	listSharesErr     error
	submitShareResp   *transport.SubmitShareResponse
	submitShareErr    error
	barrierUnsealResp *transport.BarrierUnsealShareResponse
	barrierUnsealErr  error
}

func (m *mockShareService) Connect(_ context.Context) error {
	return m.connectErr
}

func (m *mockShareService) Close() error {
	m.closeCalled = true
	return m.closeErr
}

func (m *mockShareService) ListShares(_ context.Context) (*transport.ListSharesResponse, error) {
	return m.listSharesResp, m.listSharesErr
}

func (m *mockShareService) SubmitShare(_ context.Context, _ *transport.SubmitShareRequest) (*transport.SubmitShareResponse, error) {
	return m.submitShareResp, m.submitShareErr
}

func (m *mockShareService) BarrierUnsealWithShare(_ context.Context, _ *transport.BarrierUnsealShareRequest) (*transport.BarrierUnsealShareResponse, error) {
	return m.barrierUnsealResp, m.barrierUnsealErr
}

// --- Helper: create a local share store from a temp HOME ---

func createTestShareStore(t *testing.T) sharestore.ShareStore {
	t.Helper()
	store, err := openLocalShareStore()
	require.NoError(t, err)
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func newShareEntry(serverURL, groupID string) *sharestore.ShareEntry {
	return &sharestore.ShareEntry{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  "test-group",
		ShareIndex: 1,
		ShareData:  []byte("secret-share-data-bytes"),
		Purpose:    "barrier",
		ReceivedAt: time.Date(2025, 6, 15, 12, 0, 0, 0, time.UTC),
		TenantID:   "",
	}
}

// --- Command structure tests ---

func TestShareCmd_Exists(t *testing.T) {
	assert.NotNil(t, shareCmd)
}

func TestShareCmd_Properties(t *testing.T) {
	assert.Equal(t, "share", shareCmd.Use)
	assert.NotEmpty(t, shareCmd.Short)
	assert.Contains(t, shareCmd.Short, "Shamir")

	subcommands := shareCmd.Commands()
	names := make(map[string]bool)
	for _, cmd := range subcommands {
		names[cmd.Name()] = true
	}
	assert.True(t, names["list"], "share should have list subcommand")
	assert.True(t, names["receive"], "share should have receive subcommand")
	assert.True(t, names["import"], "share should have import subcommand")
	assert.True(t, names["export"], "share should have export subcommand")
	assert.True(t, names["unseal"], "share should have unseal subcommand")
	assert.True(t, names["delete"], "share should have delete subcommand")
	assert.Equal(t, 6, len(names))
}

func TestShareCmd_RegisteredOnRoot(t *testing.T) {
	found := false
	for _, cmd := range RootCmd.Commands() {
		if cmd.Name() == "share" {
			found = true
			break
		}
	}
	assert.True(t, found, "share command should be registered on root")
}

func TestShareListCmd_Properties(t *testing.T) {
	assert.Equal(t, "list", shareListCmd.Use)
	assert.NotEmpty(t, shareListCmd.Short)
	assert.NotNil(t, shareListCmd.RunE)
	assert.Contains(t, shareListCmd.Aliases, "ls")
}

func TestShareReceiveCmd_Properties(t *testing.T) {
	assert.Equal(t, "receive", shareReceiveCmd.Use)
	assert.NotEmpty(t, shareReceiveCmd.Short)
	assert.NotNil(t, shareReceiveCmd.RunE)

	flag := shareReceiveCmd.Flags().Lookup("server")
	assert.NotNil(t, flag, "receive should have --server flag")
}

func TestShareImportCmd_Properties(t *testing.T) {
	assert.Equal(t, "import", shareImportCmd.Use)
	assert.NotEmpty(t, shareImportCmd.Short)
	assert.NotNil(t, shareImportCmd.RunE)

	flag := shareImportCmd.Flags().Lookup("file")
	assert.NotNil(t, flag, "import should have --file flag")
}

func TestShareExportCmd_Properties(t *testing.T) {
	assert.Equal(t, "export", shareExportCmd.Use)
	assert.NotEmpty(t, shareExportCmd.Short)
	assert.NotNil(t, shareExportCmd.RunE)

	for _, name := range []string{"server", "group-id", "share-index", "file"} {
		flag := shareExportCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "export should have --%s flag", name)
	}
}

func TestShareUnsealCmd_Properties(t *testing.T) {
	assert.Equal(t, "unseal", shareUnsealCmd.Use)
	assert.NotEmpty(t, shareUnsealCmd.Short)
	assert.NotNil(t, shareUnsealCmd.RunE)

	for _, name := range []string{"server", "group-id", "share-index"} {
		flag := shareUnsealCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "unseal should have --%s flag", name)
	}
}

func TestShareDeleteCmd_Properties(t *testing.T) {
	assert.Equal(t, "delete", shareDeleteCmd.Use)
	assert.NotEmpty(t, shareDeleteCmd.Short)
	assert.NotNil(t, shareDeleteCmd.RunE)
	assert.Contains(t, shareDeleteCmd.Aliases, "rm")

	for _, name := range []string{"server", "group-id", "share-index"} {
		flag := shareDeleteCmd.Flags().Lookup(name)
		assert.NotNil(t, flag, "delete should have --%s flag", name)
	}
}

// --- ShareError type tests ---

func TestShareError_Error_Full(t *testing.T) {
	inner := errors.New("connection refused")
	se := &ShareError{
		Operation: "connect",
		Message:   "server unreachable",
		Err:       inner,
	}
	result := se.Error()
	assert.Contains(t, result, "share:")
	assert.Contains(t, result, "connect")
	assert.Contains(t, result, "server unreachable")
	assert.Contains(t, result, "connection refused")
}

func TestShareError_Error_NoMessage(t *testing.T) {
	inner := errors.New("timeout")
	se := &ShareError{
		Operation: "list",
		Err:       inner,
	}
	result := se.Error()
	assert.Contains(t, result, "share: list: timeout")
	assert.NotContains(t, result, "share: list: : timeout")
}

func TestShareError_Error_NoErr(t *testing.T) {
	se := &ShareError{
		Operation: "import",
		Message:   "file not found",
	}
	result := se.Error()
	assert.Contains(t, result, "share: import: file not found")
}

func TestShareError_Error_OperationOnly(t *testing.T) {
	se := &ShareError{
		Operation: "delete",
	}
	result := se.Error()
	assert.Equal(t, "share: delete", result)
}

func TestShareError_Unwrap(t *testing.T) {
	inner := errors.New("underlying error")
	se := &ShareError{
		Operation: "unseal",
		Message:   "failed",
		Err:       inner,
	}
	assert.Equal(t, inner, se.Unwrap())
}

func TestShareError_Unwrap_Nil(t *testing.T) {
	se := &ShareError{
		Operation: "unseal",
		Message:   "no underlying error",
	}
	assert.Nil(t, se.Unwrap())
}

// --- Error types verification ---

func TestShareErrors_AreDistinct(t *testing.T) {
	allErrors := []error{
		ErrShareStoreOpen,
		ErrShareStoreList,
		ErrShareImportRead,
		ErrShareImportParse,
		ErrShareImportValidate,
		ErrShareImportSave,
		ErrShareExportLoad,
		ErrShareExportWrite,
		ErrShareExportMissingFile,
		ErrShareReceiveConnect,
		ErrShareReceiveList,
		ErrShareReceiveSave,
		ErrShareUnsealLoad,
		ErrShareUnsealConnect,
		ErrShareUnsealSubmit,
		ErrShareDeleteFailed,
		ErrShareMissingServer,
		ErrShareMissingGroupID,
		ErrShareMissingFile,
		ErrShareMissingShareIndex,
	}

	for i := 0; i < len(allErrors); i++ {
		for j := i + 1; j < len(allErrors); j++ {
			assert.NotEqual(t, allErrors[i].Error(), allErrors[j].Error(),
				"errors at index %d and %d should be distinct", i, j)
		}
	}
}

func TestShareErrors_AllContainPrefix(t *testing.T) {
	allErrors := []error{
		ErrShareStoreOpen,
		ErrShareStoreList,
		ErrShareImportRead,
		ErrShareImportParse,
		ErrShareImportValidate,
		ErrShareImportSave,
		ErrShareExportLoad,
		ErrShareExportWrite,
		ErrShareExportMissingFile,
		ErrShareReceiveConnect,
		ErrShareReceiveList,
		ErrShareReceiveSave,
		ErrShareUnsealLoad,
		ErrShareUnsealConnect,
		ErrShareUnsealSubmit,
		ErrShareDeleteFailed,
		ErrShareMissingServer,
		ErrShareMissingGroupID,
		ErrShareMissingFile,
		ErrShareMissingShareIndex,
	}

	for _, err := range allErrors {
		assert.Contains(t, err.Error(), "share:", "error %q should contain 'share:' prefix", err.Error())
	}
}

// --- defaultShareClientFactory tests ---

func TestDefaultShareClientFactory_EmptyServer(t *testing.T) {
	client, err := defaultShareClientFactory("")
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrShareMissingServer)
}

func TestDefaultShareClientFactory_WithServer(t *testing.T) {
	client, err := defaultShareClientFactory("grpc://localhost:9090")
	assert.Nil(t, client)
	assert.Error(t, err)
	var shareErr *ShareError
	assert.True(t, errors.As(err, &shareErr))
	assert.Equal(t, "connect", shareErr.Operation)
}

// --- runShareList tests ---

func TestRunShareList_Empty(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := runShareList(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No shares stored locally.")
}

func TestRunShareList_WithEntries(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Save two entries to the store.
	store := createTestShareStore(t)
	ctx := context.Background()

	entry1 := newShareEntry("grpc://server1:9090", "group-a")
	entry1.GroupName = "Alpha"
	entry1.ShareIndex = 1
	entry1.Purpose = "barrier"
	require.NoError(t, store.Save(ctx, entry1))

	entry2 := newShareEntry("grpc://server2:9090", "group-b")
	entry2.GroupName = "Bravo"
	entry2.ShareIndex = 2
	entry2.Purpose = "signing-key"
	require.NoError(t, store.Save(ctx, entry2))
	require.NoError(t, store.Close())

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&buf)

	err := runShareList(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Locally Stored Shares (2)")
	assert.Contains(t, output, "SERVER")
	assert.Contains(t, output, "GROUP ID")
	assert.Contains(t, output, "GROUP NAME")
	assert.Contains(t, output, "INDEX")
	assert.Contains(t, output, "PURPOSE")
	assert.Contains(t, output, "RECEIVED AT")
	assert.Contains(t, output, "grpc://server1:9090")
	assert.Contains(t, output, "group-a")
	assert.Contains(t, output, "Alpha")
	assert.Contains(t, output, "grpc://server2:9090")
	assert.Contains(t, output, "group-b")
	assert.Contains(t, output, "Bravo")
	assert.Contains(t, output, "barrier")
	assert.Contains(t, output, "signing-key")
}

// --- runShareImport tests ---

func TestRunShareImport_Success(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	entry := newShareEntry("grpc://import-server:9090", "imported-group")

	data, err := json.MarshalIndent(entry, "", "  ")
	require.NoError(t, err)

	filePath := filepath.Join(tempDir, "share-import.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("file", filePath, "")
	cmd.SetOut(&buf)

	err = runShareImport(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Imported share")
	assert.Contains(t, output, "grpc://import-server:9090")
	assert.Contains(t, output, "imported-group")
}

func TestRunShareImport_MissingFileFlag(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("file", "", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareImport(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingFile)
}

func TestRunShareImport_FileNotFound(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("file", "/nonexistent/path/share.json", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareImport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareImportRead))
}

func TestRunShareImport_InvalidJSON(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	filePath := filepath.Join(tempDir, "bad.json")
	require.NoError(t, os.WriteFile(filePath, []byte("not-valid-json{{{"), 0600))

	cmd := &cobra.Command{}
	cmd.Flags().String("file", filePath, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareImport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareImportParse))
}

func TestRunShareImport_InvalidEntry_MissingServerURL(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Entry with missing server_url should fail validation.
	entry := &sharestore.ShareEntry{
		GroupID:   "some-group",
		ShareData: []byte("data"),
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	filePath := filepath.Join(tempDir, "invalid-entry.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	cmd := &cobra.Command{}
	cmd.Flags().String("file", filePath, "")
	cmd.SetOut(&bytes.Buffer{})

	err = runShareImport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareImportValidate))
}

func TestRunShareImport_InvalidEntry_MissingShareData(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	entry := &sharestore.ShareEntry{
		ServerURL: "grpc://server:9090",
		GroupID:   "some-group",
		// ShareData is empty - should fail validation.
	}

	data, err := json.Marshal(entry)
	require.NoError(t, err)

	filePath := filepath.Join(tempDir, "no-share-data.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	cmd := &cobra.Command{}
	cmd.Flags().String("file", filePath, "")
	cmd.SetOut(&bytes.Buffer{})

	err = runShareImport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareImportValidate))
}

func TestRunShareImport_DuplicateEntry(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	entry := newShareEntry("grpc://dup-server:9090", "dup-group")
	data, err := json.MarshalIndent(entry, "", "  ")
	require.NoError(t, err)

	filePath := filepath.Join(tempDir, "dup-share.json")
	require.NoError(t, os.WriteFile(filePath, data, 0600))

	cmd := &cobra.Command{}
	cmd.Flags().String("file", filePath, "")

	// First import should succeed.
	var buf1 bytes.Buffer
	cmd.SetOut(&buf1)
	require.NoError(t, runShareImport(cmd, nil))

	// Second import of the same entry should fail (ErrShareExists wrapped by ErrShareImportSave).
	var buf2 bytes.Buffer
	cmd.SetOut(&buf2)
	err = runShareImport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareImportSave))
}

// --- runShareExport tests ---

func TestRunShareExport_Success(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Save an entry to export.
	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://export-server:9090", "export-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	exportFile := filepath.Join(tempDir, "exported-share.json")

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://export-server:9090", "")
	cmd.Flags().String("group-id", "export-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", exportFile, "")
	cmd.SetOut(&buf)

	err := runShareExport(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Exported share to:")
	assert.Contains(t, output, exportFile)

	// Verify the exported file can be read back.
	data, err := os.ReadFile(exportFile)
	require.NoError(t, err)

	var exported sharestore.ShareEntry
	require.NoError(t, json.Unmarshal(data, &exported))
	assert.Equal(t, "grpc://export-server:9090", exported.ServerURL)
	assert.Equal(t, "export-group", exported.GroupID)
	assert.Equal(t, entry.ShareData, exported.ShareData)
}

func TestRunShareExport_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", "/tmp/out.json", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareExport(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingServer)
}

func TestRunShareExport_MissingGroupID(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", "/tmp/out.json", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareExport(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingGroupID)
}

func TestRunShareExport_MissingShareIndex(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 0, "")
	cmd.Flags().String("file", "/tmp/out.json", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareExport(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingShareIndex)
}

func TestRunShareExport_MissingFile(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", "", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareExport(cmd, nil)
	assert.ErrorIs(t, err, ErrShareExportMissingFile)
}

func TestRunShareExport_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	exportFile := filepath.Join(tempDir, "not-found-export.json")

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://nonexistent:9090", "")
	cmd.Flags().String("group-id", "missing-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", exportFile, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareExport(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareExportLoad))
}

func TestRunShareExport_FilePermissions(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://perm-server:9090", "perm-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	exportFile := filepath.Join(tempDir, "perm-export.json")

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://perm-server:9090", "")
	cmd.Flags().String("group-id", "perm-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.Flags().String("file", exportFile, "")
	cmd.SetOut(&bytes.Buffer{})

	require.NoError(t, runShareExport(cmd, nil))

	// Verify the file was written with secure permissions (0600).
	info, err := os.Stat(exportFile)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
}

// --- runShareReceive tests ---

func TestRunShareReceive_Success(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	now := time.Now().UTC()
	mock := &mockShareService{
		listSharesResp: &transport.ListSharesResponse{
			Shares: []transport.ShareInfo{
				{
					ServerURL:  "grpc://recv-server:9090",
					GroupID:    "recv-group",
					GroupName:  "Recovery",
					ShareIndex: 1,
					ShareData:  []byte("secret-share-data"),
					Purpose:    "barrier",
					ReceivedAt: now,
				},
			},
		},
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://recv-server:9090", "")
	cmd.SetOut(&buf)

	err := runShareReceive(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Received 1 share(s)")
	assert.Contains(t, output, "saved 1 new share(s)")
	assert.True(t, mock.closeCalled, "Close should be called on client")
}

func TestRunShareReceive_NoShares(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	mock := &mockShareService{
		listSharesResp: &transport.ListSharesResponse{
			Shares: []transport.ShareInfo{},
		},
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://empty-server:9090", "")
	cmd.SetOut(&buf)

	err := runShareReceive(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "No shares available on the server.")
}

func TestRunShareReceive_FactoryError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return nil, errors.New("factory failure")
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://fail-server:9090", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareReceive(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareReceiveConnect))
}

func TestRunShareReceive_ConnectError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	mock := &mockShareService{
		connectErr: errors.New("connection refused"),
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://unreachable:9090", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareReceive(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareReceiveConnect))
}

func TestRunShareReceive_ListError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	mock := &mockShareService{
		listSharesErr: errors.New("permission denied"),
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://list-fail:9090", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareReceive(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareReceiveList))
}

func TestRunShareReceive_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareReceive(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingServer)
}

func TestRunShareReceive_DuplicateShareSkipped(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	now := time.Now().UTC()

	// Pre-save a share so the receive will encounter a duplicate.
	store := createTestShareStore(t)
	ctx := context.Background()
	entry := &sharestore.ShareEntry{
		ServerURL:  "grpc://dup-recv-server:9090",
		GroupID:    "dup-group",
		GroupName:  "Dup Group",
		ShareIndex: 1,
		ShareData:  []byte("existing-data"),
		Purpose:    "barrier",
		ReceivedAt: now,
	}
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	mock := &mockShareService{
		listSharesResp: &transport.ListSharesResponse{
			Shares: []transport.ShareInfo{
				{
					GroupID:    "dup-group",
					GroupName:  "Dup Group",
					ShareIndex: 1,
					Purpose:    "barrier",
					ReceivedAt: now,
				},
			},
		},
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://dup-recv-server:9090", "")
	cmd.SetOut(&buf)

	err := runShareReceive(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	// Should show 1 received but 0 saved (duplicate skipped).
	assert.Contains(t, output, "Received 1 share(s)")
	assert.Contains(t, output, "saved 0 new share(s)")
}

// --- runShareUnseal tests ---

func TestRunShareUnseal_Success(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Save a share locally for the unseal operation to load.
	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://unseal-server:9090", "unseal-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	mock := &mockShareService{
		barrierUnsealResp: &transport.BarrierUnsealShareResponse{
			Required:  3,
			Submitted: 2,
			Complete:  false,
		},
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://unseal-server:9090", "")
	cmd.Flags().String("group-id", "unseal-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&buf)

	err := runShareUnseal(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Share submitted for group unseal-group")
	assert.Contains(t, output, "Required:  3")
	assert.Contains(t, output, "Submitted: 2")
	assert.Contains(t, output, "1 more share(s) needed")
}

func TestRunShareUnseal_QuorumReached(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://quorum-server:9090", "quorum-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	mock := &mockShareService{
		barrierUnsealResp: &transport.BarrierUnsealShareResponse{
			Required:  3,
			Submitted: 3,
			Complete:  true,
		},
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://quorum-server:9090", "")
	cmd.Flags().String("group-id", "quorum-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&buf)

	err := runShareUnseal(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Quorum reached - barrier unsealed!")
}

func TestRunShareUnseal_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingServer)
}

func TestRunShareUnseal_MissingGroupID(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingGroupID)
}

func TestRunShareUnseal_MissingShareIndex(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 0, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingShareIndex)
}

func TestRunShareUnseal_ConnectError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://connect-fail:9090", "conn-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return nil, errors.New("transport error")
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://connect-fail:9090", "")
	cmd.Flags().String("group-id", "conn-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareUnsealConnect))
}

func TestRunShareUnseal_ClientConnectError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://client-connect-fail:9090", "ccf-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	mock := &mockShareService{
		connectErr: errors.New("dial failed"),
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://client-connect-fail:9090", "")
	cmd.Flags().String("group-id", "ccf-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareUnsealConnect))
}

func TestRunShareUnseal_SubmitError(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://submit-fail:9090", "submit-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	mock := &mockShareService{
		barrierUnsealErr: errors.New("invalid share"),
	}

	orig := shareClientFactory
	defer func() { shareClientFactory = orig }()
	shareClientFactory = func(_ string) (ShareService, error) {
		return mock, nil
	}

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://submit-fail:9090", "")
	cmd.Flags().String("group-id", "submit-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareUnsealSubmit))
}

func TestRunShareUnseal_ShareNotFound(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://missing:9090", "")
	cmd.Flags().String("group-id", "nonexistent-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareUnseal(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareUnsealLoad))
}

// --- runShareDelete tests ---

func TestRunShareDelete_Success(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store := createTestShareStore(t)
	ctx := context.Background()
	entry := newShareEntry("grpc://delete-server:9090", "delete-group")
	require.NoError(t, store.Save(ctx, entry))
	require.NoError(t, store.Close())

	var buf bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://delete-server:9090", "")
	cmd.Flags().String("group-id", "delete-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&buf)

	err := runShareDelete(cmd, nil)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Deleted share")
	assert.Contains(t, output, "grpc://delete-server:9090")
	assert.Contains(t, output, "delete-group")

	// Verify it was actually deleted by trying to load it.
	store2 := createTestShareStore(t)
	_, err = store2.Load(ctx, "grpc://delete-server:9090", "delete-group", 1)
	assert.ErrorIs(t, err, sharestore.ErrShareNotFound)
}

func TestRunShareDelete_NotFound(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://ghost:9090", "")
	cmd.Flags().String("group-id", "ghost-group", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareDelete(cmd, nil)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrShareDeleteFailed))
}

func TestRunShareDelete_MissingServer(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareDelete(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingServer)
}

func TestRunShareDelete_MissingGroupID(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "", "")
	cmd.Flags().Int("share-index", 1, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareDelete(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingGroupID)
}

func TestRunShareDelete_MissingShareIndex(t *testing.T) {
	cmd := &cobra.Command{}
	cmd.Flags().String("server", "grpc://host:9090", "")
	cmd.Flags().String("group-id", "gid", "")
	cmd.Flags().Int("share-index", 0, "")
	cmd.SetOut(&bytes.Buffer{})

	err := runShareDelete(cmd, nil)
	assert.ErrorIs(t, err, ErrShareMissingShareIndex)
}

// --- Round-trip: import -> list -> export -> delete ---

func TestShareRoundTrip_ImportListExportDelete(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	entry := newShareEntry("grpc://roundtrip:9090", "rt-group")

	// Step 1: Import.
	importData, err := json.MarshalIndent(entry, "", "  ")
	require.NoError(t, err)

	importFile := filepath.Join(tempDir, "rt-import.json")
	require.NoError(t, os.WriteFile(importFile, importData, 0600))

	importCmd := &cobra.Command{}
	importCmd.Flags().String("file", importFile, "")
	importCmd.SetOut(&bytes.Buffer{})
	require.NoError(t, runShareImport(importCmd, nil))

	// Step 2: List (verify it appears).
	var listBuf bytes.Buffer
	listCmd := &cobra.Command{}
	listCmd.SetOut(&listBuf)
	require.NoError(t, runShareList(listCmd, nil))
	assert.Contains(t, listBuf.String(), "grpc://roundtrip:9090")
	assert.Contains(t, listBuf.String(), "rt-group")

	// Step 3: Export.
	exportFile := filepath.Join(tempDir, "rt-export.json")
	exportCmd := &cobra.Command{}
	exportCmd.Flags().String("server", "grpc://roundtrip:9090", "")
	exportCmd.Flags().String("group-id", "rt-group", "")
	exportCmd.Flags().Int("share-index", 1, "")
	exportCmd.Flags().String("file", exportFile, "")
	exportCmd.SetOut(&bytes.Buffer{})
	require.NoError(t, runShareExport(exportCmd, nil))

	// Verify exported content matches.
	exportData, err := os.ReadFile(exportFile)
	require.NoError(t, err)
	var exported sharestore.ShareEntry
	require.NoError(t, json.Unmarshal(exportData, &exported))
	assert.Equal(t, "grpc://roundtrip:9090", exported.ServerURL)
	assert.Equal(t, "rt-group", exported.GroupID)
	assert.Equal(t, entry.ShareData, exported.ShareData)

	// Step 4: Delete.
	deleteCmd := &cobra.Command{}
	deleteCmd.Flags().String("server", "grpc://roundtrip:9090", "")
	deleteCmd.Flags().String("group-id", "rt-group", "")
	deleteCmd.Flags().Int("share-index", 1, "")
	deleteCmd.SetOut(&bytes.Buffer{})
	require.NoError(t, runShareDelete(deleteCmd, nil))

	// Step 5: List again (verify empty).
	var listBuf2 bytes.Buffer
	listCmd2 := &cobra.Command{}
	listCmd2.SetOut(&listBuf2)
	require.NoError(t, runShareList(listCmd2, nil))
	assert.Contains(t, listBuf2.String(), "No shares stored locally.")
}

// --- openLocalShareStore tests ---

func TestOpenLocalShareStore_CreatesStoreDir(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	store, err := openLocalShareStore()
	require.NoError(t, err)
	require.NotNil(t, store)
	require.NoError(t, store.Close())

	// Verify the shares directory was created.
	shareDir := filepath.Join(tempDir, ".xkey", "shares")
	info, err := os.Stat(shareDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

// --- resolveShareDataDir tests ---

func TestResolveShareDataDir_Default(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	// Clear any env overrides.
	t.Setenv("XKEY_DATA_DIR", "")

	// Ensure the barrier data dir flag is empty.
	saved := barrierDataDir
	barrierDataDir = ""
	defer func() { barrierDataDir = saved }()

	dir, err := resolveShareDataDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(tempDir, ".xkey"), dir)
}

func TestResolveShareDataDir_EnvOverride(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	customDir := filepath.Join(tempDir, "custom-data")
	t.Setenv("XKEY_DATA_DIR", customDir)

	saved := barrierDataDir
	barrierDataDir = ""
	defer func() { barrierDataDir = saved }()

	dir, err := resolveShareDataDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(customDir), dir)
}

func TestResolveShareDataDir_FlagOverride(t *testing.T) {
	tempDir := t.TempDir()
	t.Setenv("HOME", tempDir)

	flagDir := filepath.Join(tempDir, "flag-data")

	saved := barrierDataDir
	barrierDataDir = flagDir
	defer func() { barrierDataDir = saved }()

	dir, err := resolveShareDataDir()
	require.NoError(t, err)
	assert.Equal(t, filepath.Clean(flagDir), dir)
}

// --- Constants verification ---

func TestShareConstants(t *testing.T) {
	assert.Equal(t, "shares", defaultShareStoreSubdir)
	assert.Equal(t, "shamir", defaultShareStorePrefix)
}
