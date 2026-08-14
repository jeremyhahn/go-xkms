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

//go:build integration && linux

// Package xkey provides integration tests for the "xkey share" command
// group. The local verbs - list, import, export, and delete - operate
// entirely on the local Shamir share vault under XKEY_HOME. The server
// verbs - receive and unseal - now build a real SDK transport client from
// the --server URL, so they are covered here through their error paths: an
// unsupported scheme, an unreachable endpoint, and a missing local share.
package xkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// writeShareEntryFile marshals entry to indented JSON and writes it to a
// new file under dir, returning the file's path.
func writeShareEntryFile(t *testing.T, dir, name string, entry *xkms.ShareEntry) string {
	t.Helper()

	data, err := json.MarshalIndent(entry, "", "  ")
	require.NoError(t, err)

	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, data, 0600))
	return path
}

// TestShareCLI_List_Empty verifies that "share list" succeeds and reports
// no shares against a freshly initialized store.
func TestShareCLI_List_Empty(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	stdout := RunXKeyExpectSuccess(t, binary, "", "share", "list")

	assert.Contains(t, stdout, "No shares stored locally.")
}

// TestShareCLI_ImportListExportDelete_HappyPath exercises the full local
// lifecycle: craft a share JSON file matching the ShareEntry schema,
// import it, verify it appears in "list", export it back out and verify
// the exported content is equivalent to the original, then delete it and
// verify both "list" and "get" reflect the removal.
func TestShareCLI_ImportListExportDelete_HappyPath(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	const (
		serverURL  = "grpc://xkmsd.example.com:9090"
		groupID    = "barrier-ops"
		groupName  = "Barrier Operators"
		shareIndex = 1
		purpose    = "barrier"
	)
	shareData := []byte("shamir-share-material-0123456789")
	receivedAt := time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC)

	original := &xkms.ShareEntry{
		ServerURL:  serverURL,
		GroupID:    groupID,
		GroupName:  groupName,
		ShareIndex: shareIndex,
		ShareData:  shareData,
		Purpose:    purpose,
		ReceivedAt: receivedAt,
	}

	importFile := writeShareEntryFile(t, xkeyHome, "share-import.json", original)

	// Import.
	importOut := RunXKeyExpectSuccess(t, binary, "", "share", "import", "--file", importFile)
	assert.Contains(t, importOut, serverURL)
	assert.Contains(t, importOut, groupID)

	// List shows the imported share.
	listOut := RunXKeyExpectSuccess(t, binary, "", "share", "list")
	assert.Contains(t, listOut, serverURL)
	assert.Contains(t, listOut, groupID)
	assert.Contains(t, listOut, groupName)
	assert.Contains(t, listOut, purpose)

	// Export round-trips the same content.
	exportFile := filepath.Join(xkeyHome, "share-export.json")
	exportOut := RunXKeyExpectSuccess(t, binary, "",
		"share", "export",
		"--server", serverURL,
		"--group-id", groupID,
		"--share-index", "1",
		"--file", exportFile,
	)
	assert.Contains(t, exportOut, exportFile)

	exportedData, err := os.ReadFile(exportFile)
	require.NoError(t, err)

	var exported xkms.ShareEntry
	require.NoError(t, json.Unmarshal(exportedData, &exported))

	assert.Equal(t, original.ServerURL, exported.ServerURL)
	assert.Equal(t, original.GroupID, exported.GroupID)
	assert.Equal(t, original.GroupName, exported.GroupName)
	assert.Equal(t, original.ShareIndex, exported.ShareIndex)
	assert.Equal(t, original.ShareData, exported.ShareData)
	assert.Equal(t, original.Purpose, exported.Purpose)
	assert.True(t, original.ReceivedAt.Equal(exported.ReceivedAt))

	// Delete removes the share.
	deleteOut := RunXKeyExpectSuccess(t, binary, "",
		"share", "delete",
		"--server", serverURL,
		"--group-id", groupID,
		"--share-index", "1",
	)
	assert.Contains(t, deleteOut, serverURL)
	assert.Contains(t, deleteOut, groupID)

	// List is empty again.
	listAfterDelete := RunXKeyExpectSuccess(t, binary, "", "share", "list")
	assert.Contains(t, listAfterDelete, "No shares stored locally.")

	// Exporting the now-deleted share fails.
	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "export",
		"--server", serverURL,
		"--group-id", groupID,
		"--share-index", "1",
		"--file", filepath.Join(xkeyHome, "share-export-after-delete.json"),
	)
	assert.Contains(t, errOutput, "share: failed to load share for export")
}

// TestShareCLI_Import_NonexistentFile verifies that "share import" fails
// with a clear error when the source file does not exist.
func TestShareCLI_Import_NonexistentFile(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "import", "--file", filepath.Join(xkeyHome, "does-not-exist.json"))

	assert.Contains(t, errOutput, "share: failed to read import file")
}

// TestShareCLI_Import_InvalidJSON verifies that "share import" fails with
// a clear error when the source file is not valid JSON.
func TestShareCLI_Import_InvalidJSON(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	invalidFile := filepath.Join(xkeyHome, "invalid-share.json")
	require.NoError(t, os.WriteFile(invalidFile, []byte("{ this is not valid json"), 0600))

	errOutput := RunXKeyExpectFailure(t, binary, "", "share", "import", "--file", invalidFile)

	assert.Contains(t, errOutput, "share: failed to parse import file")
}

// TestShareCLI_Import_FailsValidation verifies that "share import" rejects
// a syntactically valid JSON document that is missing required ShareEntry
// fields (e.g. empty share data).
func TestShareCLI_Import_FailsValidation(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	incomplete := &xkms.ShareEntry{
		ServerURL:  "grpc://xkmsd.example.com:9090",
		GroupID:    "barrier-ops",
		ShareIndex: 1,
		// ShareData intentionally omitted - Validate() requires it.
	}
	importFile := writeShareEntryFile(t, xkeyHome, "share-incomplete.json", incomplete)

	errOutput := RunXKeyExpectFailure(t, binary, "", "share", "import", "--file", importFile)

	assert.Contains(t, errOutput, "share: imported share failed validation")
}

// TestShareCLI_Delete_UnknownID verifies that "share delete" fails with a
// clear error when the identified share was never imported.
func TestShareCLI_Delete_UnknownID(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "delete",
		"--server", "grpc://xkmsd.example.com:9090",
		"--group-id", "nonexistent-group",
		"--share-index", "1",
	)

	assert.Contains(t, errOutput, "share: failed to delete share")
}

// TestShareCLI_Import_MissingFileFlag verifies that "share import" without
// the required --file flag is rejected by cobra flag validation before
// any command logic runs.
func TestShareCLI_Import_MissingFileFlag(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)

	errOutput := RunXKeyExpectFailure(t, binary, "", "share", "import")

	assert.Contains(t, errOutput, "file")
}

// ---------------------------------------------------------------------------
// Server-facing verbs: receive and unseal
// ---------------------------------------------------------------------------

// isolateShareEnv sets up a clean XKEY_HOME and clears every ambient xkmsd
// credential source so the server verbs observe only what the test supplies.
func isolateShareEnv(t *testing.T) string {
	t.Helper()

	xkeyHome := SetupCleanEnvironment(t)
	t.Setenv("XKEY_HOME", xkeyHome)
	t.Setenv("XKMSD_TOKEN", "")
	t.Setenv("XKMSD_TLS_CA", "")

	return xkeyHome
}

// TestShareCLI_Receive_UnsupportedScheme verifies "share receive" resolves the
// --server URL through the shared transport dispatch and rejects an unknown
// scheme with the supported-scheme list. Before the client factory was
// implemented every --server value produced the same "requires a running
// xkmsd server" message regardless of the URL.
func TestShareCLI_Receive_UnsupportedScheme(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "receive", "--server", "ftp://xkmsd.example.invalid:21")

	assert.Contains(t, errOutput, "share: failed to connect to server")
	assert.Contains(t, errOutput, "xkmsd: unsupported server URL scheme")
	assert.Contains(t, errOutput, "grpcs://")
	assert.NotContains(t, errOutput, "requires a running xkmsd server")
}

// TestShareCLI_Receive_UnreachableServer verifies "share receive" really
// dials the configured endpoint and reports the connection failure.
func TestShareCLI_Receive_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "receive", "--server", "unix://"+filepath.Join(xkeyHome, "absent-xkmsd.sock"))

	assert.Contains(t, errOutput, "share: failed to connect to server")
	assert.Contains(t, errOutput, "no such file or directory")
	assert.NotContains(t, errOutput, "requires a running xkmsd server")
}

// TestShareCLI_Receive_ConnectionRefused verifies an http:// URL selects the
// REST transport and reports the refused TCP connection.
func TestShareCLI_Receive_ConnectionRefused(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "receive", "--server", "http://127.0.0.1:1")

	assert.Contains(t, errOutput, "share: failed to connect to server")
	assert.Contains(t, errOutput, "connection refused")
}

// TestShareCLI_Receive_MissingServerFlag verifies the required flag is
// enforced by cobra before any transport work.
func TestShareCLI_Receive_MissingServerFlag(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "", "share", "receive")

	assert.Contains(t, errOutput, "server")
}

// TestShareCLI_Unseal_UnreachableServer verifies "share unseal" loads the
// local share, then fails on the real connection attempt rather than on a
// placeholder client factory.
func TestShareCLI_Unseal_UnreachableServer(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateShareEnv(t)

	serverURL := "unix://" + filepath.Join(xkeyHome, "absent-xkmsd.sock")

	entry := &xkms.ShareEntry{
		ServerURL:  serverURL,
		GroupID:    "barrier-ops",
		GroupName:  "Barrier Operators",
		ShareIndex: 1,
		ShareData:  []byte("shamir-share-material-0123456789"),
		Purpose:    "barrier",
		ReceivedAt: time.Date(2026, 1, 15, 12, 0, 0, 0, time.UTC),
	}
	importFile := writeShareEntryFile(t, xkeyHome, "unseal-share.json", entry)
	RunXKeyExpectSuccess(t, binary, "", "share", "import", "--file", importFile)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "unseal",
		"--server", serverURL,
		"--group-id", "barrier-ops",
		"--share-index", "1",
	)

	assert.Contains(t, errOutput, "share: failed to connect to server for unseal")
	assert.Contains(t, errOutput, "no such file or directory")
	assert.NotContains(t, errOutput, "requires a running xkmsd server")
}

// TestShareCLI_Unseal_UnknownShare verifies "share unseal" fails on the local
// lookup before any server connection is attempted.
func TestShareCLI_Unseal_UnknownShare(t *testing.T) {
	binary := getOrBuildBinary(t)
	isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "unseal",
		"--server", "grpc://xkmsd.example.invalid:9090",
		"--group-id", "nonexistent-group",
		"--share-index", "1",
	)

	assert.Contains(t, errOutput, "share: failed to load share for unseal")
}

// TestShareCLI_TLSCAFlag_Rejected verifies the CA-bundle override reaches the
// TLS-bearing transports and fails closed on an unreadable bundle.
func TestShareCLI_TLSCAFlag_Rejected(t *testing.T) {
	binary := getOrBuildBinary(t)
	xkeyHome := isolateShareEnv(t)

	errOutput := RunXKeyExpectFailure(t, binary, "",
		"share", "receive",
		"--server", "grpcs://xkmsd.example.invalid:9090",
		"--tls-ca", filepath.Join(xkeyHome, "missing-ca.pem"),
	)

	assert.Contains(t, errOutput, "xkmsd: failed to build TLS configuration")
}
