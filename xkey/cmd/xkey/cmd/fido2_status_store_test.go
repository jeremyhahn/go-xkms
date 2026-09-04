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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// The credential store a passkey lands in is invisible from the filesystem:
// the barrier layout (barrier backend rooted at the data directory, prefix
// "fido2/xkey/") and the file layout (file backend rooted at <dataDir>/fido2,
// prefix "xkey/") compose to the SAME path. The same file name therefore holds
// either an encrypted record or plaintext PKCS#8 depending on how the daemon
// was started. These tests pin that the daemon reports which, and that the
// answer reaches the operator in words.

func TestDescribeStorageNamesTheBarrierStore(t *testing.T) {
	d := &fido2Device{cfg: &FIDO2Config{
		StorageType: FIDO2StorageTypeBarrier,
		StoragePath: "/data/xkey",
	}}

	got := d.describeStorage()
	require.NotNil(t, got)
	require.Equal(t, "barrier", got.Type)
	require.Equal(t, "/data/xkey", got.Path)
	require.Equal(t, fido2BarrierKeyPrefix, got.Prefix)
	require.True(t, got.EncryptedAtRest)
}

func TestDescribeStorageNamesTheFileStoreAsUnencrypted(t *testing.T) {
	d := &fido2Device{cfg: &FIDO2Config{
		StorageType: FIDO2StorageTypeFile,
		StoragePath: "/data/xkey/fido2",
	}}

	got := d.describeStorage()
	require.NotNil(t, got)
	require.Equal(t, "file", got.Type)
	require.Equal(t, fido2FileKeyPrefix, got.Prefix)
	require.False(t, got.EncryptedAtRest,
		"the file store holds plaintext credential records and must not be reported as encrypted")
}

func TestDescribeStorageReportsMemoryAsNonPersistent(t *testing.T) {
	d := &fido2Device{cfg: &FIDO2Config{StorageType: FIDO2StorageTypeMemory}}

	got := d.describeStorage()
	require.NotNil(t, got)
	require.Equal(t, "memory", got.Type)
	require.Empty(t, got.Path, "in-memory storage has no path to report")
	require.False(t, got.EncryptedAtRest)
}

// TestBarrierAndFileKeyPrefixesDiffer pins the two prefixes as distinct. They
// are not interchangeable: each compensates for the root its backend is created
// with, so unifying them silently moves where credentials are read from.
func TestBarrierAndFileKeyPrefixesDiffer(t *testing.T) {
	require.NotEqual(t, fido2BarrierKeyPrefix, fido2FileKeyPrefix,
		"the prefixes compensate for differing backend roots and must not be unified without moving data")
}

// TestHandleStatusReportsTheStore proves the description actually reaches the
// IPC response, not merely that it can be computed.
func TestHandleStatusReportsTheStore(t *testing.T) {
	d := &fido2Device{cfg: &FIDO2Config{
		StorageType: FIDO2StorageTypeFile,
		StoragePath: "/data/xkey/fido2",
	}}

	resp, err := d.HandleStatus()
	require.NoError(t, err)
	require.Equal(t, ipc.StatusOK, resp.Status)
	require.NotNil(t, resp.Storage, "status must name the live store")
	require.Equal(t, "file", resp.Storage.Type)
}

// --------------------------------------------------------------------------
// what the operator actually reads
// --------------------------------------------------------------------------

func TestPrintFIDO2StorageWarnsWhenNotEncrypted(t *testing.T) {
	var out bytes.Buffer
	printFIDO2Storage(&out, &ipc.StorageResult{
		Type:            "file",
		Path:            "/data/xkey/fido2",
		Prefix:          fido2FileKeyPrefix,
		EncryptedAtRest: false,
	})

	got := out.String()
	require.Contains(t, got, "NOT encrypted")
	require.Contains(t, got, "private keys")
	require.Contains(t, got, "/data/xkey/fido2")
}

func TestPrintFIDO2StorageConfirmsEncryption(t *testing.T) {
	var out bytes.Buffer
	printFIDO2Storage(&out, &ipc.StorageResult{
		Type:            "barrier",
		Path:            "/data/xkey",
		Prefix:          fido2BarrierKeyPrefix,
		EncryptedAtRest: true,
	})

	got := out.String()
	require.Contains(t, got, "encrypted by the barrier")
	require.NotContains(t, got, "NOT encrypted",
		"an encrypted store must not carry the plaintext warning")
}

func TestPrintFIDO2StorageSaysMemoryKeepsNothing(t *testing.T) {
	var out bytes.Buffer
	printFIDO2Storage(&out, &ipc.StorageResult{Type: "memory"})

	require.Contains(t, out.String(), "lost when the daemon exits")
}

// TestPrintFIDO2StorageAdmitsWhenUnknown proves an older daemon that does not
// report the field produces an honest "unknown" rather than a default that
// reads as a claim — reporting "encrypted" or "file" here would be worse than
// reporting nothing.
func TestPrintFIDO2StorageAdmitsWhenUnknown(t *testing.T) {
	var out bytes.Buffer
	printFIDO2Storage(&out, nil)

	got := out.String()
	require.Contains(t, got, "unknown")
	require.NotContains(t, got, "encrypted by the barrier")
	require.NotContains(t, got, "NOT encrypted")
}
