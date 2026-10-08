// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// go-qrdb's seal barrier is the ONE at-rest encryption the daemon relies on
// for the FIDO2 passkey store; xkey adds no per-credential wrap of its own.
// `--storage-type file` has no barrier under it, so the daemon must warn once
// per store open that private keys land on disk in plaintext, and point at
// the remedy. `--storage-type memory` never touches disk, so it must not
// carry the same warning (#181).

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateFIDO2Storage_FileWarnsUnencrypted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := &FIDO2Config{
		StorageType: FIDO2StorageTypeFile,
		StoragePath: t.TempDir(),
	}

	storage, err := createFIDO2Storage(cfg, logger)
	require.NoError(t, err)
	defer func() { _ = storage.Close() }()

	got := buf.String()
	assert.Contains(t, got, "passkey store is unencrypted at rest",
		"a plain file store must warn that private keys are plaintext")
	assert.Contains(t, got, "xkey barrier init",
		"the warning must point the operator at the remedy")
}

func TestCreateFIDO2Storage_MemoryDoesNotWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := &FIDO2Config{StorageType: FIDO2StorageTypeMemory}

	storage, err := createFIDO2Storage(cfg, logger)
	require.NoError(t, err)
	defer func() { _ = storage.Close() }()

	assert.Empty(t, buf.String(),
		"in-memory storage never touches disk and must not carry the plaintext warning")
}

// TestNewFIDO2Device_FileStorageWarnsUnencrypted proves the warning reaches
// the operator through the daemon's real construction path, not merely
// through the storage factory in isolation.
func TestNewFIDO2Device_FileStorageWarnsUnencrypted(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := seedPINConfig(t, FIDO2StorageTypeFile, t.TempDir(), "")

	device, err := newFIDO2Device(t.Context(), cfg, logger)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	assert.Contains(t, buf.String(), "passkey store is unencrypted at rest")
}

// TestNewFIDO2Device_MemoryStorageDoesNotWarn is the counterpart: the CLI
// default (memory) must stay silent about at-rest encryption since nothing
// is written to disk.
func TestNewFIDO2Device_MemoryStorageDoesNotWarn(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))

	cfg := seedPINConfig(t, FIDO2StorageTypeMemory, t.TempDir(), "")

	device, err := newFIDO2Device(t.Context(), cfg, logger)
	require.NoError(t, err)
	defer func() { _ = device.Close() }()

	assert.NotContains(t, buf.String(), "passkey store is unencrypted at rest")
}
