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

package sshstore

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
	"github.com/stretchr/testify/assert"
)

func TestResolveBackend_Barrier(t *testing.T) {
	ctx := context.Background()
	barrier := xkmssdk.NewStorageMemory()

	backend, err := ResolveBackend("", "", barrier)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}
	if err := backend.Put(ctx, "foo", []byte("bar")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The value lands in the underlying barrier backend under the "ssh/"
	// prefix, proving the namespacing actually happened.
	raw, err := barrier.Get(ctx, "ssh/foo")
	if err != nil {
		t.Fatalf("expected prefixed key in barrier backend: %v", err)
	}
	if string(raw) != "bar" {
		t.Fatalf("unexpected value: %q", raw)
	}
}

func TestResolveBackend_PlainFile(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()

	backend, err := ResolveBackend(dataDir, xkmssdk.StorageEngineFile, nil)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}
	defer func() { _ = backend.Close() }()

	if err := backend.Put(ctx, "foo", []byte("bar")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "ssh")); err != nil {
		t.Fatalf("expected ssh subdirectory under dataDir: %v", err)
	}
	got, err := backend.Get(ctx, "foo")
	if err != nil || string(got) != "bar" {
		t.Fatalf("Get: got %q, err %v", got, err)
	}
}

func TestResolveBackend_MissingDataDir(t *testing.T) {
	_, err := ResolveBackend("", xkmssdk.StorageEngineFile, nil)
	var target *MissingDataDirError
	if !errors.As(err, &target) {
		t.Fatalf("expected *MissingDataDirError, got %v", err)
	}
}

// TestSSHStoreErrors verifies the typed error message the CLI and GUI
// surface to users.
func TestSSHStoreErrors(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"sshstore: dataDir is required when no barrier backend is supplied",
		(&MissingDataDirError{}).Error())
}
