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
	"github.com/stretchr/testify/require"
)

// withHome points $HOME at dir for the duration of the test, so
// legacyCandidates' $HOME/.xkey-store/ssh probe is deterministic.
func withHome(t *testing.T, dir string) {
	t.Helper()
	t.Setenv("HOME", dir)
}

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

// seedLegacyStore writes raw key/value pairs directly into a plain file
// store at dir, bypassing ResolveBackend so the test controls exactly what
// legacy data looks like.
func seedLegacyStore(t *testing.T, dir string, kv map[string]string) {
	t.Helper()
	backend, err := xkmssdk.StorageOpenEngine(xkmssdk.StorageEngineConfig{Kind: xkmssdk.StorageEngineFile, Path: dir})
	if err != nil {
		t.Fatalf("seed open: %v", err)
	}
	defer func() { _ = backend.Close() }()
	for k, v := range kv {
		if err := backend.Put(context.Background(), k, []byte(v)); err != nil {
			t.Fatalf("seed put %q: %v", k, err)
		}
	}
}

func TestMigrateLegacyStores_DataDirIdempotent(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	withHome(t, t.TempDir()) // no $HOME/.xkey-store candidate in this test

	legacyDir := filepath.Join(dataDir, "ssh")
	seedLegacyStore(t, legacyDir, map[string]string{"profiles/a": "1", "hosts/b": "2"})

	barrier := xkmssdk.NewStorageMemory()
	dst, err := ResolveBackend("", "", barrier)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}

	if err := MigrateLegacyStores(ctx, dataDir, dst); err != nil {
		t.Fatalf("MigrateLegacyStores: %v", err)
	}

	for k, want := range map[string]string{"profiles/a": "1", "hosts/b": "2"} {
		got, gerr := dst.Get(ctx, k)
		if gerr != nil || string(got) != want {
			t.Fatalf("migrated key %q: got %q, err %v", k, got, gerr)
		}
	}
	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("expected legacy dir to be renamed away, stat err = %v", err)
	}
	if _, err := os.Stat(legacyDir + backupSuffix); err != nil {
		t.Fatalf("expected backup dir to exist: %v", err)
	}

	// Idempotent: a second call finds nothing left to migrate and succeeds.
	if err := MigrateLegacyStores(ctx, dataDir, dst); err != nil {
		t.Fatalf("second MigrateLegacyStores: %v", err)
	}
}

func TestMigrateLegacyStores_HomeCandidate(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir() // no dataDir/ssh candidate
	home := t.TempDir()
	withHome(t, home)

	legacyDir := filepath.Join(home, ".xkey-store", "ssh")
	seedLegacyStore(t, legacyDir, map[string]string{"keys/laptop": "k"})

	barrier := xkmssdk.NewStorageMemory()
	dst, err := ResolveBackend("", "", barrier)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}

	if err := MigrateLegacyStores(ctx, dataDir, dst); err != nil {
		t.Fatalf("MigrateLegacyStores: %v", err)
	}
	got, err := dst.Get(ctx, "keys/laptop")
	if err != nil || string(got) != "k" {
		t.Fatalf("migrated key: got %q, err %v", got, err)
	}
	if _, err := os.Stat(legacyDir); !os.IsNotExist(err) {
		t.Fatalf("expected home legacy dir renamed away, stat err = %v", err)
	}
}

func TestMigrateLegacyStores_NoLegacyDirs(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	withHome(t, t.TempDir())

	barrier := xkmssdk.NewStorageMemory()
	dst, err := ResolveBackend("", "", barrier)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}
	if err := MigrateLegacyStores(ctx, dataDir, dst); err != nil {
		t.Fatalf("expected no error when no legacy dirs exist, got %v", err)
	}
}

func TestMigrateLegacyStores_LegacyPathIsFile(t *testing.T) {
	ctx := context.Background()
	dataDir := t.TempDir()
	withHome(t, t.TempDir())

	// "ssh" exists but is a regular file, not a directory — must be skipped,
	// not treated as an error.
	if err := os.WriteFile(filepath.Join(dataDir, "ssh"), []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("seed file: %v", err)
	}

	barrier := xkmssdk.NewStorageMemory()
	dst, err := ResolveBackend("", "", barrier)
	if err != nil {
		t.Fatalf("ResolveBackend: %v", err)
	}
	if err := MigrateLegacyStores(ctx, dataDir, dst); err != nil {
		t.Fatalf("expected no error when legacy path is a file, got %v", err)
	}
}

func TestMigrateLegacyStores_NilDestination(t *testing.T) {
	err := MigrateLegacyStores(context.Background(), t.TempDir(), nil)
	var target *NilDestinationError
	if !errors.As(err, &target) {
		t.Fatalf("expected *NilDestinationError, got %v", err)
	}
}

// TestSSHStoreErrors verifies the typed error messages and unwrapping the CLI
// and GUI surface to users.
func TestSSHStoreErrors(t *testing.T) {
	t.Parallel()

	assert.Equal(t,
		"sshstore: dataDir is required when no barrier backend is supplied",
		(&MissingDataDirError{}).Error())

	assert.Equal(t, "sshstore: destination backend is required", (&NilDestinationError{}).Error())

	cause := errors.New("permission denied")
	migErr := &MigrationError{Dir: "/data/ssh", Op: "rename", Err: cause}
	assert.Equal(t, "sshstore: migrate /data/ssh: rename: permission denied", migErr.Error())
	assert.ErrorIs(t, migErr, cause)
}

// TestMigrateLegacyStores_StatFailure covers the non-ENOENT stat branch: a
// legacy path that cannot be inspected must abort the migration with a typed
// error rather than silently skipping (which would strand plaintext keys).
func TestMigrateLegacyStores_StatFailure(t *testing.T) {
	t.Parallel()

	dataDir := t.TempDir()

	// Put a regular file where the "ssh" directory's parent must be, so
	// stat("<dataDir>/blocker/ssh") fails with ENOTDIR rather than ENOENT.
	blocker := filepath.Join(dataDir, "blocker")
	require.NoError(t, os.WriteFile(blocker, []byte("x"), 0600))

	dst := xkmssdk.NewStorageMemory()

	err := MigrateLegacyStores(context.Background(), blocker, dst)
	require.Error(t, err)

	var migErr *MigrationError
	require.ErrorAs(t, err, &migErr)
	assert.Equal(t, "stat", migErr.Op)
	assert.Equal(t, filepath.Join(blocker, "ssh"), migErr.Dir)
}

// TestMigrateLegacyStores_RenameFailure verifies a legacy directory whose
// contents were imported but which cannot be renamed away is reported, so the
// caller does not believe the plaintext store is gone.
func TestMigrateLegacyStores_RenameFailure(t *testing.T) {
	dataDir := t.TempDir()
	legacy := filepath.Join(dataDir, "ssh")
	require.NoError(t, os.MkdirAll(legacy, 0700))
	require.NoError(t, os.WriteFile(filepath.Join(legacy, "key"), []byte("value"), 0600))

	// Occupy the backup path with a non-empty directory so the rename fails
	// for any user, including root.
	backup := legacy + ".pre-barrier.bak"
	require.NoError(t, os.MkdirAll(filepath.Join(backup, "occupied"), 0700))

	// Isolate the home candidate so only the dataDir candidate is consulted.
	t.Setenv("HOME", t.TempDir())

	err := MigrateLegacyStores(context.Background(), dataDir, xkmssdk.NewStorageMemory())
	require.Error(t, err)

	var migErr *MigrationError
	require.ErrorAs(t, err, &migErr)
	assert.Equal(t, "rename", migErr.Op)
}
