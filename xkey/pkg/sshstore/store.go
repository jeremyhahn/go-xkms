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

// Package sshstore is the single construction point for xkey's local SSH
// storage backend (key/profile/host-key-pin persistence), shared by both the
// GUI (xkey/pkg/gui) and the CLI (xkey/cmd/xkey/cmd) so the two front ends
// never diverge on where SSH data lives or how it is protected at rest.
//
// This package must not import xkey/pkg/gui — it sits below both front ends.
package sshstore

import (
	"context"
	"os"
	"path/filepath"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

const (
	// sshSubdir is the storage sub-directory (or key prefix) namespacing all
	// SSH data beneath a data directory / barrier backend.
	sshSubdir = "ssh"

	// barrierPrefix is the key prefix used when the SSH store is routed
	// through the barrier (encrypted at rest).
	barrierPrefix = "ssh/"

	// legacyHomeDir is the pre-shared-store-helper CLI default root
	// ("$HOME/.xkey-store"), one of the two legacy locations MigrateLegacyStores
	// consults.
	legacyHomeDir = ".xkey-store"

	// backupSuffix is appended to a legacy store directory after its contents
	// have been imported, so a subsequent call skips it (the directory no
	// longer exists at its original path) rather than re-importing.
	backupSuffix = ".pre-barrier.bak"
)

// ResolveBackend returns the shared SSH storage backend used by both the GUI
// and the CLI:
//
//   - barrierBackend != nil selects a namespaced, encrypted-at-rest view via
//     xkmssdk.NewStoragePrefixBackend(barrierBackend, "ssh/"). dataDir and
//     engineKind are ignored in this mode.
//   - barrierBackend == nil opens engineKind (file/pebble/memory) rooted at
//     filepath.Join(dataDir, "ssh") via xkmssdk.StorageOpenEngine. dataDir is
//     required in this mode.
func ResolveBackend(dataDir string, engineKind xkmssdk.StorageEngineKind, barrierBackend xkmssdk.StorageBackend) (xkmssdk.StorageBackend, error) {
	if barrierBackend != nil {
		return xkmssdk.NewStoragePrefixBackend(barrierBackend, barrierPrefix)
	}
	if dataDir == "" {
		return nil, &MissingDataDirError{}
	}
	return xkmssdk.StorageOpenEngine(xkmssdk.StorageEngineConfig{
		Kind: engineKind,
		Path: filepath.Join(dataDir, sshSubdir),
	})
}

// MigrateLegacyStores imports entries from the legacy plain-file SSH stores
// into dst, exactly once per legacy directory. It is idempotent: after a
// successful import the source directory is renamed to
// "<dir>.pre-barrier.bak", so on a later call that directory no longer
// exists at its original path and is silently skipped — the same outcome as
// a legacy directory that was never created.
//
// Two legacy locations are consulted, in order:
//
//  1. filepath.Join(dataDir, "ssh") — the plain (unencrypted) store used
//     before the barrier was enabled.
//  2. $HOME/.xkey-store/ssh — the CLI's pre-shared-store-helper default root.
//
// Only call this once a barrier backend is in effect (dst wraps it) —
// migrating a legacy plaintext store off disk only makes sense once its
// replacement is durable.
func MigrateLegacyStores(ctx context.Context, dataDir string, dst xkmssdk.StorageBackend) error {
	if dst == nil {
		return &NilDestinationError{}
	}
	for _, dir := range legacyCandidates(dataDir) {
		if err := migrateOne(ctx, dir, dst); err != nil {
			return err
		}
	}
	return nil
}

// legacyCandidates returns the legacy store directories to consult, in
// priority order.
func legacyCandidates(dataDir string) []string {
	var out []string
	if dataDir != "" {
		out = append(out, filepath.Join(dataDir, sshSubdir))
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		out = append(out, filepath.Join(home, legacyHomeDir, sshSubdir))
	}
	return out
}

// migrateOne imports dir's entries into dst and renames dir away, if dir
// exists and is a directory. A missing dir is not an error — see
// MigrateLegacyStores's idempotency contract.
func migrateOne(ctx context.Context, dir string, dst xkmssdk.StorageBackend) error {
	info, statErr := os.Stat(dir)
	if statErr != nil {
		if os.IsNotExist(statErr) {
			return nil
		}
		return &MigrationError{Dir: dir, Op: "stat", Err: statErr}
	}
	if !info.IsDir() {
		return nil
	}

	src, err := xkmssdk.StorageOpenEngine(xkmssdk.StorageEngineConfig{Kind: xkmssdk.StorageEngineFile, Path: dir})
	if err != nil {
		return &MigrationError{Dir: dir, Op: "open", Err: err}
	}

	scanErr := src.Scan(ctx, "", func(key string, value []byte) error {
		_, putErr := dst.PutIfAbsent(ctx, key, value)
		return putErr
	})
	closeErr := src.Close()
	if scanErr != nil {
		return &MigrationError{Dir: dir, Op: "scan", Err: scanErr}
	}
	if closeErr != nil {
		return &MigrationError{Dir: dir, Op: "close", Err: closeErr}
	}

	if err := os.Rename(dir, dir+backupSuffix); err != nil {
		return &MigrationError{Dir: dir, Op: "rename", Err: err}
	}
	return nil
}
