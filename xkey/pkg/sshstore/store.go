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
