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
	"os"
	"path/filepath"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// resolveDataDir resolves the xKey data directory shared by every command
// group that persists state (barrier, PIN, shares, ...). It is the ONE
// resolution chain in the CLI; command groups must delegate here instead
// of copying it, because a drifted private copy is exactly how the `pin`
// group ended up reading a phantom store (issue #295).
//
// Priority: the command group's own --data-dir flag value > XKEY_DATA_DIR
// environment variable > viper config `data_dir` > the xhome data
// directory (~/.xkey/data by default), created if it does not exist.
func resolveDataDir(flagValue string) (string, error) {
	if dir, ok := dataDirOverride(flagValue); ok {
		return dir, nil
	}

	home, err := xhome.Resolve()
	if err != nil {
		return "", err
	}
	return home.EnsureDataDir()
}

// resolveDataDirExisting resolves the same chain as resolveDataDir but
// never creates a directory. Read-only commands use it so that inspecting
// state cannot manufacture an empty data directory: a fresh install and a
// misresolved path must stay distinguishable. An explicit flag, env or
// config override is returned as given — whether its store exists is the
// caller's question — while the xhome fallback only resolves to a home
// that already exists, returning xhome.ErrHomeNotResolved otherwise.
func resolveDataDirExisting(flagValue string) (string, error) {
	if dir, ok := dataDirOverride(flagValue); ok {
		return dir, nil
	}

	home, err := xhome.ResolveExisting()
	if err != nil {
		return "", err
	}
	return home.DataDir(), nil
}

// dataDirOverride returns the explicitly configured data directory, if
// any: the command group's --data-dir flag, then XKEY_DATA_DIR, then the
// viper config `data_dir` key.
func dataDirOverride(flagValue string) (string, bool) {
	if flagValue != "" {
		return filepath.Clean(flagValue), true
	}

	if envDir := os.Getenv("XKEY_DATA_DIR"); envDir != "" {
		return filepath.Clean(envDir), true
	}

	if viperDir := viper.GetString("data_dir"); viperDir != "" {
		return filepath.Clean(viperDir), true
	}

	return "", false
}

// featureDataDir resolves the shared data directory through the ONE chain
// above and returns the named feature's subdirectory beneath it, e.g.
// <dataDir>/trust. Command groups that keep their state under a fixed
// feature segment (extension, trust, auth, agent, ...) delegate here so
// the segment is the only thing they spell; the data directory itself is
// never hand-built from $HOME. The data directory is created if absent;
// the feature subdirectory is left to the store that owns it.
//
// Delegating here is a deliberate behaviour change for groups that once
// resolved ~/.xkey/data/<feature> directly (issue #381): they now honour
// XKEY_HOME, portable (.xkey-home marker) mode, XKEY_DATA_DIR and the
// config `data_dir` key exactly as pin and barrier do.
func featureDataDir(feature string) (string, error) {
	dataDir, err := resolveDataDir("")
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, feature), nil
}

// featureDataDirExisting is the non-creating counterpart of featureDataDir
// for read-only commands: it resolves through resolveDataDirExisting, so
// inspecting a feature's state can never manufacture the data directory,
// and fails with xhome.ErrHomeNotResolved when no xKey home exists.
func featureDataDirExisting(feature string) (string, error) {
	dataDir, err := resolveDataDirExisting("")
	if err != nil {
		return "", err
	}
	return filepath.Join(dataDir, feature), nil
}
