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

package config

import (
	"errors"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Save writes the config to the default config path atomically.
func Save(cfg *Config) error {
	return SaveToPath(cfg, ConfigPath())
}

// SaveToPath writes the config to the specified path atomically.
// It uses a temporary file + rename pattern for crash safety. The parent
// directory is created with 0700 permissions if it does not exist. The
// config file is written with 0600 permissions.
func SaveToPath(cfg *Config, path string) error {
	if cfg == nil {
		return errors.Join(ErrConfigSaveFailed, errors.New("config is nil"))
	}

	if err := cfg.Validate(); err != nil {
		return errors.Join(ErrConfigInvalid, err)
	}

	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return errors.Join(ErrConfigDirCreate, err)
	}

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return errors.Join(ErrConfigSaveFailed, err)
	}

	// Write to a temporary file in the same directory so that the rename
	// is guaranteed to be atomic on POSIX filesystems (same mount point).
	tmpFile, err := os.CreateTemp(dir, ".xkey-config-*.yaml.tmp")
	if err != nil {
		return errors.Join(ErrConfigSaveFailed, err)
	}
	tmpPath := tmpFile.Name()

	// Clean up the temp file on any failure path.
	success := false
	defer func() {
		if !success {
			os.Remove(tmpPath)
		}
	}()

	if _, writeErr := tmpFile.Write(data); writeErr != nil {
		tmpFile.Close()
		return errors.Join(ErrConfigSaveFailed, writeErr)
	}

	// Sync to disk before closing to ensure durability.
	if syncErr := tmpFile.Sync(); syncErr != nil {
		tmpFile.Close()
		return errors.Join(ErrConfigSaveFailed, syncErr)
	}

	if closeErr := tmpFile.Close(); closeErr != nil {
		return errors.Join(ErrConfigSaveFailed, closeErr)
	}

	// Set restrictive permissions before the rename so the file is never
	// world-readable, even briefly.
	if chmodErr := os.Chmod(tmpPath, 0600); chmodErr != nil {
		return errors.Join(ErrConfigSaveFailed, chmodErr)
	}

	// Atomic rename replaces the target file in a single syscall.
	if renameErr := os.Rename(tmpPath, path); renameErr != nil {
		return errors.Join(ErrConfigSaveFailed, renameErr)
	}

	success = true
	return nil
}
