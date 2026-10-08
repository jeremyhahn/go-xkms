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

	"github.com/jeremyhahn/go-xkms/sdk/go/fsutil"
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

	if err := fsutil.WriteFileAtomic(path, data, 0600); err != nil {
		return errors.Join(ErrConfigSaveFailed, err)
	}
	return nil
}
