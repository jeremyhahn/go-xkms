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
	"strings"
	"sync/atomic"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

const (
	configDirName  = "xkey"
	configFileName = "xkey.yaml"
	envPrefix      = "XKEY"
	systemConfDir  = "/etc/xkey"
)

// configDirOverride allows tests to redirect the config directory to a
// temporary path. When non-empty, ConfigDir returns this value instead of
// the XDG default. Use SetConfigDir / ResetConfigDir to manage the override.
var configDirOverride atomic.Pointer[string]

// SetConfigDir overrides the config directory returned by ConfigDir.
// This is intended for testing and should be paired with ResetConfigDir.
func SetConfigDir(dir string) {
	configDirOverride.Store(&dir)
}

// ResetConfigDir clears any override set by SetConfigDir, restoring the
// default XDG-based directory resolution.
func ResetConfigDir() {
	configDirOverride.Store(nil)
}

// ConfigDir returns the XDG config directory for xkey: ~/.config/xkey/
// If SetConfigDir has been called, the override is returned instead.
func ConfigDir() string {
	if ptr := configDirOverride.Load(); ptr != nil && *ptr != "" {
		return *ptr
	}
	base, err := os.UserConfigDir()
	if err != nil {
		home, homeErr := os.UserHomeDir()
		if homeErr != nil {
			return filepath.Join(".config", configDirName)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, configDirName)
}

// ConfigPath returns the full path to the config file: ~/.config/xkey/xkey.yaml
func ConfigPath() string {
	return filepath.Join(ConfigDir(), configFileName)
}

// SystemConfigPath returns the system-wide config path: /etc/xkey/xkey.yaml
func SystemConfigPath() string {
	return filepath.Join(systemConfDir, configFileName)
}

// Load loads the config from the default paths with environment variable overlay.
// Search order: ConfigPath(), SystemConfigPath(), then defaults.
// Environment prefix: XKEY_ (e.g., XKEY_LOG_LEVEL=debug)
func Load() (*Config, error) {
	v := newViperInstance()

	v.SetConfigFile(ConfigPath())
	if readErr := v.ReadInConfig(); readErr != nil {
		if !isConfigNotFoundError(readErr) {
			return nil, errors.Join(ErrConfigLoadFailed, readErr)
		}
		// User config not found; try system config.
		v.SetConfigFile(SystemConfigPath())
		if sysErr := v.ReadInConfig(); sysErr != nil {
			if !isConfigNotFoundError(sysErr) {
				return nil, errors.Join(ErrConfigLoadFailed, sysErr)
			}
			// Neither file found; return defaults (valid first-run state).
			cfg := DefaultConfig()
			if err := cfg.Validate(); err != nil {
				return nil, errors.Join(ErrConfigInvalid, err)
			}
			return cfg, nil
		}
	}

	return unmarshalAndValidate(v)
}

// LoadFromPath loads config from a specific file path.
func LoadFromPath(path string) (*Config, error) {
	v := newViperInstance()

	v.SetConfigFile(path)
	if err := v.ReadInConfig(); err != nil {
		if isConfigNotFoundError(err) {
			return nil, errors.Join(ErrConfigNotFound, err)
		}
		return nil, errors.Join(ErrConfigLoadFailed, err)
	}

	return unmarshalAndValidate(v)
}

// LoadFromHome loads config using the resolved xhome.Home directory.
// It checks Home.ConfigPath() first, then SystemConfigPath(), then defaults.
func LoadFromHome(h *xhome.Home) (*Config, error) {
	v := newViperInstance()

	v.SetConfigFile(h.ConfigPath())
	if readErr := v.ReadInConfig(); readErr != nil {
		if !isConfigNotFoundError(readErr) {
			return nil, errors.Join(ErrConfigLoadFailed, readErr)
		}
		// Home config not found; try system config.
		v.SetConfigFile(SystemConfigPath())
		if sysErr := v.ReadInConfig(); sysErr != nil {
			if !isConfigNotFoundError(sysErr) {
				return nil, errors.Join(ErrConfigLoadFailed, sysErr)
			}
			// Neither file found; return defaults.
			cfg := DefaultConfig()
			if err := cfg.Validate(); err != nil {
				return nil, errors.Join(ErrConfigInvalid, err)
			}
			return cfg, nil
		}
	}

	return unmarshalAndValidate(v)
}

// newViperInstance creates a configured viper instance with defaults and
// environment variable binding.
func newViperInstance() *viper.Viper {
	v := viper.New()
	v.SetConfigType("yaml")

	// Set defaults from DefaultConfig so that missing keys resolve to
	// sensible values after unmarshal.
	defaults := DefaultConfig()
	setViperDefaults(v, defaults)

	// Bind environment variables with the XKEY_ prefix.
	// XKEY_LOG_LEVEL maps to log.level, XKEY_BACKEND_DEFAULT maps to
	// backend.default, etc.
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	return v
}

// setViperDefaults registers default values for all top-level config keys
// so that environment variables and partial YAML files merge correctly.
func setViperDefaults(v *viper.Viper, defaults *Config) {
	v.SetDefault("policy", defaults.Policy)
	v.SetDefault("backend", defaults.Backend)
	v.SetDefault("fido2", defaults.FIDO2)
	v.SetDefault("oath", defaults.OATH)
	v.SetDefault("phone", defaults.Phone)
	v.SetDefault("xkmsd", defaults.XKMSD)
	v.SetDefault("tpm", defaults.TPM)
	v.SetDefault("password_protection", defaults.PasswordProtection)
	v.SetDefault("trust", defaults.Trust)
	v.SetDefault("attestation", defaults.Attestation)
	v.SetDefault("log", defaults.Log)
	v.SetDefault("gui", defaults.GUI)
	v.SetDefault("state", defaults.State)
}

// unmarshalAndValidate decodes the viper state into a Config and validates it.
func unmarshalAndValidate(v *viper.Viper) (*Config, error) {
	cfg := &Config{}
	if err := v.Unmarshal(cfg); err != nil {
		return nil, errors.Join(ErrConfigLoadFailed, err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, errors.Join(ErrConfigInvalid, err)
	}
	return cfg, nil
}

// isConfigNotFoundError returns true when the error indicates the config file
// was not found on disk. This covers both viper.ConfigFileNotFoundError and
// the underlying os.ErrNotExist used by os.Stat / os.Open.
func isConfigNotFoundError(err error) bool {
	var viperNotFound viper.ConfigFileNotFoundError
	if errors.As(err, &viperNotFound) {
		return true
	}
	return os.IsNotExist(err) || errors.Is(err, os.ErrNotExist)
}
