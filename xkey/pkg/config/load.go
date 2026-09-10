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
	"reflect"
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
			// Neither file found: the valid first-run state. The defaults
			// and the environment still come through viper, so an
			// XKEY_ variable applies, and is validated, with no file.
			return unmarshalAndValidate(v)
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
			// Neither file found: defaults and environment through viper.
			return unmarshalAndValidate(v)
		}
	}

	return unmarshalAndValidate(v)
}

// newViperInstance creates a configured viper instance with defaults and
// environment variable binding.
func newViperInstance() *viper.Viper {
	v := viper.New()
	v.SetConfigType("yaml")

	// Bind environment variables with the XKEY_ prefix.
	// XKEY_LOG_LEVEL maps to log.level, XKEY_BACKEND_DEFAULT maps to
	// backend.default, etc.
	v.SetEnvPrefix(envPrefix)
	v.AutomaticEnv()
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))

	// Register every leaf key with its default and its environment binding,
	// so that environment variables and partial YAML files merge correctly.
	registerConfigKeys(v, DefaultConfig())

	return v
}

// registerConfigKeys walks cfg and registers each leaf key on v with the
// field's value as the key's default.
//
// Registering leaves rather than whole sections is what makes the environment
// reachable. AutomaticEnv only consults the environment for keys viper already
// knows, and a section registered as one opaque struct default teaches viper
// the section's name and nothing below it, so XKEY_XKMSD_ADDRESS was never
// looked up (#140). A leaf default also keeps the merge deterministic: viper
// assembles its settings from a flat key set, and a struct default sitting
// beside a nested key for the same section is resolved in map order.
//
// Every registered key reads XKEY_<KEY>. A map or a list of objects
// (backends.local, backends.remote, backends.defaults, fido2.extensions)
// cannot be expressed by one variable, so a variable set for one of them
// fails the load with ErrConfigLoadFailed instead of being ignored.
func registerConfigKeys(v *viper.Viper, cfg *Config) {
	walkConfigKeys(reflect.ValueOf(cfg).Elem(), "", func(key string, value reflect.Value) {
		v.SetDefault(key, value.Interface())
	})
}

// walkConfigKeys calls visit for every leaf field under value, with the key
// built from the mapstructure tags joined by dots. Nested structs, embedded
// or named, are descended; a nil pointer to a struct is descended through its
// type with a zero value so its keys are still registered.
func walkConfigKeys(value reflect.Value, prefix string, visit func(key string, value reflect.Value)) {
	valueType := value.Type()
	for i := range valueType.NumField() {
		field := valueType.Field(i)
		if !field.IsExported() {
			continue
		}
		name := configKeyName(field)
		if name == "" {
			continue
		}
		key := name
		if prefix != "" {
			key = prefix + "." + name
		}
		fieldValue := value.Field(i)
		if fieldValue.Kind() == reflect.Pointer && fieldValue.Type().Elem().Kind() == reflect.Struct {
			if fieldValue.IsNil() {
				fieldValue = reflect.New(fieldValue.Type().Elem())
			}
			fieldValue = fieldValue.Elem()
		}
		if fieldValue.Kind() == reflect.Struct {
			walkConfigKeys(fieldValue, key, visit)
			continue
		}
		visit(key, fieldValue)
	}
}

// configKeyName returns the key a struct field is decoded from: its
// mapstructure tag without options, or "" for a field tagged "-".
func configKeyName(field reflect.StructField) string {
	tag, ok := field.Tag.Lookup("mapstructure")
	if !ok {
		return strings.ToLower(field.Name)
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	if name == "" {
		return strings.ToLower(field.Name)
	}
	return name
}

// unmarshalAndValidate decodes the viper state onto a DefaultConfig-initialised
// Config and validates it.
//
// Decoding onto the defaults rather than a zero struct is what gives a partial
// section leaf-key merge semantics. setViperDefaults registers each section as
// one opaque default value, so as soon as a file names a section, that section's
// default is out of the picture and every key the file omits would otherwise
// land on its Go zero value — false for the policy Require* gates, 0 for
// pin_max_attempts (#114). Decoding onto the defaults means an omitted key
// keeps its default while an explicit value, including an explicit false or
// zero, still wins.
func unmarshalAndValidate(v *viper.Viper) (*Config, error) {
	cfg := DefaultConfig()
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
