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

package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"

	"github.com/jeremyhahn/go-xkms/pkg/acme/client/service"
)

// Configuration file search paths in priority order.
var configSearchPaths = []string{
	"~/.trusted-acme-client.yaml",
	"~/.config/trusted-acme-client/config.yaml",
	"/etc/trusted-acme/client-config.yaml",
}

// Global configuration variables populated from flags, config file, and env vars.
var (
	logLevel string
)

// ErrInvalidLogLevel indicates the log level is not valid.
type ErrInvalidLogLevel struct {
	Level string
}

func (e ErrInvalidLogLevel) Error() string {
	return "invalid log level: " + e.Level + " (must be one of: debug, info, warn, error)"
}

// ErrConfigRead indicates a failure reading the configuration file.
type ErrConfigRead struct {
	Path string
	Err  error
}

func (e ErrConfigRead) Error() string {
	return "failed to read config file " + e.Path + ": " + e.Err.Error()
}

func (e ErrConfigRead) Unwrap() error {
	return e.Err
}

// setDefaults configures default values for all configuration settings.
func setDefaults() {
	defaults := service.DefaultConfig()

	viper.SetDefault("storage.backend", defaults.Storage.Backend)
	viper.SetDefault("storage.options.path", defaults.Storage.Options["path"])

	viper.SetDefault("xkms.backend", defaults.XKMS.Backend)
	viper.SetDefault("xkms.options.path", defaults.XKMS.Options["path"])

	viper.SetDefault("logging.level", defaults.Logging.Level)
	viper.SetDefault("logging.format", defaults.Logging.Format)
	viper.SetDefault("logging.output", defaults.Logging.Output)

	viper.SetDefault("challenge.http01.port", defaults.Challenge.HTTP01.Port)
	viper.SetDefault("challenge.dns01.ttl", defaults.Challenge.DNS01.TTL)
}

// expandPath expands the tilde in file paths to the user's home directory.
func expandPath(path string) string {
	if !strings.HasPrefix(path, "~/") {
		return path
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	return filepath.Join(home, path[2:])
}

// findConfigFile searches for a configuration file in the standard locations.
func findConfigFile() string {
	for _, searchPath := range configSearchPaths {
		expanded := expandPath(searchPath)
		if _, err := os.Stat(expanded); err == nil {
			return expanded
		}
	}
	return ""
}

// loadConfigFile loads configuration from the specified file or searches default locations.
func loadConfigFile(configPath string) error {
	if configPath != "" {
		viper.SetConfigFile(configPath)
	} else {
		configFile := findConfigFile()
		if configFile != "" {
			viper.SetConfigFile(configFile)
		} else {
			return nil
		}
	}

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); ok {
			return nil
		}
		return ErrConfigRead{Path: viper.ConfigFileUsed(), Err: err}
	}

	return nil
}

// isValidLogLevel checks if the given log level is valid.
func isValidLogLevel(level string) bool {
	validLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	return validLevels[level]
}

// validateConfiguration validates all configuration values.
func validateConfiguration() error {
	if !isValidLogLevel(logLevel) {
		return ErrInvalidLogLevel{Level: logLevel}
	}
	return nil
}

// initConfig initializes the viper configuration system.
func initConfig() error {
	setDefaults()

	viper.SetEnvPrefix("ACME_CLIENT")
	viper.SetEnvKeyReplacer(strings.NewReplacer("-", "_", ".", "_"))
	viper.AutomaticEnv()

	configPath := viper.GetString("config")
	if err := loadConfigFile(configPath); err != nil {
		return err
	}

	logLevel = viper.GetString("logging.level")

	if err := validateConfiguration(); err != nil {
		return err
	}

	return nil
}

// buildServiceConfig constructs a service.Config from the current viper state.
func buildServiceConfig() *service.Config {
	cfg := service.DefaultConfig()
	if err := viper.Unmarshal(cfg); err != nil {
		return cfg
	}
	if cfg.Accounts == nil {
		cfg.Accounts = make(map[string]*service.AccountConfig)
	}
	if cfg.Certificates == nil {
		cfg.Certificates = make(map[string]*service.CertificateSpec)
	}
	return cfg
}

// createService constructs a new Service from the current configuration.
func createService() (*service.Service, error) {
	cfg := buildServiceConfig()
	logger := service.InitLogger(cfg.Logging)
	return service.NewService(cfg, logger)
}
