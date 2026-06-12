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
	"errors"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	xkeyconfig "github.com/jeremyhahn/go-xkms/xkey/pkg/config"
)

// Configuration command errors.
var (
	// ErrConfigFileExists indicates the config file already exists and --force was not specified.
	ErrConfigFileExists = errors.New("config: file already exists, use --force to overwrite")

	// ErrConfigFileWrite indicates the config file could not be written.
	ErrConfigFileWrite = errors.New("config: failed to write configuration file")

	// ErrConfigHomeDirResolve indicates the home directory could not be resolved.
	ErrConfigHomeDirResolve = errors.New("config: failed to resolve home directory")
)

var (
	// configInitForce forces overwriting existing config file.
	configInitForce bool
)

// configCmd is the parent command for configuration management.
var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Manage xKey configuration",
	Long: `Manage the xKey configuration.

xKey reads configuration from the following sources (in order of precedence):
  1. Command-line flags
  2. Environment variables (prefixed with XKEY_)
  3. Configuration file (~/.config/xkey/xkey.yaml or /etc/xkey/xkey.yaml)

Subcommands:
  show    Display the current effective configuration
  init    Create a default configuration file
  path    Show configuration file search paths`,
}

// configShowCmd displays the current configuration.
var configShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Display current configuration",
	Long: `Display the current effective configuration from all sources.

Shows the unified configuration struct as loaded by the config package,
which merges the configuration file, environment variables, and defaults.
The output is formatted as YAML for readability.`,
	RunE: runConfigShow,
}

// configInitCmd creates a default configuration file.
var configInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Create default configuration file",
	Long: `Create a default configuration file at ~/.config/xkey/xkey.yaml.

The generated file contains the default configuration matching the
unified config struct layout. Existing files will not be overwritten
unless the --force flag is specified.

Example:
  xkey config init
  xkey config init --force`,
	RunE: runConfigInit,
}

// configPathCmd shows configuration file locations.
var configPathCmd = &cobra.Command{
	Use:   "path",
	Short: "Show configuration file locations",
	Long: `Show all paths where configuration files are searched.

xKey searches for configuration files in the following order:
  1. Path specified via --config flag
  2. ~/.config/xkey/xkey.yaml
  3. /etc/xkey/xkey.yaml

The currently loaded configuration file (if any) is indicated.`,
	RunE: runConfigPath,
}

func init() {
	// Add config subcommands
	configCmd.AddCommand(configShowCmd)
	configCmd.AddCommand(configInitCmd)
	configCmd.AddCommand(configPathCmd)

	// Add flags to init command
	configInitCmd.Flags().BoolVar(&configInitForce, "force", false,
		"overwrite existing configuration file")

	// Add config command to root
	RootCmd.AddCommand(configCmd)
}

// runConfigShow executes the config show command.
func runConfigShow(cmd *cobra.Command, args []string) error {
	cfg := loadedConfig
	if cfg == nil {
		cfg = xkeyconfig.DefaultConfig()
	}

	// Show config file path
	configPath := xkeyconfig.ConfigPath()
	if cfgFile != "" {
		configPath = cfgFile
	}

	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf("# Configuration loaded from: %s\n", configPath)
	} else {
		fmt.Println("# No configuration file loaded (using defaults and environment)")
	}
	fmt.Println()

	yamlData, err := yaml.Marshal(cfg)
	if err != nil {
		return &ConfigShowError{Err: err}
	}

	fmt.Print(string(yamlData))
	return nil
}

// runConfigInit executes the config init command.
func runConfigInit(cmd *cobra.Command, args []string) error {
	configPath := xkeyconfig.ConfigPath()

	// Check if file exists
	if _, err := os.Stat(configPath); err == nil {
		if !configInitForce {
			fmt.Printf("Configuration file already exists: %s\n", configPath)
			fmt.Println("Use --force to overwrite.")
			return ErrConfigFileExists
		}
		fmt.Printf("Overwriting existing configuration file: %s\n", configPath)
	}

	// Write the default config using the config package for consistency
	// with the struct layout.
	cfg := xkeyconfig.DefaultConfig()
	if err := xkeyconfig.SaveToPath(cfg, configPath); err != nil {
		return &ConfigInitError{
			Path: configPath,
			Err:  err,
		}
	}

	fmt.Printf("Created configuration file: %s\n", configPath)
	return nil
}

// runConfigPath executes the config path command.
func runConfigPath(cmd *cobra.Command, args []string) error {
	// Define search paths using the config package
	paths := []string{
		xkeyconfig.ConfigPath(),
		xkeyconfig.SystemConfigPath(),
	}

	// If a config file was specified via flag, show it first
	if cfgFile != "" {
		fmt.Println("Configuration search paths:")
		fmt.Println()
		fmt.Printf("  %s (from --config flag)\n", cfgFile)
	} else {
		fmt.Println("Configuration search paths:")
		fmt.Println()
	}

	// Show standard search paths
	for _, path := range paths {
		// Check if file exists
		if _, err := os.Stat(path); err == nil {
			fmt.Printf("  %s (exists)\n", path)
		} else {
			fmt.Printf("  %s\n", path)
		}
	}

	fmt.Println()
	if cfgFile != "" {
		fmt.Printf("Currently using: %s\n", cfgFile)
	} else if _, err := os.Stat(xkeyconfig.ConfigPath()); err == nil {
		fmt.Printf("Currently using: %s\n", xkeyconfig.ConfigPath())
	} else if _, err := os.Stat(xkeyconfig.SystemConfigPath()); err == nil {
		fmt.Printf("Currently using: %s\n", xkeyconfig.SystemConfigPath())
	} else {
		fmt.Println("No configuration file currently loaded.")
	}

	return nil
}

// ConfigShowError represents an error displaying configuration.
type ConfigShowError struct {
	Err error
}

// Error returns the error message.
func (e *ConfigShowError) Error() string {
	return fmt.Sprintf("config show failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigShowError) Unwrap() error {
	return e.Err
}

// ConfigInitError represents an error initializing configuration.
type ConfigInitError struct {
	Path string
	Err  error
}

// Error returns the error message.
func (e *ConfigInitError) Error() string {
	if e.Path != "" {
		return fmt.Sprintf("config init failed for %s: %v", e.Path, e.Err)
	}
	return fmt.Sprintf("config init failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigInitError) Unwrap() error {
	return e.Err
}

// ConfigPathError represents an error showing configuration paths.
type ConfigPathError struct {
	Err error
}

// Error returns the error message.
func (e *ConfigPathError) Error() string {
	return fmt.Sprintf("config path failed: %v", e.Err)
}

// Unwrap returns the underlying error.
func (e *ConfigPathError) Unwrap() error {
	return e.Err
}
