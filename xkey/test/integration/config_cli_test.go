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

//go:build integration && linux

// Package xkey provides integration tests for the "xkey config" command
// group (init, path, show), exercised against the compiled CLI binary with
// an isolated HOME/XDG_CONFIG_HOME so the host user's real configuration is
// never touched.
package xkey

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// setupIsolatedConfigHome creates a temporary directory and points HOME and
// XDG_CONFIG_HOME at it. "xkey config init"/"xkey config path" resolve
// their file location via os.UserConfigDir()/os.UserHomeDir() (see
// pkg/config/load.go ConfigDir), not the XKEY_HOME override used by most
// other commands, so isolating HOME/XDG_CONFIG_HOME is required to keep
// these tests hermetic.
func setupIsolatedConfigHome(t *testing.T) string {
	t.Helper()

	dir := SetupCleanEnvironment(t)
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", "")
	return dir
}

// expectedConfigPath returns the path "xkey config init"/"xkey config path"
// resolve to under an isolated HOME with XDG_CONFIG_HOME unset:
// $HOME/.config/xkey/xkey.yaml.
func expectedConfigPath(home string) string {
	return filepath.Join(home, ".config", "xkey", "xkey.yaml")
}

// ---------------------------------------------------------------------------
// config init
// ---------------------------------------------------------------------------

// TestConfigCLI_Init_Success verifies that "config init" creates a default
// configuration file at the expected XDG path.
func TestConfigCLI_Init_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedConfigHome(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "config", "init")

	if !strings.Contains(stdout, "Created configuration file") {
		t.Errorf("Expected 'Created configuration file' in output, got: %s", stdout)
	}

	cfgPath := expectedConfigPath(home)
	info, err := os.Stat(cfgPath)
	if err != nil {
		t.Fatalf("Expected config file at %s, got error: %v", cfgPath, err)
	}
	if info.IsDir() {
		t.Fatalf("Expected %s to be a file, got a directory", cfgPath)
	}

	data, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatalf("Failed to read created config file: %v", err)
	}
	if len(data) == 0 {
		t.Error("Expected non-empty config file content")
	}
}

// TestConfigCLI_Init_AlreadyExists_Fails verifies that re-running
// "config init" without --force fails once a config file exists, and that
// --force allows overwriting it.
func TestConfigCLI_Init_AlreadyExists_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedConfigHome(t)

	RunXKeyExpectSuccess(t, binary, "", "config", "init")

	errOutput := RunXKeyExpectFailure(t, binary, "", "config", "init")
	if !strings.Contains(errOutput, "already exists") {
		t.Errorf("Expected 'already exists' in error output, got: %s", errOutput)
	}

	// --force is the documented escape hatch; confirm it actually works so
	// the error path above isn't masking a permanently stuck state.
	stdout := RunXKeyExpectSuccess(t, binary, "", "config", "init", "--force")
	if !strings.Contains(stdout, "Created configuration file") {
		t.Errorf("Expected --force re-init to succeed, got: %s", stdout)
	}

	cfgPath := expectedConfigPath(home)
	if _, err := os.Stat(cfgPath); err != nil {
		t.Fatalf("Expected config file to still exist at %s: %v", cfgPath, err)
	}
}

// ---------------------------------------------------------------------------
// config path
// ---------------------------------------------------------------------------

// TestConfigCLI_Path_Success verifies that "config path" lists the search
// paths and correctly reports whether a config file exists at each one.
func TestConfigCLI_Path_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedConfigHome(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "config", "path")
	if !strings.Contains(stdout, "Configuration search paths") {
		t.Errorf("Expected 'Configuration search paths' in output, got: %s", stdout)
	}
	if !strings.Contains(stdout, "No configuration file currently loaded") {
		t.Errorf("Expected 'No configuration file currently loaded' before init, got: %s", stdout)
	}

	RunXKeyExpectSuccess(t, binary, "", "config", "init")

	stdout2 := RunXKeyExpectSuccess(t, binary, "", "config", "path")
	cfgPath := expectedConfigPath(home)
	if !strings.Contains(stdout2, cfgPath) {
		t.Errorf("Expected search paths to include %s, got: %s", cfgPath, stdout2)
	}
	if !strings.Contains(stdout2, "(exists)") {
		t.Errorf("Expected '(exists)' marker after config init, got: %s", stdout2)
	}
	if !strings.Contains(stdout2, "Currently using: "+cfgPath) {
		t.Errorf("Expected 'Currently using: %s', got: %s", cfgPath, stdout2)
	}
}

// TestConfigCLI_Path_NonexistentConfigFlag_Fails verifies that pointing the
// global --config flag at a nonexistent file fails during startup
// configuration loading, before any subcommand runs.
func TestConfigCLI_Path_NonexistentConfigFlag_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedConfigHome(t)

	missing := filepath.Join(home, "does-not-exist.yaml")
	errOutput := RunXKeyExpectFailure(t, binary, "", "--config", missing, "config", "path")

	if !strings.Contains(errOutput, "not found") {
		t.Errorf("Expected 'not found' in error output, got: %s", errOutput)
	}
}

// ---------------------------------------------------------------------------
// config show
// ---------------------------------------------------------------------------

// TestConfigCLI_Show_Success verifies that "config show" prints the
// effective configuration as YAML, including well-known default sections.
func TestConfigCLI_Show_Success(t *testing.T) {
	binary := getOrBuildBinary(t)
	setupIsolatedConfigHome(t)

	stdout := RunXKeyExpectSuccess(t, binary, "", "config", "show")

	if !strings.Contains(stdout, "backend:") {
		t.Errorf("Expected YAML output to contain 'backend:', got: %s", stdout)
	}
	if !strings.Contains(stdout, "log:") {
		t.Errorf("Expected YAML output to contain 'log:', got: %s", stdout)
	}
}

// TestConfigCLI_Show_CorruptConfigFile_Fails verifies that "config show"
// fails when the resolved configuration file contains invalid YAML.
//
// Note: "config show" loads its configuration through the resolved xKey
// home directory (XKEY_HOME, or ~/.xkey/ by default -- see
// cmd/xkey/cmd/root.go initConfig -> xkeyconfig.LoadFromHome), which is a
// *different* file than the one "config init"/"config path" manage via the
// XDG config directory. See the final report for more on this
// inconsistency.
func TestConfigCLI_Show_CorruptConfigFile_Fails(t *testing.T) {
	binary := getOrBuildBinary(t)
	home := setupIsolatedConfigHome(t)

	xkeyHome := filepath.Join(home, ".xkey")
	if err := os.MkdirAll(xkeyHome, 0700); err != nil {
		t.Fatalf("Failed to create xkey home dir: %v", err)
	}
	t.Setenv("XKEY_HOME", xkeyHome)

	corrupt := []byte("backend: [this is not: valid: yaml: -\n")
	if err := os.WriteFile(filepath.Join(xkeyHome, "config.yaml"), corrupt, 0600); err != nil {
		t.Fatalf("Failed to write corrupt config file: %v", err)
	}

	errOutput := RunXKeyExpectFailure(t, binary, "", "config", "show")
	if !strings.Contains(errOutput, "failed to load") {
		t.Errorf("Expected 'failed to load' in error output, got: %s", errOutput)
	}
}
