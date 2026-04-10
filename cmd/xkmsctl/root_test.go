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
	"bytes"
	"testing"
)

func TestRootCmd_Initialization(t *testing.T) {
	// Verify rootCmd is initialized
	if rootCmd == nil {
		t.Fatal("rootCmd should be initialized")
	}

	if rootCmd.Use != "xkmsctl" {
		t.Errorf("rootCmd.Use = %v, want xkmsctl", rootCmd.Use)
	}

	if rootCmd.Short == "" {
		t.Error("rootCmd.Short should not be empty")
	}

	if rootCmd.Long == "" {
		t.Error("rootCmd.Long should not be empty")
	}
}

func TestRootCmd_HasSubcommands(t *testing.T) {
	// Verify expected subcommands are registered
	subcommands := rootCmd.Commands()

	expectedCmds := []string{"version", "backends", "key", "cert", "tls", "fido2", "admin", "user"}
	foundCmds := make(map[string]bool)

	for _, cmd := range subcommands {
		foundCmds[cmd.Use] = true
	}

	for _, expected := range expectedCmds {
		if !foundCmds[expected] {
			t.Errorf("expected subcommand %q not found", expected)
		}
	}
}

func TestRootCmd_PersistentFlags(t *testing.T) {
	// Verify persistent flags are set up correctly
	flags := rootCmd.PersistentFlags()

	flagTests := []struct {
		name        string
		expectedSet bool
	}{
		{"config", true},
		{"backend", true},
		{"key-dir", true},
		{"output", true},
		{"verbose", true},
		{"protocol", true},
		{"server", true},
		{"tls-cert", true},
		{"tls-key", true},
		{"tls-ca", true},
		{"token", true},
	}

	for _, tt := range flagTests {
		t.Run(tt.name, func(t *testing.T) {
			flag := flags.Lookup(tt.name)
			if tt.expectedSet && flag == nil {
				t.Errorf("expected flag %q to exist", tt.name)
			}
		})
	}
}

func TestRootCmd_TLSInsecureFlagRemoved(t *testing.T) {
	// Verify the --tls-insecure flag has been removed for security hardening.
	flags := rootCmd.PersistentFlags()
	flag := flags.Lookup("tls-insecure")
	if flag != nil {
		t.Error("tls-insecure flag should not exist; insecure TLS has been removed")
	}
}

func TestGetConfig(t *testing.T) {
	// Test getConfig returns a valid config
	cfg := getConfig()
	if cfg == nil {
		t.Fatal("getConfig() should return non-nil config")
	}
}

func TestPrintVerbose_WhenVerboseEnabled(t *testing.T) {
	// Save original config state
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	// Enable verbose mode
	globalConfig.Verbose = true

	// printVerbose prints to stderr, so we just verify it doesn't panic
	printVerbose("test message with %s", "args")
}

func TestPrintVerbose_WhenVerboseDisabled(t *testing.T) {
	// Save original config state
	originalConfig := *globalConfig
	defer func() { *globalConfig = originalConfig }()

	// Disable verbose mode
	globalConfig.Verbose = false

	// printVerbose should do nothing when verbose is disabled
	printVerbose("test message with %s", "args")
}

func TestExecute_RootCommand(t *testing.T) {
	// Reset the command before testing
	rootCmd.SetArgs([]string{"--help"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	// Execute should work without error for help
	err := rootCmd.Execute()
	if err != nil {
		t.Errorf("Execute() returned error for help: %v", err)
	}
}

func TestRootCmd_SilenceUsage(t *testing.T) {
	if !rootCmd.SilenceUsage {
		t.Error("rootCmd.SilenceUsage should be true")
	}
}

func TestRootCmd_SilenceErrors(t *testing.T) {
	if !rootCmd.SilenceErrors {
		t.Error("rootCmd.SilenceErrors should be true")
	}
}

func TestGlobalConfig_Initialized(t *testing.T) {
	if globalConfig == nil {
		t.Fatal("globalConfig should be initialized")
	}

	// Verify defaults are set
	if globalConfig.OutputFormat == "" {
		t.Error("globalConfig.OutputFormat should have a default value")
	}

	if globalConfig.Backend == "" {
		t.Error("globalConfig.Backend should have a default value")
	}

	if globalConfig.KeyDir == "" {
		t.Error("globalConfig.KeyDir should have a default value")
	}
}
