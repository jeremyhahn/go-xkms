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
		{"transport", true},
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

func TestRootCmd_TransportFlagIsCanonical(t *testing.T) {
	// --transport is the only flag that selects the SDK transport; the
	// deprecated --protocol/-P alias was removed outright.
	flags := rootCmd.PersistentFlags()

	transportFlag := flags.Lookup("transport")
	if transportFlag == nil {
		t.Fatal("--transport flag must exist")
	}
	if transportFlag.Deprecated != "" {
		t.Errorf("--transport flag must not be deprecated, got Deprecated=%q", transportFlag.Deprecated)
	}

	if protocolFlag := flags.Lookup("protocol"); protocolFlag != nil {
		t.Error("--protocol flag must not exist; the deprecated alias was removed")
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

// TestRootCmd_PKCS11PINFlagSealsSecret proves --pkcs11-pin is sealed into
// globalConfig.PKCS11PIN as a *secure.Secret by rootCmd's PersistentPreRunE
// before any subcommand runs.
func TestRootCmd_PKCS11PINFlagSealsSecret(t *testing.T) {
	originalPIN := globalConfig.PKCS11PIN
	originalFlag := pkcs11PINFlag
	defer func() {
		globalConfig.PKCS11PIN = originalPIN
		pkcs11PINFlag = originalFlag
	}()

	rootCmd.SetArgs([]string{"--pkcs11-pin", "s3cr3t", "version"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if globalConfig.PKCS11PIN == nil {
		t.Fatal("expected --pkcs11-pin to seal a non-nil secret")
	}
	sealed, err := globalConfig.PKCS11PIN.Open()
	if err != nil {
		t.Fatalf("Open() failed: %v", err)
	}
	defer sealed.Destroy()
	if string(sealed.Bytes()) != "s3cr3t" {
		t.Errorf("sealed PIN = %q, want %q", string(sealed.Bytes()), "s3cr3t")
	}
}

// TestRootCmd_PKCS11PINFlagAbsentLeavesNil proves that omitting --pkcs11-pin
// leaves globalConfig.PKCS11PIN nil rather than sealing an empty secret.
func TestRootCmd_PKCS11PINFlagAbsentLeavesNil(t *testing.T) {
	originalPIN := globalConfig.PKCS11PIN
	originalFlag := pkcs11PINFlag
	defer func() {
		globalConfig.PKCS11PIN = originalPIN
		pkcs11PINFlag = originalFlag
	}()

	pkcs11PINFlag = ""
	globalConfig.PKCS11PIN = nil

	rootCmd.SetArgs([]string{"version"})
	buf := new(bytes.Buffer)
	rootCmd.SetOut(buf)
	rootCmd.SetErr(buf)

	if err := rootCmd.Execute(); err != nil {
		t.Fatalf("Execute() returned error: %v", err)
	}

	if globalConfig.PKCS11PIN != nil {
		t.Error("expected globalConfig.PKCS11PIN to remain nil when --pkcs11-pin is not set")
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
