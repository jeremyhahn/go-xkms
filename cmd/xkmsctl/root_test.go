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
	if got := openTestPIN(t, globalConfig.PKCS11PIN); got != "s3cr3t" {
		t.Errorf("sealed PIN = %q, want %q", got, "s3cr3t")
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
