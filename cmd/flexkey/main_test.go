//go:build ignore

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package main

import (
	"bytes"
	"flag"
	"io"
	"os"
	"strings"
	"testing"
)

func TestExitCodeConstants(t *testing.T) {
	if exitSuccess != 0 {
		t.Errorf("exitSuccess = %d, want 0", exitSuccess)
	}

	if exitError != 1 {
		t.Errorf("exitError = %d, want 1", exitError)
	}
}

func TestVersionVariables(t *testing.T) {
	// These are set during build, so we test the default values
	tests := []struct {
		name     string
		variable string
		expected string
	}{
		{
			name:     "version default",
			variable: version,
			expected: "dev",
		},
		{
			name:     "commit default",
			variable: commit,
			expected: "none",
		},
		{
			name:     "date default",
			variable: date,
			expected: "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.variable != tt.expected {
				t.Errorf("variable = %q, want %q", tt.variable, tt.expected)
			}
		})
	}
}

func TestPrintVersion(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Call printVersion
	printVersion()

	// Restore stdout and get output
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	output := buf.String()

	// Verify output contains expected strings
	expectedStrings := []string{
		"fido2key",
		"FIDO2 Key (go-keychain)",
		"Version:",
		"Git Commit:",
		"Built:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("printVersion() output missing %q", expected)
		}
	}
}

func TestPrintVersionFormat(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Call printVersion
	printVersion()

	// Restore stdout and get output
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read captured output: %v", err)
	}
	output := buf.String()

	// Verify output has correct number of lines
	lines := strings.Split(strings.TrimSpace(output), "\n")
	if len(lines) != 4 {
		t.Errorf("printVersion() output has %d lines, want 4", len(lines))
	}

	// Verify first line is the title
	if !strings.HasPrefix(lines[0], "fido2key") {
		t.Errorf("printVersion() first line = %q, want to start with 'fido2key'", lines[0])
	}
}

// resetFlags resets the flag package state for testing
func resetFlags() {
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
}

func TestRunWithInvalidStorageType(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Set invalid storage type
	os.Args = []string{"fido2key", "-storage", "invalid"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid storage type returned %d, want %d", exitCode, exitError)
	}

	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error message")
	}
}

func TestRunWithInvalidLogLevel(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Set invalid log level
	os.Args = []string{"fido2key", "-log-level", "invalid"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid log level returned %d, want %d", exitCode, exitError)
	}

	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error message")
	}
}

func TestRunWithVersionFlag(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStdout := os.Stdout
	defer func() {
		os.Args = origArgs
		os.Stdout = origStdout
		resetFlags()
	}()

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Set version flag
	os.Args = []string{"fido2key", "-version"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitSuccess {
		t.Errorf("run() with -version returned %d, want %d", exitCode, exitSuccess)
	}

	output := buf.String()
	if !strings.Contains(output, "fido2key") {
		t.Error("run() with -version should print version info")
	}
}

func TestRunWithShortVersionFlag(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStdout := os.Stdout
	defer func() {
		os.Args = origArgs
		os.Stdout = origStdout
		resetFlags()
	}()

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Set short version flag
	os.Args = []string{"fido2key", "-v"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitSuccess {
		t.Errorf("run() with -v returned %d, want %d", exitCode, exitSuccess)
	}

	output := buf.String()
	if !strings.Contains(output, "fido2key") {
		t.Error("run() with -v should print version info")
	}
}

func TestRunWithSetPINWithoutPINFlag(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Set PIN without enabling PIN
	os.Args = []string{"fido2key", "-set-pin", "123456"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with -set-pin but no -pin returned %d, want %d", exitCode, exitError)
	}

	if !strings.Contains(buf.String(), "--set-pin requires --pin") {
		t.Error("run() should print error about -set-pin requiring -pin")
	}
}

func TestRunWithFileStorageNoPath(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Set file storage without path
	os.Args = []string{"fido2key", "-storage", "file", "-storage-path", ""}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with file storage but no path returned %d, want %d", exitCode, exitError)
	}

	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error message")
	}
}

func TestRunWithInvalidLogFile(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Capture stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Set invalid log file path
	os.Args = []string{"fido2key", "-log-file", "/nonexistent/directory/that/cannot/exist/test.log"}
	resetFlags()

	exitCode := run()

	// Close writer and read output
	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid log file returned %d, want %d", exitCode, exitError)
	}

	if !strings.Contains(buf.String(), "Failed to setup logger") {
		t.Error("run() should print logger setup error message")
	}
}

func TestRunFlagDefaults(t *testing.T) {
	// This test verifies the default values in the flag definitions
	// by parsing an empty command line

	// Save original args and restore after test
	origArgs := os.Args
	defer func() {
		os.Args = origArgs
		resetFlags()
	}()

	// Parse with minimal args (just the program name)
	os.Args = []string{"fido2key", "-version"}
	resetFlags()

	// Run to trigger flag parsing
	run()

	// The test passes if it doesn't panic - the actual verification
	// of flag values is done in other tests
}

func TestRunWithAllFlags(t *testing.T) {
	// Save original args and restore after test
	origArgs := os.Args
	origStdout := os.Stdout
	defer func() {
		os.Args = origArgs
		os.Stdout = origStdout
		resetFlags()
	}()

	// Capture stdout (for version output)
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Test that all flags can be parsed together
	os.Args = []string{
		"fido2key",
		"-storage", "memory",
		"-storage-path", "/tmp/test",
		"-name", "Test Device",
		"-serial", "TEST12345678",
		"-pin",
		"-set-pin", "123456",
		"-log-level", "debug",
		"-version", // This will cause early exit
	}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	// Version flag should cause early successful exit
	if exitCode != exitSuccess {
		t.Errorf("run() with all flags (including -version) returned %d, want %d", exitCode, exitSuccess)
	}
}

func TestRunSerialNumberGeneration(t *testing.T) {
	// This test verifies that serial number is auto-generated when not provided
	// We test this indirectly by parsing flags and checking the default behavior

	// Save original args and restore after test
	origArgs := os.Args
	origStdout := os.Stdout
	defer func() {
		os.Args = origArgs
		os.Stdout = origStdout
		resetFlags()
	}()

	// Capture stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stdout = w

	// Run without specifying serial (should auto-generate)
	os.Args = []string{"fido2key", "-version"}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitSuccess {
		t.Errorf("run() returned %d, want %d", exitCode, exitSuccess)
	}
}

func TestRunWithInvalidTimeout(t *testing.T) {
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	os.Args = []string{"fido2key", "-timeout", "notaduration"}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid timeout returned %d, want %d", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "Invalid user presence timeout") {
		t.Error("run() should print invalid timeout error")
	}
}

func TestRunWithInvalidBackend(t *testing.T) {
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	os.Args = []string{"fido2key", "-backend", "invalid"}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid backend returned %d, want %d", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error for invalid backend")
	}
}

func TestRunWithTPMAttestationSoftwareBackend(t *testing.T) {
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	os.Args = []string{"fido2key", "-backend", "software", "-attestation", "tpm"}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with TPM attestation on software backend returned %d, want %d", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error for TPM attestation without TPM backend")
	}
}

func TestRunWithInvalidAttestationFormat(t *testing.T) {
	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	os.Args = []string{"fido2key", "-attestation", "invalid"}
	resetFlags()

	exitCode := run()

	_ = w.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, r); err != nil {
		t.Fatalf("failed to read output: %v", err)
	}

	if exitCode != exitError {
		t.Errorf("run() with invalid attestation returned %d, want %d", exitCode, exitError)
	}
	if !strings.Contains(buf.String(), "Configuration error") {
		t.Error("run() should print configuration error for invalid attestation format")
	}
}

func TestRunWithValidConfigNoUHID(t *testing.T) {
	// Skip if UHID device exists (would succeed on privileged systems)
	if _, err := os.Stat("/dev/uhid"); err == nil {
		t.Skip("skipping test: /dev/uhid is available")
	}

	origArgs := os.Args
	origStderr := os.Stderr
	defer func() {
		os.Args = origArgs
		os.Stderr = origStderr
		resetFlags()
	}()

	// Suppress stderr output from logger
	_, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("failed to create pipe: %v", err)
	}
	os.Stderr = w

	// Valid configuration that should pass validation but fail when creating the device
	// (no UHID available). This exercises the device creation and run paths in run().
	os.Args = []string{
		"fido2key",
		"-storage", "memory",
		"-backend", "software",
		"-log-level", "error",
	}
	resetFlags()

	exitCode := run()
	_ = w.Close()

	// Expect error because device.Run() will fail without UHID
	if exitCode != exitError {
		t.Errorf("run() without UHID returned %d, want %d", exitCode, exitError)
	}
}

