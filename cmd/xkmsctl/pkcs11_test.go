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
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCS11Cmd_Help(t *testing.T) {
	// Capture stdout
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	// Reset root command for testing
	rootCmd.SetArgs([]string{"pkcs11", "--help"})
	err := rootCmd.Execute()

	// Restore stdout
	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	assert.NoError(t, err)
	assert.Contains(t, output, "PKCS#11 token management")
	assert.Contains(t, output, "probe")
	assert.Contains(t, output, "register")
	assert.Contains(t, output, "list-modules")
	assert.Contains(t, output, "list-tokens")
	assert.Contains(t, output, "init-token")
	assert.Contains(t, output, "connect")
	assert.Contains(t, output, "disconnect")
}

func TestPKCS11ProbeCmd(t *testing.T) {
	// Reset root command for testing
	rootCmd.SetArgs([]string{"pkcs11", "probe"})
	err := rootCmd.Execute()
	// Should not error even if no modules found
	assert.NoError(t, err)
}

func TestPKCS11ListModulesCmd(t *testing.T) {
	// Reset root command for testing
	rootCmd.SetArgs([]string{"pkcs11", "list-modules"})
	err := rootCmd.Execute()
	// Should not error even if no modules registered
	assert.NoError(t, err)
}

func TestPKCS11ListTokensCmd(t *testing.T) {
	// Reset root command for testing
	rootCmd.SetArgs([]string{"pkcs11", "list-tokens"})
	err := rootCmd.Execute()
	// Should not error even if no tokens found
	assert.NoError(t, err)
}

func TestPKCS11RegisterCmd_MissingModule(t *testing.T) {
	// Override exitFunc to capture exit call
	exitCalled := false
	exitCode := 0
	oldExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = oldExitFunc }()

	// Reset root command for testing
	rootCmd.SetArgs([]string{"pkcs11", "register"})
	_ = rootCmd.Execute()

	assert.True(t, exitCalled)
	assert.Equal(t, 1, exitCode)
}

func TestPKCS11InitTokenCmd_MissingArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"MissingLabel", []string{"pkcs11", "init-token", "--so-pin", "123", "--user-pin", "456"}},
		{"MissingSOPIN", []string{"pkcs11", "init-token", "--label", "test", "--user-pin", "456"}},
		{"MissingUserPIN", []string{"pkcs11", "init-token", "--label", "test", "--so-pin", "123"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exitCalled := false
			exitCode := 0
			oldExitFunc := exitFunc
			exitFunc = func(code int) {
				exitCalled = true
				exitCode = code
			}
			defer func() { exitFunc = oldExitFunc }()

			rootCmd.SetArgs(tt.args)
			_ = rootCmd.Execute()

			assert.True(t, exitCalled)
			assert.Equal(t, 1, exitCode)
		})
	}
}

func TestPKCS11ConnectCmd_MissingPIN(t *testing.T) {
	exitCalled := false
	exitCode := 0
	oldExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = oldExitFunc }()

	rootCmd.SetArgs([]string{"pkcs11", "connect", "--module-id", "test"})
	_ = rootCmd.Execute()

	assert.True(t, exitCalled)
	assert.Equal(t, 1, exitCode)
}

func TestPKCS11DisconnectCmd_MissingModuleID(t *testing.T) {
	exitCalled := false
	exitCode := 0
	oldExitFunc := exitFunc
	exitFunc = func(code int) {
		exitCalled = true
		exitCode = code
	}
	defer func() { exitFunc = oldExitFunc }()

	rootCmd.SetArgs([]string{"pkcs11", "disconnect"})
	_ = rootCmd.Execute()

	assert.True(t, exitCalled)
	assert.Equal(t, 1, exitCode)
}

func TestPKCS11Cmd_JSONOutput(t *testing.T) {
	// Test JSON output format for probe command
	oldStdout := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	rootCmd.SetArgs([]string{"pkcs11", "probe", "-o", "json"})
	err := rootCmd.Execute()

	_ = w.Close()
	os.Stdout = oldStdout

	var buf bytes.Buffer
	_, _ = buf.ReadFrom(r)
	output := buf.String()

	require.NoError(t, err)
	// Output should be valid JSON (either empty array or array of modules)
	output = strings.TrimSpace(output)
	assert.True(t, strings.HasPrefix(output, "[") || output == "null",
		"Expected JSON array output, got: %s", output)
}

func TestPKCS11Cmd_Subcommands_Exist(t *testing.T) {
	// Verify all expected subcommands are registered
	subcommands := []string{
		"probe",
		"register",
		"list-modules",
		"list-tokens",
		"init-token",
		"connect",
		"disconnect",
	}

	for _, name := range subcommands {
		found := false
		for _, cmd := range pkcs11Cmd.Commands() {
			if cmd.Name() == name {
				found = true
				break
			}
		}
		assert.True(t, found, "Subcommand %s should be registered", name)
	}
}
