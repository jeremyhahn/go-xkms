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

//go:build integration

// Package touch provides integration tests for the xkey touch and
// password type CLI commands. These tests execute the real xkey binary
// and verify actual CLI behavior.
package touch

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestTouchCLI_DaemonNotRunning verifies that touch fails gracefully when
// the daemon is not running (no socket file exists).
func TestTouchCLI_DaemonNotRunning(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunTouch()

	assert.False(t, result.Success(), "should fail when daemon not running")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon is not running: %s", result.Combined())
}

// TestTouchCLI_DaemonNotRunning_WithPassword verifies that touch --password
// fails gracefully when the daemon is not running.
func TestTouchCLI_DaemonNotRunning_WithPassword(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunTouch("--password", "MyPassword")

	assert.False(t, result.Success(), "should fail when daemon not running")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon is not running: %s", result.Combined())
}

// TestTouchCLI_PasswordType_DaemonNotRunning verifies that password type
// fails gracefully when the daemon is not running.
func TestTouchCLI_PasswordType_DaemonNotRunning(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunPasswordType("MyPassword")

	assert.False(t, result.Success(), "should fail when daemon not running")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon is not running: %s", result.Combined())
}

// TestTouchCLI_PasswordType_MissingArg verifies that password type without
// a name argument fails with a clear error.
func TestTouchCLI_PasswordType_MissingArg(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("password", "type")

	assert.False(t, result.Success(), "should fail without name arg")
	assert.True(t, result.OutputContains("specify") || result.OutputContains("required"),
		"should indicate name is required: %s", result.Combined())
}

// TestTouchCLI_HelpOutput verifies that touch --help displays expected info.
func TestTouchCLI_HelpOutput(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("touch", "--help")

	assert.True(t, result.Success(), "help should succeed: %s", result.Combined())
	assert.True(t, result.OutputContainsAll("touch", "--password", "--socket"),
		"help should show flags: %s", result.Combined())
}

// TestTouchCLI_PasswordTypeHelp verifies that password type --help displays
// expected info.
func TestTouchCLI_PasswordTypeHelp(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("password", "type", "--help")

	assert.True(t, result.Success(), "help should succeed: %s", result.Combined())
	assert.True(t, result.OutputContainsAll("type", "--socket", "keyboard"),
		"help should show flags: %s", result.Combined())
}

// TestTouchCLI_CommandAliases verifies that the emit alias for password type
// works correctly.
func TestTouchCLI_CommandAliases(t *testing.T) {
	helper := NewTouchTestHelper(t)

	// "password emit" should be an alias for "password type".
	result := helper.RunCommand("password", "emit", "--help")
	assert.True(t, result.Success(), "emit alias should work: %s", result.Combined())
}

// TestTouchCLI_InvalidSocketPath verifies that a non-existent socket path
// returns a daemon-not-running error, not a crash.
func TestTouchCLI_InvalidSocketPath(t *testing.T) {
	helper := NewTouchTestHelper(t)

	// Use a path that definitely does not have a daemon listening.
	result := helper.RunCommand("touch", "--socket", "/tmp/nonexistent-xkey-socket-12345.sock")

	assert.False(t, result.Success(), "should fail with invalid socket")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon not running: %s", result.Combined())
}

// TestTouchCLI_PasswordType_InvalidSocketPath verifies that password type
// with a non-existent socket path returns a daemon-not-running error.
func TestTouchCLI_PasswordType_InvalidSocketPath(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("password", "type", "SomePassword",
		"--socket", "/tmp/nonexistent-xkey-socket-67890.sock")

	assert.False(t, result.Success(), "should fail with invalid socket")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon not running: %s", result.Combined())
}

// TestTouchCLI_TouchHelpContainsDaemonInfo verifies that the touch help text
// mentions that the daemon must be running.
func TestTouchCLI_TouchHelpContainsDaemonInfo(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("touch", "--help")

	assert.True(t, result.Success(), "help should succeed: %s", result.Combined())
	assert.True(t, result.OutputContains("daemon"),
		"touch help should mention daemon: %s", result.Combined())
	assert.True(t, result.OutputContains("IPC") || result.OutputContains("ipc"),
		"touch help should mention IPC: %s", result.Combined())
}

// TestTouchCLI_PasswordTypeHelpContainsKeyboardInfo verifies that the
// password type help text mentions virtual keyboard functionality.
func TestTouchCLI_PasswordTypeHelpContainsKeyboardInfo(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("password", "type", "--help")

	assert.True(t, result.Success(), "help should succeed: %s", result.Combined())
	assert.True(t, result.OutputContains("keyboard"),
		"password type help should mention keyboard: %s", result.Combined())
	assert.True(t, result.OutputContains("daemon"),
		"password type help should mention daemon: %s", result.Combined())
}

// TestTouchCLI_TouchExitCode verifies that the exit code is non-zero when
// the daemon is not running.
func TestTouchCLI_TouchExitCode(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunTouch()

	assert.NotEqual(t, 0, result.ExitCode,
		"exit code should be non-zero when daemon is not running")
}

// TestTouchCLI_PasswordType_ExitCode verifies that the exit code is non-zero
// when the daemon is not running for password type.
func TestTouchCLI_PasswordType_ExitCode(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunPasswordType("TestPassword")

	assert.NotEqual(t, 0, result.ExitCode,
		"exit code should be non-zero when daemon is not running")
}

// TestTouchCLI_PasswordType_EmitAliasDaemonNotRunning verifies that the emit
// alias for password type also fails gracefully when the daemon is not running.
func TestTouchCLI_PasswordType_EmitAliasDaemonNotRunning(t *testing.T) {
	helper := NewTouchTestHelper(t)

	result := helper.RunCommand("password", "emit", "MyPassword",
		"--socket", helper.SocketPath())

	assert.False(t, result.Success(), "should fail when daemon not running")
	assert.True(t, result.OutputContains("daemon") || result.OutputContains("not running"),
		"should indicate daemon is not running: %s", result.Combined())
}

// TestTouchCLI_TouchWithPasswordFlag verifies that the touch --password flag
// appears in help and is accepted by the parser.
func TestTouchCLI_TouchWithPasswordFlag(t *testing.T) {
	helper := NewTouchTestHelper(t)

	// Verify that --password is accepted (even though daemon is not running,
	// the flag parsing should succeed before the IPC connection attempt).
	result := helper.RunTouch("--password", "SomeName")

	// The command should fail because the daemon is not running, but the error
	// should NOT be about unknown flags.
	assert.False(t, result.Success(), "should fail when daemon not running")
	assert.False(t, result.OutputContains("unknown flag"),
		"should not report unknown flag: %s", result.Combined())
}
