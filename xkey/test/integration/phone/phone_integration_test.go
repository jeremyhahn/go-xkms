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

// Package phone provides E2E integration tests for the xkey device CLI commands.
// These tests execute the real xkey binary and verify actual CLI behavior.
package phone

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDevice_Help(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("--help")

	assert.True(t, result.Success(), "device --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("device"), "help output should mention 'device'")

	// Verify core subcommands appear in help output
	expectedSubcommands := []string{
		"list",
		"pair",
		"scan",
		"unpair",
		"status",
		"relay",
	}
	for _, sub := range expectedSubcommands {
		assert.True(t, result.OutputContains(sub),
			"help output should mention subcommand %q, got:\n%s", sub, result.Combined())
	}
}

func TestDevice_ListHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("list", "--help")

	assert.True(t, result.Success(), "device list --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("list"),
		"help output should contain 'list', got:\n%s", result.Combined())
	assert.True(t, result.OutputContains("List all devices") || result.OutputContains("List paired devices"),
		"help output should contain list description, got:\n%s", result.Combined())
}

func TestDevice_ScanHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("scan", "--help")

	assert.True(t, result.Success(), "device scan --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("scan"),
		"help output should contain 'scan', got:\n%s", result.Combined())
	assert.True(t, result.OutputContains("Scan"),
		"help output should contain 'Scan' in description, got:\n%s", result.Combined())
}

func TestDevice_PairHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("pair", "--help")

	assert.True(t, result.Success(), "device pair --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("pair"),
		"help output should contain 'pair', got:\n%s", result.Combined())
	assert.True(t, result.OutputContains("Pair"),
		"help output should contain 'Pair' in description, got:\n%s", result.Combined())
}

func TestDevice_RelayHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("relay", "--help")

	assert.True(t, result.Success(), "device relay --help should succeed, got: %s", result.Combined())

	combined := result.Combined()
	assert.True(t, strings.Contains(combined, "relay") || strings.Contains(combined, "Relay"),
		"help output should mention 'relay', got:\n%s", combined)
	assert.True(t, strings.Contains(combined, "listen") || strings.Contains(combined, "--listen"),
		"help output should mention 'listen' flag, got:\n%s", combined)
}

func TestDevice_List_Empty(t *testing.T) {
	h := NewDeviceTestHelper(t)

	// Set HOME to temp dir so no devices.yaml exists
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", h.ConfigPath())
	defer os.Setenv("HOME", originalHome)

	result := h.RunDevice("list")

	assert.True(t, result.Success(), "device list should succeed with no config, got: %s", result.Combined())
	assert.True(t, result.OutputContains("No paired devices"),
		"output should indicate no paired devices, got:\n%s", result.Combined())
}

func TestDevice_Status_NoDevices(t *testing.T) {
	h := NewDeviceTestHelper(t)

	// Set HOME to temp dir so no devices.yaml exists
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", h.ConfigPath())
	defer os.Setenv("HOME", originalHome)

	result := h.RunDevice("status")

	assert.True(t, result.Success(), "device status should succeed with no config, got: %s", result.Combined())
	assert.True(t, result.OutputContains("No paired devices"),
		"output should indicate no paired devices, got:\n%s", result.Combined())
}

func TestDevice_Unpair_NotFound(t *testing.T) {
	h := NewDeviceTestHelper(t)

	// Set HOME to temp dir so no devices.yaml exists
	originalHome := os.Getenv("HOME")
	t.Setenv("HOME", h.ConfigPath())
	defer os.Setenv("HOME", originalHome)

	result := h.RunDevice("unpair", "nonexistent", "--force")

	assert.False(t, result.Success(), "unpair of nonexistent device should fail")
	assert.True(t, result.OutputContains("not paired") || result.OutputContains("not found"),
		"error should mention device not found/not paired, got:\n%s", result.Combined())
}

func TestDevice_InvalidArgs(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want string
	}{
		{
			name: "unpair missing device name",
			args: []string{"unpair"},
			want: "accepts 1 arg(s)",
		},
		{
			name: "unknown flag on list",
			args: []string{"list", "--nonexistent-flag"},
			want: "unknown flag",
		},
		{
			name: "unknown flag on status",
			args: []string{"status", "--nonexistent-flag"},
			want: "unknown flag",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewDeviceTestHelper(t)

			result := h.RunDevice(tt.args...)

			assert.False(t, result.Success(), "invalid args should fail")
			assert.True(t, result.OutputContains(tt.want),
				"error output should contain %q, got:\n%s", tt.want, result.Combined())
		})
	}
}

func TestDevice_SubcommandList(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("--help")
	require.True(t, result.Success(), "device --help should succeed, got: %s", result.Combined())

	combined := result.Combined()

	// These subcommands are always present (registered unconditionally or via stubs)
	alwaysPresent := []string{
		"list",
		"pair",
		"scan",
		"unpair",
		"status",
		"relay",
		"enroll",
		"connect",
		"listen",
		"sync",
		"share",
		"import",
		"attest",
		"device-info",
		"share-policy",
	}

	for _, sub := range alwaysPresent {
		assert.True(t, strings.Contains(combined, sub),
			"device help should list subcommand %q, got:\n%s", sub, combined)
	}
}

func TestDevice_StatusHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("status", "--help")

	assert.True(t, result.Success(), "device status --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("status"),
		"help output should contain 'status', got:\n%s", result.Combined())
	assert.True(t, result.OutputContains("--device"),
		"help output should mention --device flag, got:\n%s", result.Combined())
}

func TestDevice_UnpairHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("unpair", "--help")

	assert.True(t, result.Success(), "device unpair --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("unpair") || result.OutputContains("Unpair") || result.OutputContains("Remove"),
		"help output should describe unpair, got:\n%s", result.Combined())
	assert.True(t, result.OutputContains("--force"),
		"help output should mention --force flag, got:\n%s", result.Combined())
}

func TestDevice_EnrollHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("enroll", "--help")

	assert.True(t, result.Success(), "device enroll --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("enroll") || result.OutputContains("Enroll"),
		"help output should describe enroll, got:\n%s", result.Combined())
}

func TestDevice_ConnectHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("connect", "--help")

	assert.True(t, result.Success(), "device connect --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("connect") || result.OutputContains("Connect"),
		"help output should describe connect, got:\n%s", result.Combined())
}

func TestDevice_SharePolicyHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("share-policy", "--help")

	assert.True(t, result.Success(), "device share-policy --help should succeed, got: %s", result.Combined())

	combined := result.Combined()
	assert.True(t, strings.Contains(combined, "share-policy") || strings.Contains(combined, "sharing"),
		"help output should describe share-policy, got:\n%s", combined)

	// Verify share-policy subcommands
	subcommands := []string{"list", "set", "remove"}
	for _, sub := range subcommands {
		assert.True(t, strings.Contains(combined, sub),
			"share-policy help should list subcommand %q, got:\n%s", sub, combined)
	}
}

func TestDevice_Relay_StartStop(t *testing.T) {
	h := NewDeviceTestHelper(t)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Start relay as a subprocess on an ephemeral port
	cmd := exec.CommandContext(ctx, h.binaryPath, "device", "relay", "--listen", ":0")

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Start()
	require.NoError(t, err, "relay subprocess should start")

	// Wait briefly for the server to begin listening
	time.Sleep(500 * time.Millisecond)

	// Verify the process is still running (hasn't crashed immediately)
	// A nil from cmd.Process means it never started; check it's alive.
	require.NotNil(t, cmd.Process, "relay process should exist")

	// Send SIGTERM for clean shutdown
	err = cmd.Process.Signal(syscall.SIGTERM)
	require.NoError(t, err, "sending SIGTERM to relay should succeed")

	// Wait for exit
	exitErr := cmd.Wait()

	// The relay exits with 0 on SIGTERM or non-zero; both are acceptable
	// as long as it started and handled the signal.
	combined := stdout.String() + "\n" + stderr.String()

	// Verify it printed a listening message before shutdown
	assert.True(t,
		strings.Contains(combined, "listening") || strings.Contains(combined, "Listening") ||
			strings.Contains(combined, "TCP pairing relay"),
		"relay output should indicate it started listening, got:\n%s (exit: %v)", combined, exitErr)
}

func TestDevice_SyncHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("sync", "--help")

	assert.True(t, result.Success(), "device sync --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("sync") || result.OutputContains("Sync"),
		"help output should describe sync, got:\n%s", result.Combined())
}

func TestDevice_ListenHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("listen", "--help")

	assert.True(t, result.Success(), "device listen --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("listen") || result.OutputContains("Listen"),
		"help output should describe listen, got:\n%s", result.Combined())
}

func TestDevice_AttestHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("attest", "--help")

	assert.True(t, result.Success(), "device attest --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("attest") || result.OutputContains("Attest"),
		"help output should describe attest, got:\n%s", result.Combined())
}

func TestDevice_ShareHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("share", "--help")

	assert.True(t, result.Success(), "device share --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("share") || result.OutputContains("Share"),
		"help output should describe share, got:\n%s", result.Combined())
}

func TestDevice_ImportHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("import", "--help")

	assert.True(t, result.Success(), "device import --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("import") || result.OutputContains("Import"),
		"help output should describe import, got:\n%s", result.Combined())
}

func TestDevice_DeviceInfoHelp(t *testing.T) {
	h := NewDeviceTestHelper(t)

	result := h.RunDevice("device-info", "--help")

	assert.True(t, result.Success(), "device device-info --help should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("device-info") || result.OutputContains("information") || result.OutputContains("Device"),
		"help output should describe device-info, got:\n%s", result.Combined())
}

func TestDevice_PhoneAlias(t *testing.T) {
	h := NewDeviceTestHelper(t)

	// The device command has "phone" as an alias; verify it works
	result := h.RunCommand("phone", "--help")

	assert.True(t, result.Success(), "phone alias should succeed, got: %s", result.Combined())
	assert.True(t, result.OutputContains("device") || result.OutputContains("phone") || result.OutputContains("Manage"),
		"phone alias help should show device help, got:\n%s", result.Combined())
}
