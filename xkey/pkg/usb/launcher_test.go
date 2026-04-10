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

package usb

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGenerateLauncher_NotEmpty(t *testing.T) {
	script := GenerateLauncher()
	assert.NotEmpty(t, script)
}

func TestGenerateLauncher_Shebang(t *testing.T) {
	script := GenerateLauncher()
	assert.True(t, strings.HasPrefix(script, "#!/bin/sh"),
		"launcher should start with POSIX shebang")
}

func TestGenerateLauncher_ArchDetection(t *testing.T) {
	script := GenerateLauncher()

	architectures := []struct {
		pattern string
		binary  string
	}{
		{"x86_64", "xkey-linux-amd64"},
		{"amd64", "xkey-linux-amd64"},
		{"aarch64", "xkey-linux-arm64"},
		{"arm64", "xkey-linux-arm64"},
		{"armv7l", "xkey-linux-arm"},
		{"armv6l", "xkey-linux-arm"},
	}

	for _, arch := range architectures {
		t.Run(arch.pattern, func(t *testing.T) {
			assert.Contains(t, script, arch.pattern,
				"launcher should detect %s architecture", arch.pattern)
			assert.Contains(t, script, arch.binary,
				"launcher should reference %s binary", arch.binary)
		})
	}
}

func TestGenerateLauncher_SetsXKEYHOME(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, "XKEY_HOME",
		"launcher should set XKEY_HOME environment variable")
	assert.Contains(t, script, `export XKEY_HOME`,
		"launcher should export XKEY_HOME")
}

func TestGenerateLauncher_HandlesUnsupportedArch(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, "unsupported architecture",
		"launcher should handle unsupported architectures")
	assert.Contains(t, script, "exit 1",
		"launcher should exit with error for unsupported architectures")
}

func TestGenerateLauncher_HandlesMissingBinary(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, "binary not found",
		"launcher should handle missing binary case")
}

func TestGenerateLauncher_UsesExec(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, "exec ",
		"launcher should use exec to replace shell process")
}

func TestGenerateLauncher_PassesArguments(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, `"$@"`,
		"launcher should pass through command-line arguments")
}

func TestGenerateLauncher_SetE(t *testing.T) {
	script := GenerateLauncher()
	assert.Contains(t, script, "set -e",
		"launcher should use set -e for error handling")
}

func TestGenerateLauncher_Idempotent(t *testing.T) {
	script1 := GenerateLauncher()
	script2 := GenerateLauncher()
	assert.Equal(t, script1, script2,
		"GenerateLauncher should be deterministic")
}

func TestGenerateReadme_NotEmpty(t *testing.T) {
	readme := GenerateReadme()
	assert.NotEmpty(t, readme)
}

func TestGenerateReadme_ContainsPartitionInfo(t *testing.T) {
	readme := GenerateReadme()
	assert.Contains(t, readme, "FAT32")
	assert.Contains(t, readme, "LUKS2")
	assert.Contains(t, readme, "XKEY")
	assert.Contains(t, readme, "xkey-data")
}

func TestGenerateReadme_ContainsUsageInstructions(t *testing.T) {
	readme := GenerateReadme()
	assert.Contains(t, readme, "xkey.sh")
	assert.Contains(t, readme, ".xkey-home")
	assert.Contains(t, readme, "README.txt")
}

func TestGenerateReadme_ContainsSecurityNotes(t *testing.T) {
	readme := GenerateReadme()
	assert.Contains(t, readme, "Security")
	assert.Contains(t, readme, "AES-256")
	assert.Contains(t, readme, "passphrase")
}

func TestGenerateReadme_Idempotent(t *testing.T) {
	readme1 := GenerateReadme()
	readme2 := GenerateReadme()
	assert.Equal(t, readme1, readme2,
		"GenerateReadme should be deterministic")
}
