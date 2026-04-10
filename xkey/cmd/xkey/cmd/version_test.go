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
	"bytes"
	"strings"
	"testing"
)

func TestVersionCmd(t *testing.T) {
	// Test via root command to properly route output
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"version"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("version command failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"xkey",
		"xKey (go-xkms)",
		"Version:",
		"Git Commit:",
		"Built:",
		"Go Version:",
		"OS/Arch:",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Version output missing %q", expected)
		}
	}
}

func TestVersionVariables(t *testing.T) {
	// Test default values (set at build time)
	tests := []struct {
		name     string
		variable string
		expected string
	}{
		{
			name:     "version default",
			variable: Version,
			expected: "dev",
		},
		{
			name:     "commit default",
			variable: Commit,
			expected: "none",
		},
		{
			name:     "date default",
			variable: Date,
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

func TestGetVersionInfo(t *testing.T) {
	info := GetVersionInfo()

	if !strings.Contains(info, "xkey") {
		t.Error("GetVersionInfo() should contain 'xkey'")
	}
	if !strings.Contains(info, Version) {
		t.Error("GetVersionInfo() should contain version")
	}
	if !strings.Contains(info, Commit) {
		t.Error("GetVersionInfo() should contain commit")
	}
	if !strings.Contains(info, Date) {
		t.Error("GetVersionInfo() should contain date")
	}
}
