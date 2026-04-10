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

func TestRootCmd_Help(t *testing.T) {
	buf := new(bytes.Buffer)
	RootCmd.SetOut(buf)
	RootCmd.SetErr(buf)
	RootCmd.SetArgs([]string{"--help"})

	err := RootCmd.Execute()
	if err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	output := buf.String()
	expectedStrings := []string{
		"xKey",
		"FIDO2/WebAuthn",
		"OATH TOTP/HOTP",
		"PIV",
		"xkey [command]",
	}

	for _, expected := range expectedStrings {
		if !strings.Contains(output, expected) {
			t.Errorf("Help output missing %q", expected)
		}
	}
}

func TestRootCmd_SubcommandRegistration(t *testing.T) {
	// Verify subcommands are registered
	subcommands := map[string]bool{
		"fido2":   false,
		"oath":    false,
		"config":  false,
		"version": false,
	}

	for _, cmd := range RootCmd.Commands() {
		if _, ok := subcommands[cmd.Name()]; ok {
			subcommands[cmd.Name()] = true
		}
	}

	for name, found := range subcommands {
		if !found {
			t.Errorf("Subcommand %q not registered with root command", name)
		}
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"debug", "DEBUG"},
		{"DEBUG", "DEBUG"},
		{"info", "INFO"},
		{"INFO", "INFO"},
		{"warn", "WARN"},
		{"warning", "WARN"},
		{"error", "ERROR"},
		{"ERROR", "ERROR"},
		{"invalid", "INFO"}, // Default to INFO
		{"", "INFO"},        // Empty defaults to INFO
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			level := parseLogLevel(tt.input)
			if level.String() != tt.expected {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, level.String(), tt.expected)
			}
		})
	}
}

func TestConfigError(t *testing.T) {
	tests := []struct {
		name     string
		err      *ConfigError
		wantPart string
	}{
		{
			name: "with path",
			err: &ConfigError{
				Operation: "read",
				Path:      "/etc/xkey/config.yaml",
				Err:       nil,
			},
			wantPart: "/etc/xkey/config.yaml",
		},
		{
			name: "without path",
			err: &ConfigError{
				Operation: "init",
				Path:      "",
				Err:       nil,
			},
			wantPart: "init",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			errStr := tt.err.Error()
			if !strings.Contains(errStr, tt.wantPart) {
				t.Errorf("ConfigError.Error() = %q, want to contain %q", errStr, tt.wantPart)
			}
		})
	}
}

func TestGetConfig_ReturnsNilBeforeInit(t *testing.T) {
	// Before initConfig runs, GetConfig should return whatever loadedConfig is.
	// Save and restore to avoid test pollution.
	saved := loadedConfig
	defer func() { loadedConfig = saved }()

	loadedConfig = nil
	cfg := GetConfig()
	if cfg != nil {
		t.Error("GetConfig() should return nil before initConfig()")
	}
}
