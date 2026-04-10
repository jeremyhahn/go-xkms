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
	"log/slog"
	"os"
	"path/filepath"
	"testing"
)

func TestHasFlag(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
		want bool
	}{
		{"flag present", []string{"--gui", "phone"}, "--gui", true},
		{"flag absent", []string{"phone", "pair"}, "--gui", false},
		{"empty args", []string{}, "--gui", false},
		{"no-gui present", []string{"--no-gui"}, "--no-gui", true},
		{"help short", []string{"-h"}, "-h", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasFlag(tt.args, tt.flag)
			if got != tt.want {
				t.Errorf("hasFlag(%v, %q) = %v, want %v", tt.args, tt.flag, got, tt.want)
			}
		})
	}
}

func TestHasSubcommand(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{"subcommand only", []string{"phone"}, true},
		{"subcommand with sub", []string{"phone", "pair"}, true},
		{"flags only", []string{"--gui"}, false},
		{"known flags only", []string{"--gui", "--no-gui", "--help", "-h"}, false},
		{"global flag with value", []string{"--log-level", "debug"}, false},
		{"global flag then subcommand", []string{"--log-level", "debug", "phone"}, true},
		{"multiple global flags then subcommand", []string{"--log-level", "debug", "--config", "/etc/xkey.yaml", "phone", "pair"}, true},
		{"unknown flag no value", []string{"--verbose"}, false},
		{"empty args", []string{}, false},
		{"flag with equals", []string{"--config=/etc/xkey.yaml"}, false},
		{"subcommand with flags", []string{"phone", "pair", "--trust-new-devices"}, true},
		{"version subcommand", []string{"version"}, true},
		{"oath totp generate", []string{"oath", "totp", "generate", "--account", "myservice"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasSubcommand(tt.args)
			if got != tt.want {
				t.Errorf("hasSubcommand(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}

func TestStripFlags(t *testing.T) {
	tests := []struct {
		name  string
		args  []string
		flags []string
		want  []string
	}{
		{
			"strip gui flags",
			[]string{"xkey", "--no-gui", "phone", "pair"},
			[]string{"--no-gui", "--gui"},
			[]string{"xkey", "phone", "pair"},
		},
		{
			"nothing to strip",
			[]string{"xkey", "phone", "pair"},
			[]string{"--no-gui", "--gui"},
			[]string{"xkey", "phone", "pair"},
		},
		{
			"strip all",
			[]string{"--gui"},
			[]string{"--gui"},
			[]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := stripFlags(tt.args, tt.flags...)
			if len(got) != len(tt.want) {
				t.Fatalf("stripFlags() returned %d items, want %d: %v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("stripFlags()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestExtractFlagValue(t *testing.T) {
	tests := []struct {
		name string
		args []string
		flag string
		want string
	}{
		{
			"space-separated value",
			[]string{"--log-level", "debug"},
			"--log-level",
			"debug",
		},
		{
			"equals-separated value",
			[]string{"--log-level=warn"},
			"--log-level",
			"warn",
		},
		{
			"flag not present",
			[]string{"--gui", "phone"},
			"--log-level",
			"",
		},
		{
			"empty args",
			[]string{},
			"--log-level",
			"",
		},
		{
			"flag at end without value",
			[]string{"--gui", "--log-level"},
			"--log-level",
			"",
		},
		{
			"multiple flags extract correct one",
			[]string{"--log-level", "debug", "--log-file", "/tmp/xkey.log"},
			"--log-file",
			"/tmp/xkey.log",
		},
		{
			"equals with empty value",
			[]string{"--log-file="},
			"--log-file",
			"",
		},
		{
			"equals with path value",
			[]string{"--log-file=/var/log/xkey.log"},
			"--log-file",
			"/var/log/xkey.log",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFlagValue(tt.args, tt.flag)
			if got != tt.want {
				t.Errorf("extractFlagValue(%v, %q) = %q, want %q", tt.args, tt.flag, got, tt.want)
			}
		})
	}
}

func TestParseLogLevel(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  slog.Level
	}{
		{"debug lowercase", "debug", slog.LevelDebug},
		{"debug uppercase", "DEBUG", slog.LevelDebug},
		{"debug mixed case", "Debug", slog.LevelDebug},
		{"info", "info", slog.LevelInfo},
		{"warn", "warn", slog.LevelWarn},
		{"warning", "warning", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"empty string defaults to info", "", slog.LevelInfo},
		{"unknown defaults to info", "trace", slog.LevelInfo},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLogLevel(tt.input)
			if got != tt.want {
				t.Errorf("parseLogLevel(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestInitGUILogging_Defaults(t *testing.T) {
	// With no flags, initGUILogging should succeed and configure info-level
	// logging to stderr without error.
	err := initGUILogging([]string{})
	if err != nil {
		t.Fatalf("initGUILogging with no flags: unexpected error: %v", err)
	}

	// Verify the logger is enabled at info level and not at debug level
	logger := slog.Default()
	if !logger.Enabled(nil, slog.LevelInfo) {
		t.Error("expected info level to be enabled with default settings")
	}
	if logger.Enabled(nil, slog.LevelDebug) {
		t.Error("expected debug level to be disabled with default settings")
	}
}

func TestInitGUILogging_DebugLevel(t *testing.T) {
	err := initGUILogging([]string{"--log-level", "debug"})
	if err != nil {
		t.Fatalf("initGUILogging with debug level: unexpected error: %v", err)
	}

	logger := slog.Default()
	if !logger.Enabled(nil, slog.LevelDebug) {
		t.Error("expected debug level to be enabled after --log-level debug")
	}
}

func TestInitGUILogging_LogFile(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "test.log")

	err := initGUILogging([]string{"--log-file", logPath, "--log-level", "warn"})
	if err != nil {
		t.Fatalf("initGUILogging with log file: unexpected error: %v", err)
	}

	// Write a log entry to confirm the file is being used
	slog.Warn("test log entry")

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file should exist after logging: %v", err)
	}
	if info.Size() == 0 {
		t.Error("log file should contain data after logging a warning")
	}
}

func TestInitGUILogging_LogFileEqualsStyle(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "eq.log")

	err := initGUILogging([]string{"--log-file=" + logPath})
	if err != nil {
		t.Fatalf("initGUILogging with --log-file=path: unexpected error: %v", err)
	}

	slog.Info("equals style test")

	info, err := os.Stat(logPath)
	if err != nil {
		t.Fatalf("log file should exist: %v", err)
	}
	if info.Size() == 0 {
		t.Error("log file should contain data")
	}
}

func TestInitGUILogging_InvalidPath(t *testing.T) {
	// A path under a non-existent directory should fail.
	err := initGUILogging([]string{"--log-file", "/no/such/directory/xkey.log"})
	if err == nil {
		t.Fatal("initGUILogging should return error for invalid log file path")
	}
}

func TestIsNativeMessagingInvocation(t *testing.T) {
	tests := []struct {
		name string
		args []string
		want bool
	}{
		{
			"chrome origin argument",
			[]string{"/usr/bin/xkey", "chrome-extension://ogbhdplieldlomhnokdapcopejmkelkl/"},
			true,
		},
		{
			"chrome origin with different id",
			[]string{"/usr/bin/xkey", "chrome-extension://abcdefghijklmnop/"},
			true,
		},
		{
			"normal subcommand",
			[]string{"/usr/bin/xkey", "extension", "host"},
			false,
		},
		{
			"no arguments",
			[]string{"/usr/bin/xkey"},
			false,
		},
		{
			"empty args",
			[]string{},
			false,
		},
		{
			"flags only",
			[]string{"/usr/bin/xkey", "--gui"},
			false,
		},
		{
			"chrome origin not first arg",
			[]string{"/usr/bin/xkey", "--log-level", "debug", "chrome-extension://id/"},
			true,
		},
		{
			"firefox manifest path (linux)",
			[]string{"/usr/bin/xkey", "/home/user/.mozilla/native-messaging-hosts/com.automatethethings.xkey.json"},
			true,
		},
		{
			"firefox manifest path (macos)",
			[]string{"/usr/bin/xkey", "/Users/user/Library/Application Support/Mozilla/NativeMessagingHosts/com.automatethethings.xkey.json"},
			true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isNativeMessagingInvocation(tt.args)
			if got != tt.want {
				t.Errorf("isNativeMessagingInvocation(%v) = %v, want %v", tt.args, got, tt.want)
			}
		})
	}
}
