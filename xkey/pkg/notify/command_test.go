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

package notify

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewCommandNotifier_Valid(t *testing.T) {
	n, err := NewCommandNotifier("echo hello", slog.Default())
	require.NoError(t, err)
	require.NotNil(t, n)
	assert.Equal(t, "echo hello", n.command)
}

func TestNewCommandNotifier_EmptyCommand(t *testing.T) {
	n, err := NewCommandNotifier("", slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
	assert.Nil(t, n)
}

func TestNewCommandNotifier_WhitespaceOnly(t *testing.T) {
	n, err := NewCommandNotifier("   \t\n  ", slog.Default())
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCommand)
	assert.Nil(t, n)
}

func TestExpandTemplate(t *testing.T) {
	tests := []struct {
		name     string
		tmpl     string
		req      *TouchRequest
		expected string
	}{
		{
			name: "all variables",
			tmpl: "echo op=%o rp=%r name=%n user=%u",
			req: &TouchRequest{
				Operation: "register",
				RPID:      "example.com",
				RPName:    "Example Corp",
				UserName:  "alice",
			},
			expected: "echo op=register rp=example.com name=Example Corp user=alice",
		},
		{
			name: "no variables",
			tmpl: "echo hello world",
			req: &TouchRequest{
				Operation: "register",
				RPID:      "example.com",
			},
			expected: "echo hello world",
		},
		{
			name: "repeated variables",
			tmpl: "%o-%o-%r",
			req: &TouchRequest{
				Operation: "auth",
				RPID:      "example.com",
			},
			expected: "auth-auth-example.com",
		},
		{
			name: "empty field values",
			tmpl: "echo %o %r %n %u",
			req: &TouchRequest{
				Operation: "register",
				RPID:      "",
				RPName:    "",
				UserName:  "",
			},
			expected: "echo register   ",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := expandTemplate(tc.tmpl, tc.req)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestCommandNotifier_NotifyTouchRequired(t *testing.T) {
	tmpDir := t.TempDir()
	outFile := filepath.Join(tmpDir, "notify_output.txt")

	cmd := "echo '%o %r %n %u' > " + outFile
	n, err := NewCommandNotifier(cmd, slog.Default())
	require.NoError(t, err)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example",
		UserName:  "alice",
	}

	err = n.NotifyTouchRequired(req)
	require.NoError(t, err)

	// The command runs asynchronously, so poll for the output file.
	var content []byte
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		content, err = os.ReadFile(outFile)
		if err == nil && len(content) > 0 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}

	require.NoError(t, err, "output file should exist")
	assert.Contains(t, string(content), "register example.com Example alice")
}

func TestCommandNotifier_NotifyTouchRequired_InvalidCommand(t *testing.T) {
	// The command is invalid but NotifyTouchRequired should not block or
	// return an error since execution is asynchronous. The error is logged.
	n, err := NewCommandNotifier("/nonexistent/binary", slog.Default())
	require.NoError(t, err)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}

	err = n.NotifyTouchRequired(req)
	require.NoError(t, err)
}

func TestCommandNotifier_CloseIdempotent(t *testing.T) {
	n, err := NewCommandNotifier("echo test", slog.Default())
	require.NoError(t, err)

	require.NoError(t, n.Close())
	assert.True(t, n.closed.Load())

	require.NoError(t, n.Close())
}

func TestCommandNotifier_NotifyAfterClose(t *testing.T) {
	n, err := NewCommandNotifier("echo test", slog.Default())
	require.NoError(t, err)

	require.NoError(t, n.Close())

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}
	err = n.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotifierClosed)
}
