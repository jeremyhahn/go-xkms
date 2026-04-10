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
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewLogNotifier(t *testing.T) {
	logger := slog.Default()
	n := NewLogNotifier(logger)
	require.NotNil(t, n)
	assert.Equal(t, logger, n.logger)
	assert.False(t, n.closed.Load())
}

func TestLogNotifier_NotifyTouchRequired(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
	n := NewLogNotifier(logger)

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
		RPName:    "Example Corp",
		UserName:  "alice",
	}

	err := n.NotifyTouchRequired(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "Touch required")
	assert.Contains(t, output, "register")
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "Example Corp")
	assert.Contains(t, output, "alice")
}

func TestLogNotifier_NotifyTouchRequired_FallsBackToRPID(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{
		Level: slog.LevelWarn,
	}))
	n := NewLogNotifier(logger)

	req := &TouchRequest{
		Operation: "authenticate",
		RPID:      "example.com",
		RPName:    "",
		UserName:  "bob",
	}

	err := n.NotifyTouchRequired(req)
	require.NoError(t, err)

	output := buf.String()
	assert.Contains(t, output, "example.com")
	assert.Contains(t, output, "display=example.com")
}

func TestLogNotifier_CloseIdempotent(t *testing.T) {
	n := NewLogNotifier(slog.Default())

	err := n.Close()
	require.NoError(t, err)
	assert.True(t, n.closed.Load())

	err = n.Close()
	require.NoError(t, err)
}

func TestLogNotifier_NotifyAfterClose(t *testing.T) {
	n := NewLogNotifier(slog.Default())

	require.NoError(t, n.Close())

	req := &TouchRequest{
		Operation: "register",
		RPID:      "example.com",
	}
	err := n.NotifyTouchRequired(req)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotifierClosed)
}
