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

//go:build frost

package main

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// frostMessageCmd builds a command carrying the three message flags the
// FROST sign verbs register, set to the given values.
func frostMessageCmd(t *testing.T, values map[string]string) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "sign"}
	for _, name := range []string{"message", "message-file", "message-hex"} {
		cmd.Flags().String(name, "", "")
	}
	for name, value := range values {
		require.NoError(t, cmd.Flags().Set(name, value))
	}
	return cmd
}

func TestGetMessage_Sources(t *testing.T) {
	path := filepath.Join(t.TempDir(), "msg.bin")
	require.NoError(t, os.WriteFile(path, []byte("file contents"), 0600))
	fileDigest := sha256.Sum256([]byte("file contents"))

	cases := []struct {
		name   string
		values map[string]string
		want   []byte
	}{
		{"literal message", map[string]string{"message": "hello"}, []byte("hello")},
		{"literal wins over the other sources", map[string]string{"message": "hello", "message-hex": "ff"}, []byte("hello")},
		{"file is signed as its SHA-256 digest", map[string]string{"message-file": path}, fileDigest[:]},
		{"hex", map[string]string{"message-hex": "deadbeef"}, []byte{0xde, 0xad, 0xbe, 0xef}},
		{"hex with 0x prefix", map[string]string{"message-hex": "0xdeadbeef"}, []byte{0xde, 0xad, 0xbe, 0xef}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getMessage(frostMessageCmd(t, tc.values))
			require.NoError(t, err)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestGetMessage_Errors(t *testing.T) {
	cases := []struct {
		name     string
		cmd      func(t *testing.T) *cobra.Command
		sentinel error
	}{
		{"no source", func(t *testing.T) *cobra.Command { return frostMessageCmd(t, nil) }, ErrMessageInputRequired},
		{"unreadable file", func(t *testing.T) *cobra.Command {
			return frostMessageCmd(t, map[string]string{"message-file": filepath.Join(t.TempDir(), "absent")})
		}, ErrReadMessageFileFailed},
		{"invalid hex", func(t *testing.T) *cobra.Command {
			return frostMessageCmd(t, map[string]string{"message-hex": "xyz"})
		}, ErrInvalidMessageHex},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := getMessage(tc.cmd(t))
			assert.ErrorIs(t, err, tc.sentinel)
			assert.Nil(t, got)
		})
	}
}

func TestGetMessage_UnregisteredFlag(t *testing.T) {
	got, err := getMessage(&cobra.Command{Use: "sign"})
	assert.Error(t, err)
	assert.Nil(t, got)
}

func TestTruncateMessage(t *testing.T) {
	assert.Equal(t, "short", truncateMessage([]byte("short"), 8))
	assert.Equal(t, "exactly8", truncateMessage([]byte("exactly8"), 8))
	assert.Equal(t, "too long...", truncateMessage([]byte("too long message"), 8))
}
