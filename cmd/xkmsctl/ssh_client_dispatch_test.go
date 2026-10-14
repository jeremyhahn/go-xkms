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

// ssh_client_dispatch_test.go pins how the SSH verbs build their client from
// --server, and that an unusable embedded store or server URL is refused.
package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestXkmsctlSSHClient_RemoteServer(t *testing.T) {
	cfg := NewConfig()
	cfg.Protocol = "rest"
	cfg.Server = "https://127.0.0.1:1"
	withGlobalConfig(t, cfg)

	cl, closer, err := xkmsctlSSHClient()
	require.NoError(t, err)
	assert.NotNil(t, cl)
	closer()
}

func TestXkmsctlSSHClient_Refusals(t *testing.T) {
	notDir := filepath.Join(t.TempDir(), "plain.txt")
	require.NoError(t, os.WriteFile(notDir, []byte("x"), 0600))

	cases := []struct {
		name     string
		protocol string
		server   string
		keyDir   string
	}{
		{"embedded store under a file", "embedded", "", notDir},
		{"unsupported server scheme", "rest", "ftp://127.0.0.1:1", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := NewConfig()
			cfg.Protocol, cfg.Server, cfg.KeyDir = tc.protocol, tc.server, tc.keyDir
			withGlobalConfig(t, cfg)

			cl, closer, err := xkmsctlSSHClient()
			assert.Error(t, err)
			assert.Nil(t, cl)
			assert.Nil(t, closer)
		})
	}
}
