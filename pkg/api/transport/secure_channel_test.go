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

package transport

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIsUnixEndpoint(t *testing.T) {
	for address, want := range map[string]bool{
		"unix:///run/xkms/xkms.sock": true,
		"unix:relative.sock":         true,
		"127.0.0.1:8443":             false,
		"localhost:8443":             false,
		"http://unix:8443":           false,
		"":                           false,
	} {
		assert.Equal(t, want, IsUnixEndpoint(address), address)
	}
}

func TestRequireSecureChannel(t *testing.T) {
	tests := []struct {
		name      string
		env       string
		allow     bool
		plaintext bool
		wantErr   bool
	}{
		{name: "encrypted channel", plaintext: false},
		{name: "plaintext refused", plaintext: true, wantErr: true},
		{name: "config opt-out", allow: true, plaintext: true},
		{name: "env opt-out", env: "true", plaintext: true},
		{name: "env overrides config opt-out", env: "false", allow: true, plaintext: true, wantErr: true},
		{name: "unreadable env keeps the guard on", env: "maybe", allow: true, plaintext: true, wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Setenv(EnvAllowInsecureTransport, tt.env)
			cfg := &Config{Address: "10.0.0.1:8443", AllowInsecureTransport: tt.allow}

			err := cfg.RequireSecureChannel("grpc", tt.plaintext)
			if !tt.wantErr {
				assert.NoError(t, err)
				return
			}
			require.ErrorIs(t, err, ErrInsecureTransport)
			assert.Contains(t, err.Error(), "grpc")
			assert.NotContains(t, err.Error(), cfg.Address, "the error names the transport, not the endpoint")
		})
	}
}

func TestWithAllowInsecureTransport(t *testing.T) {
	cfg := DefaultConfig()
	assert.False(t, cfg.AllowInsecureTransport, "the guard is on by default")

	require.NoError(t, ApplyOptions(cfg, WithAllowInsecureTransport(true)))
	assert.True(t, cfg.AllowInsecureTransport)
	assert.True(t, cfg.Clone().AllowInsecureTransport, "Clone carries the opt-out")

	require.NoError(t, ApplyOptions(cfg, WithAllowInsecureTransport(false)))
	assert.False(t, cfg.AllowInsecureTransport)
}
