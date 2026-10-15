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

package module

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport/unix"
)

// TestCreateUnixClient_CarriesClientCertificate verifies a unix:// target
// dials with the module's mTLS configuration: xkmsd's socket is the qrdb
// node's TLS listener, which admits a caller by its client certificate.
func TestCreateUnixClient_CarriesClientCertificate(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Target = "unix:///var/run/xkms/xkms.sock"
	cfg.TLS.Enabled = true
	cfg.TLS.CertFile = "/path/to/client.crt"
	cfg.TLS.KeyFile = "/path/to/client.key"
	cfg.TLS.CAFile = "/path/to/ca.crt"

	m, err := New(WithConfig(cfg))
	require.NoError(t, err)
	require.NoError(t, m.initializeClient())

	client, ok := m.client.(*unix.Transport)
	require.True(t, ok, "a unix:// target must build the unix transport")
	got := client.Config()
	require.Equal(t, "/var/run/xkms/xkms.sock", got.Address)
	require.True(t, got.TLSEnabled)
	require.Equal(t, cfg.TLS.CertFile, got.TLSCertFile)
	require.Equal(t, cfg.TLS.KeyFile, got.TLSKeyFile)
	require.Equal(t, cfg.TLS.CAFile, got.TLSCAFile)
}

// TestCreateUnixClient_PlaintextWhenTLSDisabled verifies a unix:// target
// with TLS disabled stays plaintext, the node-local signserver's socket.
func TestCreateUnixClient_PlaintextWhenTLSDisabled(t *testing.T) {
	m, err := New(WithConfig(DefaultConfig()))
	require.NoError(t, err)

	client, err := m.createUnixClient("/run/signserver.sock")
	require.NoError(t, err)
	got := client.(*unix.Transport).Config()
	require.False(t, got.TLSEnabled)
	require.Empty(t, got.TLSCertFile)
}

// TestCreateUnixClient_EmptySocketPath verifies an empty socket path is
// refused with the transport's typed configuration error.
func TestCreateUnixClient_EmptySocketPath(t *testing.T) {
	m, err := New(WithConfig(DefaultConfig()))
	require.NoError(t, err)

	_, err = m.createUnixClient("")
	var cfgErr *transport.ConfigError
	require.ErrorAs(t, err, &cfgErr)
	require.Equal(t, "Address", cfgErr.Field)
}
