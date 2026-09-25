// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package server

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
)

// closedTCPAddr binds an ephemeral 127.0.0.1 port, immediately closes it, and
// returns the address string, so a dial against it fails fast with connection
// refused instead of timing out against an unroutable address.
func closedTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())
	return addr
}

// TestNewRemoteQRDBStorage_UnsupportedTransport proves an unsupported
// transport name is rejected before any dial is attempted.
func TestNewRemoteQRDBStorage_UnsupportedTransport(t *testing.T) {
	s := &Server{config: &config.Config{}, logger: custodyQuietLogger()}

	_, err := s.newRemoteQRDBStorage("carrier-pigeon")
	require.Error(t, err)
	var unsupported *ErrUnsupportedStorageBackend
	require.ErrorAs(t, err, &unsupported)
}

// TestNewRemoteQRDBStorage_ConnectFails proves a REST transport dialed
// against an address nothing is listening on surfaces the connect failure
// rather than returning a half-built backend.
func TestNewRemoteQRDBStorage_ConnectFails(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			QRDB: config.QRDBConfig{Address: "http://" + closedTCPAddr(t)},
		},
	}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	_, err := s.newRemoteQRDBStorage("rest")
	require.Error(t, err)
}

// TestInitializeQRDBStorage_RemoteConnectFailsWraps proves initializeQRDBStorage
// wraps a remote-transport connect failure into *ErrStorageCreate rather than
// leaking the bare underlying error.
func TestInitializeQRDBStorage_RemoteConnectFailsWraps(t *testing.T) {
	cfg := &config.Config{
		Storage: config.StorageConfig{
			Backend: "qrdb",
			QRDB: config.QRDBConfig{
				Transport: "rest",
				Address:   "http://" + closedTCPAddr(t),
			},
		},
	}
	s := &Server{config: cfg, logger: custodyQuietLogger()}

	err := s.initializeQRDBStorage()
	require.Error(t, err)
	var createErr *ErrStorageCreate
	require.ErrorAs(t, err, &createErr)
	require.Equal(t, "remote qrdb storage", createErr.Resource)
}
