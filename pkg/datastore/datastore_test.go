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

package datastore

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

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

// TestOpen_StandaloneMemoryEngine proves the in-memory engine works end to
// end through Open for the SDK/library composition path. Engine "memory"
// still requires Datastore.Path: go-qrdb roots the node's on-disk state
// (its vector-storage subsystem in particular) under it regardless of the
// primary KV engine -- adopted here exactly, not worked around -- so the
// primary KV data itself is non-durable but the directory is still real.
func TestOpen_StandaloneMemoryEngine(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory", Path: t.TempDir()},
	}

	backend, err := Open(context.Background(), cfg, testLogger())
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	require.NoError(t, backend.Put(context.Background(), "k", []byte("v")))
	got, err := backend.Get(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, []byte("v"), got)
}

// TestOpen_StandaloneMissingPath proves Datastore.Path is required for
// standalone mode regardless of Engine, matching config.Validate's own
// requirement -- this is the same check for an embedded/programmatic caller
// that never ran Validate.
func TestOpen_StandaloneMissingPath(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Engine: "memory"},
	}

	_, err := Open(context.Background(), cfg, testLogger())
	require.Error(t, err)

	var pathErr *embeddednode.ErrDatastorePathRequired
	require.ErrorAs(t, err, &pathErr)
}

// TestOpen_StandaloneDefaultModeIsStandalone proves an empty Mode defaults to
// "standalone", matching config.Validate's own default.
func TestOpen_StandaloneDefaultModeIsStandalone(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Path: t.TempDir()},
	}

	backend, err := Open(context.Background(), cfg, testLogger())
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()
}

// TestOpen_UnsupportedMode proves an unrecognized Datastore.Mode is rejected
// with a typed error rather than silently defaulting to standalone.
func TestOpen_UnsupportedMode(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{Mode: "carrier-pigeon"},
	}

	_, err := Open(context.Background(), cfg, testLogger())
	require.Error(t, err)
	var modeErr *ErrUnsupportedDatastoreMode
	require.ErrorAs(t, err, &modeErr)
}

// TestOpen_RemoteUnsupportedTransport proves a remote mode with an
// unsupported transport is rejected before any dial is attempted, wrapped as
// *ErrOpenDatastore.
func TestOpen_RemoteUnsupportedTransport(t *testing.T) {
	cfg := &config.Config{
		Datastore: config.DatastoreConfig{
			Mode:   "remote",
			Remote: config.DatastoreRemoteConfig{Transport: "ftp"},
		},
	}

	_, err := Open(context.Background(), cfg, testLogger())
	require.Error(t, err)

	var openErr *ErrOpenDatastore
	require.ErrorAs(t, err, &openErr)
	assert.Equal(t, "remote", openErr.Mode)

	var unsupported *ErrUnsupportedStorageBackend
	require.ErrorAs(t, err, &unsupported)
}

// TestDialRemote_UnsupportedTransport proves an unsupported transport name is
// rejected before any dial is attempted.
func TestDialRemote_UnsupportedTransport(t *testing.T) {
	_, err := DialRemote(context.Background(), config.DatastoreRemoteConfig{Transport: "carrier-pigeon"})
	require.Error(t, err)
	var unsupported *ErrUnsupportedStorageBackend
	require.ErrorAs(t, err, &unsupported)
}

// TestDialRemote_ConnectFails proves a REST transport dialed against an
// address nothing is listening on surfaces the connect failure rather than
// returning a half-built backend.
func TestDialRemote_ConnectFails(t *testing.T) {
	_, err := DialRemote(context.Background(), config.DatastoreRemoteConfig{
		Transport: "rest",
		Address:   closedTCPAddr(t),
	})
	require.Error(t, err)
}

// TestTransportOptions_Empty proves an unconfigured remote (no address, no
// TLS) yields no transport options.
func TestTransportOptions_Empty(t *testing.T) {
	opts := TransportOptions(config.DatastoreRemoteConfig{
		Address: "",
		TLS:     config.TLSConfig{Enabled: false},
	})
	assert.Empty(t, opts)
}

// TestTransportOptions_WithAddress proves an address alone yields exactly one
// option.
func TestTransportOptions_WithAddress(t *testing.T) {
	opts := TransportOptions(config.DatastoreRemoteConfig{
		Address: "localhost:63002",
		TLS:     config.TLSConfig{Enabled: false},
	})
	assert.Len(t, opts, 1)
}

// TestTransportOptions_WithAddressAndTLS proves an address plus a complete
// TLS config yields two options.
func TestTransportOptions_WithAddressAndTLS(t *testing.T) {
	opts := TransportOptions(config.DatastoreRemoteConfig{
		Address: "localhost:63002",
		TLS: config.TLSConfig{
			Enabled:  true,
			CAFile:   "/path/to/ca.pem",
			CertFile: "/path/to/cert.pem",
			KeyFile:  "/path/to/key.pem",
		},
	})
	assert.Len(t, opts, 2)
}

// TestErrUnsupportedStorageBackend_Error exercises the typed error's message.
func TestErrUnsupportedStorageBackend_Error(t *testing.T) {
	e := &ErrUnsupportedStorageBackend{Backend: "redis"}
	assert.Contains(t, e.Error(), "redis")
}

// TestErrUnsupportedDatastoreMode_Error exercises the typed error's message.
func TestErrUnsupportedDatastoreMode_Error(t *testing.T) {
	e := &ErrUnsupportedDatastoreMode{Mode: "teleport"}
	assert.Contains(t, e.Error(), "teleport")
}

// TestErrOpenDatastore_ErrorAndUnwrap exercises the typed error's message and
// Unwrap.
func TestErrOpenDatastore_ErrorAndUnwrap(t *testing.T) {
	cause := errors.New("boom")
	e := &ErrOpenDatastore{Mode: "standalone", Err: cause}
	assert.Contains(t, e.Error(), "standalone")
	assert.Contains(t, e.Error(), "boom")
	assert.Same(t, cause, e.Unwrap())
}
