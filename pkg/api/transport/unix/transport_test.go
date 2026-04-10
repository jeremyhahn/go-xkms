// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package unix

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Constructor tests ---

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("/tmp/test.sock"))
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, "/tmp/test.sock", tr.config.Address)
}

func TestNew_NoAddress(t *testing.T) {
	_, err := New()
	assert.ErrorIs(t, err, ErrSocketPathRequired)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	_, err := NewWithConfig(nil)
	assert.ErrorIs(t, err, ErrSocketPathRequired)
}

func TestNewWithConfig_EmptyAddress(t *testing.T) {
	cfg := transport.DefaultConfig()
	_, err := NewWithConfig(cfg)
	assert.ErrorIs(t, err, ErrSocketPathRequired)
}

func TestNewWithConfig_ValidAddress(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/xkms.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/xkms.sock", tr.config.Address)
}

// --- Close without connection ---

func TestClose_NilConn(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

// --- Conn ---

func TestConn_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

// --- Config ---

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "/tmp/test.sock", tr.Config().Address)
}

// --- NotConnected error paths ---

func TestHealth_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListBackends_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGetBackend_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.GetBackend(context.Background(), "software")
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateKey_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSign_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.Sign(context.Background(), &transport.SignRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSeal_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.Seal(context.Background(), &transport.SealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierStatus_NotConnected(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/test.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	_, err = tr.BarrierStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

// --- Connect to non-existent socket ---

func TestConnect_FailedDial(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "/tmp/nonexistent-xkms-test-socket.sock"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	err = tr.Connect(context.Background())
	assert.Error(t, err)
}
