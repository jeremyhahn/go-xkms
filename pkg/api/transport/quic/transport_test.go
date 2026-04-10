// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package quic

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Constructor tests ---

func TestNew_DefaultConfig(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.config)
}

func TestNew_WithAddress(t *testing.T) {
	tr, err := New(transport.WithAddress("localhost:8443"))
	require.NoError(t, err)
	assert.Equal(t, "https://localhost:8443", tr.baseURL)
}

func TestNew_InvalidOption(t *testing.T) {
	_, err := New(transport.WithAddress(""))
	require.Error(t, err)
}

func TestNewWithConfig_NilConfig(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
}

func TestNewWithConfig_CustomConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "custom:8443"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://custom:8443", tr.baseURL)
}

func TestNewWithConfig_HTTPSPrefix(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "https://already-prefixed:443"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://already-prefixed:443", tr.baseURL)
}

func TestNewWithConfig_TrailingSlash(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "https://host:443/"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://host:443", tr.baseURL)
}

// --- Close without connection ---

func TestClose_NilClient(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

// --- Conn ---

func TestConn_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

// --- Config ---

func TestConfig(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "test:8443"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "test:8443", tr.Config().Address)
}

// --- BaseURL ---

func TestBaseURL(t *testing.T) {
	cfg := transport.DefaultConfig()
	cfg.Address = "myhost:443"
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	assert.Equal(t, "https://myhost:443", tr.BaseURL())
}

// --- IsConnected ---

func TestIsConnected_Default(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.IsConnected())
}

// --- Healthy ---

func TestHealthy_NilClient(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

// --- RequestStream ---

func TestRequestStream_NotSupported(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.RequestStream(context.Background(), "test", nil)
	assert.ErrorIs(t, err, transport.ErrStreamNotSupported)
}

// --- NotConnected error paths ---

func TestHealth_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Health(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestListBackends_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.ListBackends(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestGenerateKey_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSign_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Sign(context.Background(), &transport.SignRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestSeal_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.Seal(context.Background(), &transport.SealRequest{})
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestBarrierStatus_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.BarrierStatus(context.Background())
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.DoRequest(context.Background(), "GET", "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestDoRawRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	_, err = tr.DoRawRequest(context.Background(), "GET", "/health", nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequest_NotConnected(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	err = tr.Request(context.Background(), "/health", nil, nil)
	assert.ErrorIs(t, err, ErrNotConnected)
}
