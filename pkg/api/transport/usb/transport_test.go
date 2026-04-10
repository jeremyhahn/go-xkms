// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.

package usb

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPhoneUSB implements the phoneTransport interface for testing.
type mockPhoneUSB struct {
	connectErr      error
	closeErr        error
	connected       bool
	sendReceiveResp []byte
	sendReceiveErr  error
}

func (m *mockPhoneUSB) Connect(_ context.Context) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockPhoneUSB) Close() error {
	m.connected = false
	return m.closeErr
}

func (m *mockPhoneUSB) IsConnected() bool {
	return m.connected
}

func (m *mockPhoneUSB) SendAndReceive(_ context.Context, _ []byte) ([]byte, error) {
	if m.sendReceiveErr != nil {
		return nil, m.sendReceiveErr
	}
	return m.sendReceiveResp, nil
}

func TestNew(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.NotNil(t, tr.Config())
	assert.Equal(t, 30*time.Second, tr.Config().Timeout)
}

func TestNewWithOptions(t *testing.T) {
	tr, err := New(func(cfg *transport.Config) error {
		cfg.Timeout = 5 * time.Second
		return nil
	})
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 5*time.Second, tr.Config().Timeout)
}

func TestNewWithBadOption(t *testing.T) {
	tr, err := New(func(cfg *transport.Config) error {
		return assert.AnError
	})
	require.Error(t, err)
	assert.Nil(t, tr)
}

func TestNewWithConfig(t *testing.T) {
	cfg := &transport.Config{Timeout: 10 * time.Second}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 10*time.Second, tr.Config().Timeout)
}

func TestNewWithConfigNil(t *testing.T) {
	tr, err := NewWithConfig(nil)
	require.NoError(t, err)
	require.NotNil(t, tr)
	assert.Equal(t, 30*time.Second, tr.Config().Timeout)
}

func TestCloseNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

func TestCloseWithPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &mockPhoneUSB{connected: true}
	tr.connected = true
	assert.NoError(t, tr.Close())
	assert.False(t, tr.connected)
}

func TestCloseWithPhoneUSBError(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &mockPhoneUSB{connected: true, closeErr: errors.New("close failed")}
	tr.connected = true
	err = tr.Close()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "close failed")
}

func TestHealthyNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.False(t, tr.Healthy(context.Background()))
}

func TestHealthyConnectedButNilPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.connected = true
	assert.False(t, tr.Healthy(context.Background()))
}

func TestHealthyConnectedAndPhoneUSBConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &mockPhoneUSB{connected: true}
	tr.connected = true
	assert.True(t, tr.Healthy(context.Background()))
}

func TestHealthyConnectedButPhoneUSBDisconnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.phoneUSB = &mockPhoneUSB{connected: false}
	tr.connected = true
	assert.False(t, tr.Healthy(context.Background()))
}

func TestConnNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	assert.Nil(t, tr.Conn())
}

func TestConnWithPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	mock := &mockPhoneUSB{connected: true}
	tr.phoneUSB = mock
	assert.Equal(t, mock, tr.Conn())
}

func TestRequestNotConnected(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	err = tr.Request(context.Background(), "test", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequestConnectedButNilPhoneUSB(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	tr.connected = true
	err = tr.Request(context.Background(), "test", nil, nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestRequestMarshalError(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	mock := &mockPhoneUSB{connected: true}
	tr.phoneUSB = mock
	tr.connected = true

	// Channels cannot be marshalled to JSON.
	err = tr.Request(context.Background(), "test", make(chan int), nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrInvalidRequest)
}

func TestRequestSendReceiveError(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	mock := &mockPhoneUSB{
		connected:      true,
		sendReceiveErr: errors.New("send failed"),
	}
	tr.phoneUSB = mock
	tr.connected = true

	err = tr.Request(context.Background(), "test", "hello", nil)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
	assert.False(t, tr.connected)
}

func TestRequestSuccessNilResp(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	mock := &mockPhoneUSB{
		connected:       true,
		sendReceiveResp: []byte(`{"status":"ok"}`),
	}
	tr.phoneUSB = mock
	tr.connected = true

	err = tr.Request(context.Background(), "test", "hello", nil)
	require.NoError(t, err)
	assert.True(t, tr.connected)
}

func TestRequestSuccessWithResp(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)

	type testResp struct {
		Status string `json:"status"`
	}

	mock := &mockPhoneUSB{
		connected:       true,
		sendReceiveResp: []byte(`{"status":"ok"}`),
	}
	tr.phoneUSB = mock
	tr.connected = true

	var resp testResp
	err = tr.Request(context.Background(), "test", map[string]string{"key": "val"}, &resp)
	require.NoError(t, err)
	assert.Equal(t, "ok", resp.Status)
}

func TestRequestUnmarshalError(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	mock := &mockPhoneUSB{
		connected:       true,
		sendReceiveResp: []byte(`not-json`),
	}
	tr.phoneUSB = mock
	tr.connected = true

	var resp json.RawMessage
	err = tr.Request(context.Background(), "test", "hello", &resp)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrInvalidResponse)
}

func TestRequestStreamNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	s, err := tr.RequestStream(context.Background(), "test", nil)
	require.Error(t, err)
	assert.Nil(t, s)
	assert.ErrorIs(t, err, ErrStreamNotSupported)
}

func TestPasswordOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"PasswordAdd", func() error { _, e := tr.PasswordAdd(ctx, nil); return e }},
		{"PasswordGet", func() error { _, e := tr.PasswordGet(ctx, nil); return e }},
		{"PasswordList", func() error { _, e := tr.PasswordList(ctx, nil); return e }},
		{"PasswordUpdate", func() error { return tr.PasswordUpdate(ctx, nil) }},
		{"PasswordDelete", func() error { return tr.PasswordDelete(ctx, nil) }},
		{"PasswordStoreUnlock", func() error { return tr.PasswordStoreUnlock(ctx, nil) }},
		{"PasswordStoreLock", func() error { return tr.PasswordStoreLock(ctx) }},
		{"PasswordStoreStatus", func() error { _, e := tr.PasswordStoreStatus(ctx); return e }},
		{"PasswordStoreSetAccessMode", func() error { return tr.PasswordStoreSetAccessMode(ctx, nil) }},
		{"PasswordGenerate", func() error { _, e := tr.PasswordGenerate(ctx, nil); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

func TestSealStoreOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"SealStorePut", func() error { return tr.SealStorePut(ctx, nil) }},
		{"SealStoreGet", func() error { _, e := tr.SealStoreGet(ctx, nil); return e }},
		{"SealStoreDelete", func() error { return tr.SealStoreDelete(ctx, nil) }},
		{"SealStoreList", func() error { _, e := tr.SealStoreList(ctx); return e }},
		{"SealStoreReseal", func() error { return tr.SealStoreReseal(ctx, nil) }},
		{"SealStoreStatus", func() error { _, e := tr.SealStoreStatus(ctx); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

func TestPolicyOperationsNotSupported(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"PolicyCreate", func() error { _, e := tr.PolicyCreate(ctx, nil); return e }},
		{"PolicyGet", func() error { _, e := tr.PolicyGet(ctx, nil); return e }},
		{"PolicyList", func() error { _, e := tr.PolicyList(ctx); return e }},
		{"PolicyDelete", func() error { return tr.PolicyDelete(ctx, nil) }},
		{"PolicyRefresh", func() error { _, e := tr.PolicyRefresh(ctx, nil); return e }},
		{"PolicyVerify", func() error { _, e := tr.PolicyVerify(ctx, nil); return e }},
		{"PolicyExport", func() error { _, e := tr.PolicyExport(ctx, nil); return e }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.ErrorIs(t, err, ErrNotSupported)
		})
	}
}

func TestConnectFailsWithoutUSBDevice(t *testing.T) {
	tr, err := New()
	require.NoError(t, err)
	ctx := context.Background()
	err = tr.Connect(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
	assert.False(t, tr.connected)
}

func TestConnectWithCustomTimeout(t *testing.T) {
	tr, err := New(func(cfg *transport.Config) error {
		cfg.Timeout = 1 * time.Second
		return nil
	})
	require.NoError(t, err)
	ctx := context.Background()
	err = tr.Connect(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
}

func TestConnectWithZeroTimeout(t *testing.T) {
	cfg := &transport.Config{Timeout: 0}
	tr, err := NewWithConfig(cfg)
	require.NoError(t, err)
	ctx := context.Background()
	err = tr.Connect(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, transport.ErrConnectionFailed)
}
