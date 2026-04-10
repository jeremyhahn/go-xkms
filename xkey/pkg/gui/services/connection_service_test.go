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

package services

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui/events"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConnectionServiceNewDefault(t *testing.T) {
	svc := NewConnectionService()
	require.NotNil(t, svc)

	info := svc.GetConnectionInfo()
	require.NotNil(t, info)
	assert.Equal(t, "disconnected", info.State)
	assert.Empty(t, info.Protocol)
	assert.Empty(t, info.Address)
	assert.False(t, info.TLS)
	assert.Empty(t, info.Version)
	assert.Empty(t, info.Error)
}

func TestConnectionServiceSetContext(t *testing.T) {
	svc := NewConnectionService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestConnectionServiceSetEventEmitter(t *testing.T) {
	svc := NewConnectionService()
	assert.Nil(t, svc.emitter)

	var received []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		received = append(received, e)
	})
	assert.NotNil(t, svc.emitter)

	// Verify the emitter is wired correctly by calling emit directly.
	svc.emit(events.NewEvent(events.EventServerConnected, nil))
	require.Len(t, received, 1)
	assert.Equal(t, events.EventServerConnected, received[0].Type)
}

func TestConnectionServiceEmitNilEmitter(t *testing.T) {
	svc := NewConnectionService()
	// Should not panic when no emitter is set.
	svc.emit(events.NewEvent(events.EventServerConnected, nil))
}

func TestConnectionServiceInvalidProtocol(t *testing.T) {
	svc := NewConnectionService()

	info, err := svc.Connect("invalid-proto", "localhost:9443", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidProtocol))
	assert.Nil(t, info)
}

func TestConnectionServiceInvalidAddress(t *testing.T) {
	svc := NewConnectionService()

	info, err := svc.Connect("grpc", "", false, "", "")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAddress))
	assert.Nil(t, info)
}

func TestConnectionServiceDisconnectWhenNotConnected(t *testing.T) {
	svc := NewConnectionService()

	err := svc.Disconnect()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerNotConnected))
}

func TestConnectionServiceHealthCheckWhenNotConnected(t *testing.T) {
	svc := NewConnectionService()

	resp, err := svc.HealthCheck()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrServerNotConnected))
	assert.Nil(t, resp)
}

func TestConnectionServiceIsConnected(t *testing.T) {
	svc := NewConnectionService()
	assert.False(t, svc.IsConnected())
}

func TestConnectionServiceGetClientNil(t *testing.T) {
	svc := NewConnectionService()
	assert.Nil(t, svc.GetClient())
}

func TestConnectionServiceSetErrorState(t *testing.T) {
	svc := NewConnectionService()

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	testErr := errors.New("connection refused")
	info := svc.setErrorState("grpc", "localhost:9443", true, "connect", testErr)

	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.Equal(t, "grpc", info.Protocol)
	assert.Equal(t, "localhost:9443", info.Address)
	assert.True(t, info.TLS)
	assert.Equal(t, "connection refused", info.Error)

	// Verify state was stored.
	storedInfo := svc.GetConnectionInfo()
	assert.Equal(t, "error", storedInfo.State)

	// Verify error event was emitted.
	require.Len(t, emittedEvents, 1)
	assert.Equal(t, events.EventServerError, emittedEvents[0].Type)
	payload, ok := emittedEvents[0].Payload.(events.ServerErrorPayload)
	require.True(t, ok)
	assert.Equal(t, "connection refused", payload.Message)
	assert.Equal(t, "connect", payload.Operation)
}

func TestConnectionServiceConnectAlreadyConnected(t *testing.T) {
	svc := NewConnectionService()
	// Manually force a "connected" state.
	svc.state.Store(&ConnectionInfo{State: "connected"})

	_, err := svc.Connect("grpc", "localhost:9443", false, "", "")
	assert.True(t, errors.Is(err, ErrServerAlreadyConnected))
}

func TestConnectionServiceConnectSdkNewError(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	// The unix protocol with a non-existent socket path will fail on Connect.
	// Use "unix" protocol which will attempt to create a client but fail connecting.
	info, err := svc.Connect("unix", "/nonexistent/path/socket.sock", false, "", "")
	require.Error(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)

	// Verify error event was emitted.
	assert.NotEmpty(t, emittedEvents)
}

func TestConnectionServiceDisconnectEmitsEvent(t *testing.T) {
	svc := NewConnectionService()

	var emittedEvents []events.Event
	var mu sync.Mutex
	svc.SetEventEmitter(func(e events.Event) {
		mu.Lock()
		emittedEvents = append(emittedEvents, e)
		mu.Unlock()
	})

	// Inject a mock client that implements Close.
	svc.mu.Lock()
	svc.client = &mockCloseClient{}
	svc.mu.Unlock()
	svc.state.Store(&ConnectionInfo{State: "connected"})

	err := svc.Disconnect()
	assert.NoError(t, err)

	// Verify disconnected state.
	info := svc.GetConnectionInfo()
	assert.Equal(t, "disconnected", info.State)

	// Verify event emitted.
	mu.Lock()
	defer mu.Unlock()
	require.Len(t, emittedEvents, 1)
	assert.Equal(t, events.EventServerDisconnected, emittedEvents[0].Type)
}

func TestConnectionServiceDisconnectCloseError(t *testing.T) {
	svc := NewConnectionService()
	svc.SetEventEmitter(func(e events.Event) {})

	closeErr := errors.New("close failed")
	svc.mu.Lock()
	svc.client = &mockCloseClient{err: closeErr}
	svc.mu.Unlock()
	svc.state.Store(&ConnectionInfo{State: "connected"})

	err := svc.Disconnect()
	assert.True(t, errors.Is(err, closeErr))

	// State should still transition to disconnected even on close error.
	info := svc.GetConnectionInfo()
	assert.Equal(t, "disconnected", info.State)
}

// mockCloseClient is a minimal mock that only implements Close.
type mockCloseClient struct {
	mockClient
	err error
}

func (m *mockCloseClient) Connect(context.Context) error { return nil }
func (m *mockCloseClient) Close() error                  { return m.err }

func TestConnectionServiceValidProtocols(t *testing.T) {
	expected := []string{"unix", "rest", "grpc", "quic", "mcp"}
	for _, proto := range expected {
		_, ok := validProtocols[proto]
		assert.True(t, ok, "expected protocol %q to be valid", proto)
	}
}

func TestConnectionServiceConnectWithSPKIPin(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	var emittedEvents []events.Event
	svc.SetEventEmitter(func(e events.Event) {
		emittedEvents = append(emittedEvents, e)
	})

	// Using an SPKI pin with a non-existent server will fail at connect,
	// but it should enable TLS and use the functional options path.
	info, err := svc.Connect("rest", "https://127.0.0.1:1", false, "", "abcdef1234567890")
	require.Error(t, err)
	require.NotNil(t, info)
	assert.Equal(t, "error", info.State)
	assert.True(t, info.TLS, "SPKI pin should enable TLS")

	// Verify error event was emitted.
	assert.NotEmpty(t, emittedEvents)
}

func TestConnectionServiceConnectSPKIPinEnablesTLS(t *testing.T) {
	svc := NewConnectionService()
	svc.SetContext(context.Background())

	// Connect with tlsEnabled=false but spkiPin set - TLS should be forced on.
	info, err := svc.Connect("rest", "https://127.0.0.1:1", false, "", "deadbeef")
	require.Error(t, err) // expected: can't reach server
	require.NotNil(t, info)
	assert.True(t, info.TLS, "SPKI pin should force TLS enabled")
}

func TestConnectionServiceSPKIPinFieldInConnectionInfo(t *testing.T) {
	svc := NewConnectionService()

	info := svc.GetConnectionInfo()
	assert.Empty(t, info.SPKIPin)

	// Manually store state with SPKI pin.
	svc.state.Store(&ConnectionInfo{
		State:   "connected",
		SPKIPin: "sha256/test-pin",
	})
	info = svc.GetConnectionInfo()
	assert.Equal(t, "sha256/test-pin", info.SPKIPin)
}
