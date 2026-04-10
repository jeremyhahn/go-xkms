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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ---------------------------------------------------------------------------
// Mock connector for server service tests
// ---------------------------------------------------------------------------

// mockServerConnector implements ServerConnector for testing.
type mockServerConnector struct {
	connected  bool
	connInfo   *ConnectionInfo
	connectErr error
	disconnErr error
}

func (m *mockServerConnector) Connect(_ context.Context, _, _ string, _ bool) error {
	if m.connectErr != nil {
		return m.connectErr
	}
	m.connected = true
	return nil
}

func (m *mockServerConnector) Disconnect() error {
	if m.disconnErr != nil {
		return m.disconnErr
	}
	m.connected = false
	return nil
}

func (m *mockServerConnector) IsConnected() bool                  { return m.connected }
func (m *mockServerConnector) GetConnectionInfo() *ConnectionInfo { return m.connInfo }

// ---------------------------------------------------------------------------
// Constructor tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_NewServerService(t *testing.T) {
	svc := NewServerService()
	require.NotNil(t, svc)
	assert.NotNil(t, svc.servers)
	assert.NotNil(t, svc.connInfo)
	assert.NotNil(t, svc.log)
	assert.Nil(t, svc.ctx)
	assert.Nil(t, svc.connector)
	assert.Nil(t, svc.saveFn)
	assert.Nil(t, svc.loadFn)
}

// ---------------------------------------------------------------------------
// Setter tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_SetContext(t *testing.T) {
	svc := NewServerService()
	ctx := context.Background()
	svc.SetContext(ctx)
	assert.Equal(t, ctx, svc.ctx)
}

func TestServerService_Coverage_SetConnector(t *testing.T) {
	svc := NewServerService()
	assert.Nil(t, svc.connector)

	connector := &mockServerConnector{}
	svc.SetConnector(connector)
	assert.NotNil(t, svc.connector)
}

func TestServerService_Coverage_SetConnector_Nil(t *testing.T) {
	svc := NewServerService()
	svc.SetConnector(nil)
	assert.Nil(t, svc.connector)
}

func TestServerService_Coverage_SetSaveFunc(t *testing.T) {
	svc := NewServerService()
	assert.Nil(t, svc.saveFn)

	called := false
	svc.SetSaveFunc(func(_ []*ServerEntry) error {
		called = true
		return nil
	})
	assert.NotNil(t, svc.saveFn)

	err := svc.saveFn(nil)
	require.NoError(t, err)
	assert.True(t, called)
}

func TestServerService_Coverage_SetLoadFunc(t *testing.T) {
	svc := NewServerService()
	assert.Nil(t, svc.loadFn)

	svc.SetLoadFunc(func() ([]*ServerEntry, error) {
		return []*ServerEntry{{URL: "https://test.example.com"}}, nil
	})
	assert.NotNil(t, svc.loadFn)
}

// ---------------------------------------------------------------------------
// LoadServers tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_LoadServers_NilLoadFunc(t *testing.T) {
	svc := NewServerService()
	err := svc.LoadServers()
	require.NoError(t, err)
}

func TestServerService_Coverage_LoadServers_Error(t *testing.T) {
	svc := NewServerService()
	loadErr := errors.New("load failed")
	svc.SetLoadFunc(func() ([]*ServerEntry, error) {
		return nil, loadErr
	})

	err := svc.LoadServers()
	assert.Equal(t, loadErr, err)
}

func TestServerService_Coverage_LoadServers_Success(t *testing.T) {
	svc := NewServerService()
	servers := []*ServerEntry{
		{URL: "https://server1.example.com", Protocol: "rest", TLSEnabled: true},
		{URL: "https://server2.example.com", Protocol: "grpc", TLSEnabled: false},
	}
	svc.SetLoadFunc(func() ([]*ServerEntry, error) {
		return servers, nil
	})

	err := svc.LoadServers()
	require.NoError(t, err)

	// Verify servers are loaded.
	assert.Len(t, svc.servers, 2)
	assert.NotNil(t, svc.servers["https://server1.example.com"])
	assert.NotNil(t, svc.servers["https://server2.example.com"])

	// Verify connection info is initialized.
	info1 := svc.connInfo["https://server1.example.com"]
	require.NotNil(t, info1)
	assert.Equal(t, "disconnected", info1.State)
	assert.Equal(t, "rest", info1.Protocol)
	assert.True(t, info1.TLS)

	info2 := svc.connInfo["https://server2.example.com"]
	require.NotNil(t, info2)
	assert.Equal(t, "grpc", info2.Protocol)
	assert.False(t, info2.TLS)
}

// ---------------------------------------------------------------------------
// ListServers tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_ListServers_Empty(t *testing.T) {
	svc := NewServerService()
	result, err := svc.ListServers()
	require.NoError(t, err)
	assert.Empty(t, result)
}

func TestServerService_Coverage_ListServers_WithServers(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{
		URL:      "https://server1.example.com",
		Protocol: "rest",
	})
	require.NoError(t, err)

	result, err := svc.ListServers()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "https://server1.example.com", result[0].URL)
	assert.Equal(t, "disconnected", result[0].State)
}

func TestServerService_Coverage_ListServers_NilConnInfoFallback(t *testing.T) {
	svc := NewServerService()
	// Manually insert server without corresponding connInfo.
	svc.servers["https://manual.example.com"] = &ServerEntry{
		URL:        "https://manual.example.com",
		Protocol:   "grpc",
		TLSEnabled: true,
	}

	result, err := svc.ListServers()
	require.NoError(t, err)
	require.Len(t, result, 1)
	assert.Equal(t, "disconnected", result[0].State)
	assert.Equal(t, "grpc", result[0].Protocol)
	assert.True(t, result[0].TLS)
}

// ---------------------------------------------------------------------------
// AddServer tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_AddServer_NilEntry(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(nil)
	assert.ErrorIs(t, err, ErrServerInvalidURL)
}

func TestServerService_Coverage_AddServer_EmptyURL(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: ""})
	assert.ErrorIs(t, err, ErrServerInvalidURL)
}

func TestServerService_Coverage_AddServer_Duplicate(t *testing.T) {
	svc := NewServerService()
	entry := &ServerEntry{URL: "https://test.example.com", Protocol: "rest"}

	err := svc.AddServer(entry)
	require.NoError(t, err)

	err = svc.AddServer(entry)
	assert.ErrorIs(t, err, ErrServerAlreadyExists)
}

func TestServerService_Coverage_AddServer_Success(t *testing.T) {
	svc := NewServerService()
	entry := &ServerEntry{
		URL:        "https://test.example.com",
		Protocol:   "grpc",
		TLSEnabled: true,
		Name:       "Test Server",
	}

	err := svc.AddServer(entry)
	require.NoError(t, err)

	assert.NotNil(t, svc.servers["https://test.example.com"])
	assert.False(t, entry.AddedAt.IsZero(), "AddedAt should be set")

	info := svc.connInfo["https://test.example.com"]
	require.NotNil(t, info)
	assert.Equal(t, "disconnected", info.State)
	assert.Equal(t, "grpc", info.Protocol)
	assert.True(t, info.TLS)
}

func TestServerService_Coverage_AddServer_PersistsCalled(t *testing.T) {
	svc := NewServerService()
	var savedServers []*ServerEntry
	svc.SetSaveFunc(func(servers []*ServerEntry) error {
		savedServers = servers
		return nil
	})

	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)
	require.Len(t, savedServers, 1)
	assert.Equal(t, "https://test.example.com", savedServers[0].URL)
}

func TestServerService_Coverage_AddServer_PersistError(t *testing.T) {
	svc := NewServerService()
	svc.SetSaveFunc(func(_ []*ServerEntry) error {
		return errors.New("disk full")
	})

	// Save error is logged but does not fail AddServer.
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	// Server should still be added despite save error.
	assert.NotNil(t, svc.servers["https://test.example.com"])
}

// ---------------------------------------------------------------------------
// RemoveServer tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_RemoveServer_NotFound(t *testing.T) {
	svc := NewServerService()
	err := svc.RemoveServer("https://nonexistent.example.com")
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_RemoveServer_Success(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	err = svc.RemoveServer("https://test.example.com")
	require.NoError(t, err)

	assert.Nil(t, svc.servers["https://test.example.com"])
	assert.Nil(t, svc.connInfo["https://test.example.com"])
}

func TestServerService_Coverage_RemoveServer_PersistsCalled(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://a.example.com", Protocol: "rest"})
	require.NoError(t, err)
	err = svc.AddServer(&ServerEntry{URL: "https://b.example.com", Protocol: "grpc"})
	require.NoError(t, err)

	var savedServers []*ServerEntry
	svc.SetSaveFunc(func(servers []*ServerEntry) error {
		savedServers = servers
		return nil
	})

	err = svc.RemoveServer("https://a.example.com")
	require.NoError(t, err)
	require.Len(t, savedServers, 1)
	assert.Equal(t, "https://b.example.com", savedServers[0].URL)
}

func TestServerService_Coverage_RemoveServer_PersistError(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	svc.SetSaveFunc(func(_ []*ServerEntry) error {
		return errors.New("write error")
	})

	// Save error is logged but does not fail RemoveServer.
	err = svc.RemoveServer("https://test.example.com")
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// Connect tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_Connect_NotFound(t *testing.T) {
	svc := NewServerService()
	err := svc.Connect("https://nonexistent.example.com")
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_Connect_NoConnector(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	err = svc.Connect("https://test.example.com")
	assert.ErrorIs(t, err, ErrServerConnectFailed)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "error", info.State)
	assert.Equal(t, "no connector configured", info.Error)
}

func TestServerService_Coverage_Connect_ConnectorError(t *testing.T) {
	svc := NewServerService()
	svc.SetConnector(&mockServerConnector{
		connectErr: errors.New("connection refused"),
	})

	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	err = svc.Connect("https://test.example.com")
	assert.ErrorIs(t, err, ErrServerConnectFailed)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "error", info.State)
	assert.Contains(t, info.Error, "connection refused")
}

func TestServerService_Coverage_Connect_Success(t *testing.T) {
	svc := NewServerService()
	connector := &mockServerConnector{
		connInfo: &ConnectionInfo{Version: "2.0.0"},
	}
	svc.SetConnector(connector)

	err := svc.AddServer(&ServerEntry{
		URL:        "https://test.example.com",
		Protocol:   "rest",
		TLSEnabled: true,
	})
	require.NoError(t, err)

	err = svc.Connect("https://test.example.com")
	require.NoError(t, err)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "connected", info.State)
	assert.Empty(t, info.Error)
	assert.Equal(t, "2.0.0", info.Version)
}

func TestServerService_Coverage_Connect_SuccessNilConnInfo(t *testing.T) {
	svc := NewServerService()
	connector := &mockServerConnector{
		connInfo: nil, // No connection info returned.
	}
	svc.SetConnector(connector)

	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	err = svc.Connect("https://test.example.com")
	require.NoError(t, err)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "connected", info.State)
	assert.Empty(t, info.Version, "version should be empty when connInfo is nil")
}

// ---------------------------------------------------------------------------
// Disconnect tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_Disconnect_NotFound(t *testing.T) {
	svc := NewServerService()
	err := svc.Disconnect("https://nonexistent.example.com")
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_Disconnect_NoConnector(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	// No connector set - should still succeed (just sets state to disconnected).
	err = svc.Disconnect("https://test.example.com")
	require.NoError(t, err)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "disconnected", info.State)
}

func TestServerService_Coverage_Disconnect_ConnectorError(t *testing.T) {
	svc := NewServerService()
	svc.SetConnector(&mockServerConnector{
		disconnErr: errors.New("disconnect error"),
	})

	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	// Disconnect errors are logged but not returned.
	err = svc.Disconnect("https://test.example.com")
	require.NoError(t, err)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "disconnected", info.State)
}

func TestServerService_Coverage_Disconnect_Success(t *testing.T) {
	svc := NewServerService()
	connector := &mockServerConnector{connInfo: &ConnectionInfo{Version: "1.0"}}
	svc.SetConnector(connector)

	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	// First connect.
	err = svc.Connect("https://test.example.com")
	require.NoError(t, err)
	assert.Equal(t, "connected", svc.connInfo["https://test.example.com"].State)

	// Then disconnect.
	err = svc.Disconnect("https://test.example.com")
	require.NoError(t, err)

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "disconnected", info.State)
	assert.Empty(t, info.Error)
}

// ---------------------------------------------------------------------------
// GetConnectionStatus tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_GetConnectionStatus_NotFound(t *testing.T) {
	svc := NewServerService()
	info, err := svc.GetConnectionStatus("https://nonexistent.example.com")
	assert.Nil(t, info)
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_GetConnectionStatus_Success(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "grpc", TLSEnabled: true})
	require.NoError(t, err)

	info, err := svc.GetConnectionStatus("https://test.example.com")
	require.NoError(t, err)
	assert.Equal(t, "https://test.example.com", info.URL)
	assert.Equal(t, "disconnected", info.State)
	assert.Equal(t, "grpc", info.Protocol)
	assert.True(t, info.TLS)
}

// ---------------------------------------------------------------------------
// GetServer tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_GetServer_NotFound(t *testing.T) {
	svc := NewServerService()
	srv, err := svc.GetServer("https://nonexistent.example.com")
	assert.Nil(t, srv)
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_GetServer_Success(t *testing.T) {
	svc := NewServerService()
	entry := &ServerEntry{
		URL:        "https://test.example.com",
		Protocol:   "rest",
		TLSEnabled: true,
		Name:       "Test Server",
		SPKIPin:    "sha256//abc123",
	}
	err := svc.AddServer(entry)
	require.NoError(t, err)

	srv, err := svc.GetServer("https://test.example.com")
	require.NoError(t, err)
	assert.Equal(t, "Test Server", srv.Name)
	assert.Equal(t, "rest", srv.Protocol)
	assert.True(t, srv.TLSEnabled)
	assert.Equal(t, "sha256//abc123", srv.SPKIPin)
}

// ---------------------------------------------------------------------------
// UpdateServer tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_UpdateServer_NilEntry(t *testing.T) {
	svc := NewServerService()
	err := svc.UpdateServer(nil)
	assert.ErrorIs(t, err, ErrServerInvalidURL)
}

func TestServerService_Coverage_UpdateServer_EmptyURL(t *testing.T) {
	svc := NewServerService()
	err := svc.UpdateServer(&ServerEntry{URL: ""})
	assert.ErrorIs(t, err, ErrServerInvalidURL)
}

func TestServerService_Coverage_UpdateServer_NotFound(t *testing.T) {
	svc := NewServerService()
	err := svc.UpdateServer(&ServerEntry{URL: "https://nonexistent.example.com"})
	assert.ErrorIs(t, err, ErrServerNotFound)
}

func TestServerService_Coverage_UpdateServer_Success(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{
		URL:      "https://test.example.com",
		Protocol: "rest",
		Name:     "Old Name",
	})
	require.NoError(t, err)

	err = svc.UpdateServer(&ServerEntry{
		URL:        "https://test.example.com",
		Protocol:   "grpc",
		Name:       "New Name",
		TLSEnabled: true,
	})
	require.NoError(t, err)

	srv := svc.servers["https://test.example.com"]
	assert.Equal(t, "New Name", srv.Name)
	assert.Equal(t, "grpc", srv.Protocol)
	assert.True(t, srv.TLSEnabled)
}

func TestServerService_Coverage_UpdateServer_PersistsCalled(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	var savedServers []*ServerEntry
	svc.SetSaveFunc(func(servers []*ServerEntry) error {
		savedServers = servers
		return nil
	})

	err = svc.UpdateServer(&ServerEntry{URL: "https://test.example.com", Protocol: "grpc"})
	require.NoError(t, err)
	require.Len(t, savedServers, 1)
	assert.Equal(t, "grpc", savedServers[0].Protocol)
}

func TestServerService_Coverage_UpdateServer_PersistError(t *testing.T) {
	svc := NewServerService()
	err := svc.AddServer(&ServerEntry{URL: "https://test.example.com", Protocol: "rest"})
	require.NoError(t, err)

	svc.SetSaveFunc(func(_ []*ServerEntry) error {
		return errors.New("write error")
	})

	// Save error is logged but does not fail UpdateServer.
	err = svc.UpdateServer(&ServerEntry{URL: "https://test.example.com", Protocol: "grpc"})
	require.NoError(t, err)
}

// ---------------------------------------------------------------------------
// AutoConnectServers tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_AutoConnectServers_NoServers(t *testing.T) {
	svc := NewServerService()
	// Should not panic with no servers.
	svc.AutoConnectServers()
}

func TestServerService_Coverage_AutoConnectServers_NoAutoConnect(t *testing.T) {
	svc := NewServerService()
	connector := &mockServerConnector{}
	svc.SetConnector(connector)

	err := svc.AddServer(&ServerEntry{
		URL:         "https://test.example.com",
		Protocol:    "rest",
		AutoConnect: false,
	})
	require.NoError(t, err)

	svc.AutoConnectServers()

	info := svc.connInfo["https://test.example.com"]
	assert.Equal(t, "disconnected", info.State)
}

func TestServerService_Coverage_AutoConnectServers_WithAutoConnect(t *testing.T) {
	svc := NewServerService()
	connector := &mockServerConnector{
		connInfo: &ConnectionInfo{Version: "1.0"},
	}
	svc.SetConnector(connector)

	err := svc.AddServer(&ServerEntry{
		URL:         "https://auto.example.com",
		Protocol:    "grpc",
		AutoConnect: true,
	})
	require.NoError(t, err)

	err = svc.AddServer(&ServerEntry{
		URL:         "https://manual.example.com",
		Protocol:    "rest",
		AutoConnect: false,
	})
	require.NoError(t, err)

	svc.AutoConnectServers()

	// Auto-connect server should be connected.
	autoInfo := svc.connInfo["https://auto.example.com"]
	assert.Equal(t, "connected", autoInfo.State)

	// Manual server should remain disconnected.
	manualInfo := svc.connInfo["https://manual.example.com"]
	assert.Equal(t, "disconnected", manualInfo.State)
}

func TestServerService_Coverage_AutoConnectServers_ConnectError(t *testing.T) {
	svc := NewServerService()
	svc.SetConnector(&mockServerConnector{
		connectErr: errors.New("timeout"),
	})

	err := svc.AddServer(&ServerEntry{
		URL:         "https://fail.example.com",
		Protocol:    "rest",
		AutoConnect: true,
	})
	require.NoError(t, err)

	// Should not panic even when connect fails.
	svc.AutoConnectServers()

	info := svc.connInfo["https://fail.example.com"]
	assert.Equal(t, "error", info.State)
}

// ---------------------------------------------------------------------------
// Error sentinel tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_ErrorSentinels(t *testing.T) {
	sentinels := []struct {
		err     error
		message string
	}{
		{ErrServerNotFound, "server_service: server not found"},
		{ErrServerAlreadyExists, "server_service: server already exists"},
		{ErrServerConnectFailed, "server_service: connection failed"},
		{ErrServerInvalidURL, "server_service: invalid server URL"},
	}
	for _, s := range sentinels {
		assert.NotNil(t, s.err)
		assert.Equal(t, s.message, s.err.Error())
	}

	// Verify sentinels are distinct.
	assert.NotErrorIs(t, ErrServerNotFound, ErrServerAlreadyExists)
	assert.NotErrorIs(t, ErrServerConnectFailed, ErrServerInvalidURL)
}

// ---------------------------------------------------------------------------
// ServerEntry and ServerConnectionInfo type tests
// ---------------------------------------------------------------------------

func TestServerService_Coverage_ServerEntryFields(t *testing.T) {
	entry := &ServerEntry{
		URL:         "https://test.example.com",
		Name:        "Test",
		Protocol:    "quic",
		TLSEnabled:  true,
		SPKIPin:     "sha256//pin",
		AutoConnect: true,
	}
	assert.Equal(t, "https://test.example.com", entry.URL)
	assert.Equal(t, "Test", entry.Name)
	assert.Equal(t, "quic", entry.Protocol)
	assert.True(t, entry.TLSEnabled)
	assert.Equal(t, "sha256//pin", entry.SPKIPin)
	assert.True(t, entry.AutoConnect)
}

func TestServerService_Coverage_ServerConnectionInfoFields(t *testing.T) {
	info := &ServerConnectionInfo{
		URL:          "https://test.example.com",
		State:        "connected",
		Version:      "1.0.0",
		Protocol:     "grpc",
		TLS:          true,
		Error:        "",
		BackendCount: 5,
	}
	assert.Equal(t, "https://test.example.com", info.URL)
	assert.Equal(t, "connected", info.State)
	assert.Equal(t, "1.0.0", info.Version)
	assert.Equal(t, "grpc", info.Protocol)
	assert.True(t, info.TLS)
	assert.Empty(t, info.Error)
	assert.Equal(t, 5, info.BackendCount)
}
