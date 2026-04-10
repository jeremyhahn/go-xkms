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
	"log/slog"
	"sync"
	"time"
)

// Server service errors.
var (
	ErrServerNotFound      = errors.New("server_service: server not found")
	ErrServerAlreadyExists = errors.New("server_service: server already exists")
	ErrServerConnectFailed = errors.New("server_service: connection failed")
	ErrServerInvalidURL    = errors.New("server_service: invalid server URL")
)

// ServerEntry describes a configured xkmsd server.
type ServerEntry struct {
	URL         string    `json:"url"`
	Name        string    `json:"name"`
	Protocol    string    `json:"protocol"` // rest, grpc, quic, mcp
	TLSEnabled  bool      `json:"tls_enabled"`
	SPKIPin     string    `json:"spki_pin,omitempty"`
	AutoConnect bool      `json:"auto_connect"`
	AddedAt     time.Time `json:"added_at"`
}

// ServerConnectionInfo describes the connection state for a server.
type ServerConnectionInfo struct {
	URL          string `json:"url"`
	State        string `json:"state"` // connected, disconnected, connecting, error
	Version      string `json:"version,omitempty"`
	Protocol     string `json:"protocol"`
	TLS          bool   `json:"tls"`
	Error        string `json:"error,omitempty"`
	BackendCount int    `json:"backend_count"`
}

// ServerConnector provides server connection management.
type ServerConnector interface {
	Connect(ctx context.Context, url, protocol string, tls bool) error
	Disconnect() error
	IsConnected() bool
	GetConnectionInfo() *ConnectionInfo
}

// ServerService manages multiple xkmsd server connections.
type ServerService struct {
	ctx       context.Context
	log       *slog.Logger
	servers   map[string]*ServerEntry
	connInfo  map[string]*ServerConnectionInfo
	mu        sync.RWMutex
	connector ServerConnector
	saveFn    func([]*ServerEntry) error
	loadFn    func() ([]*ServerEntry, error)
}

// NewServerService creates a new ServerService.
func NewServerService() *ServerService {
	return &ServerService{
		log:      slog.Default().With("component", "server_service"),
		servers:  make(map[string]*ServerEntry),
		connInfo: make(map[string]*ServerConnectionInfo),
	}
}

// SetContext is called by the Wails startup lifecycle hook.
func (s *ServerService) SetContext(ctx context.Context) {
	s.ctx = ctx
}

// SetConnector sets the server connector for managing connections.
func (s *ServerService) SetConnector(connector ServerConnector) {
	s.connector = connector
}

// SetSaveFunc sets the function to persist server list.
func (s *ServerService) SetSaveFunc(fn func([]*ServerEntry) error) {
	s.saveFn = fn
}

// SetLoadFunc sets the function to load server list.
func (s *ServerService) SetLoadFunc(fn func() ([]*ServerEntry, error)) {
	s.loadFn = fn
}

// LoadServers loads the server list from persistent storage.
func (s *ServerService) LoadServers() error {
	if s.loadFn == nil {
		return nil
	}
	servers, err := s.loadFn()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, srv := range servers {
		s.servers[srv.URL] = srv
		s.connInfo[srv.URL] = &ServerConnectionInfo{
			URL:      srv.URL,
			State:    "disconnected",
			Protocol: srv.Protocol,
			TLS:      srv.TLSEnabled,
		}
	}
	return nil
}

// ListServers returns all configured servers with their connection status.
func (s *ServerService) ListServers() ([]*ServerConnectionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	result := make([]*ServerConnectionInfo, 0, len(s.servers))
	for url, srv := range s.servers {
		info := s.connInfo[url]
		if info == nil {
			info = &ServerConnectionInfo{
				URL:      srv.URL,
				State:    "disconnected",
				Protocol: srv.Protocol,
				TLS:      srv.TLSEnabled,
			}
		}
		result = append(result, info)
	}
	return result, nil
}

// AddServer adds a new server to the configuration.
func (s *ServerService) AddServer(entry *ServerEntry) error {
	if entry == nil || entry.URL == "" {
		return ErrServerInvalidURL
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.servers[entry.URL]; exists {
		return ErrServerAlreadyExists
	}

	entry.AddedAt = time.Now().UTC()
	s.servers[entry.URL] = entry
	s.connInfo[entry.URL] = &ServerConnectionInfo{
		URL:      entry.URL,
		State:    "disconnected",
		Protocol: entry.Protocol,
		TLS:      entry.TLSEnabled,
	}

	// Persist the updated server list.
	if s.saveFn != nil {
		servers := make([]*ServerEntry, 0, len(s.servers))
		for _, srv := range s.servers {
			servers = append(servers, srv)
		}
		if err := s.saveFn(servers); err != nil {
			s.log.Warn("failed to save server list", "error", err)
		}
	}

	return nil
}

// RemoveServer removes a server from the configuration.
func (s *ServerService) RemoveServer(url string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.servers[url]; !exists {
		return ErrServerNotFound
	}

	delete(s.servers, url)
	delete(s.connInfo, url)

	// Persist the updated server list.
	if s.saveFn != nil {
		servers := make([]*ServerEntry, 0, len(s.servers))
		for _, srv := range s.servers {
			servers = append(servers, srv)
		}
		if err := s.saveFn(servers); err != nil {
			s.log.Warn("failed to save server list", "error", err)
		}
	}

	return nil
}

// Connect establishes a connection to the specified server.
func (s *ServerService) Connect(url string) error {
	s.mu.Lock()
	srv, exists := s.servers[url]
	if !exists {
		s.mu.Unlock()
		return ErrServerNotFound
	}
	info := s.connInfo[url]
	info.State = "connecting"
	s.mu.Unlock()

	if s.connector == nil {
		s.mu.Lock()
		info.State = "error"
		info.Error = "no connector configured"
		s.mu.Unlock()
		return ErrServerConnectFailed
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := s.connector.Connect(ctx, srv.URL, srv.Protocol, srv.TLSEnabled); err != nil {
		s.mu.Lock()
		info.State = "error"
		info.Error = err.Error()
		s.mu.Unlock()
		return ErrServerConnectFailed
	}

	s.mu.Lock()
	info.State = "connected"
	info.Error = ""
	if connInfo := s.connector.GetConnectionInfo(); connInfo != nil {
		info.Version = connInfo.Version
	}
	s.mu.Unlock()

	s.log.Info("connected to server", "url", url)
	return nil
}

// Disconnect terminates the connection to the specified server.
func (s *ServerService) Disconnect(url string) error {
	s.mu.Lock()
	if _, exists := s.servers[url]; !exists {
		s.mu.Unlock()
		return ErrServerNotFound
	}
	info := s.connInfo[url]
	s.mu.Unlock()

	if s.connector != nil {
		if err := s.connector.Disconnect(); err != nil {
			s.log.Warn("disconnect error", "url", url, "error", err)
		}
	}

	s.mu.Lock()
	info.State = "disconnected"
	info.Error = ""
	s.mu.Unlock()

	s.log.Info("disconnected from server", "url", url)
	return nil
}

// GetConnectionStatus returns the connection status for a specific server.
func (s *ServerService) GetConnectionStatus(url string) (*ServerConnectionInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	info, exists := s.connInfo[url]
	if !exists {
		return nil, ErrServerNotFound
	}
	return info, nil
}

// GetServer returns a server entry by URL.
func (s *ServerService) GetServer(url string) (*ServerEntry, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	srv, exists := s.servers[url]
	if !exists {
		return nil, ErrServerNotFound
	}
	return srv, nil
}

// UpdateServer updates a server entry.
func (s *ServerService) UpdateServer(entry *ServerEntry) error {
	if entry == nil || entry.URL == "" {
		return ErrServerInvalidURL
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.servers[entry.URL]; !exists {
		return ErrServerNotFound
	}

	s.servers[entry.URL] = entry

	// Persist the updated server list.
	if s.saveFn != nil {
		servers := make([]*ServerEntry, 0, len(s.servers))
		for _, srv := range s.servers {
			servers = append(servers, srv)
		}
		if err := s.saveFn(servers); err != nil {
			s.log.Warn("failed to save server list", "error", err)
		}
	}

	return nil
}

// AutoConnectServers connects to all servers marked for auto-connect.
func (s *ServerService) AutoConnectServers() {
	s.mu.RLock()
	servers := make([]*ServerEntry, 0)
	for _, srv := range s.servers {
		if srv.AutoConnect {
			servers = append(servers, srv)
		}
	}
	s.mu.RUnlock()

	for _, srv := range servers {
		if err := s.Connect(srv.URL); err != nil {
			s.log.Warn("auto-connect failed", "url", srv.URL, "error", err)
		}
	}
}
