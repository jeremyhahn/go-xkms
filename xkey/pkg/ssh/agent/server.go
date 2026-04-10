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

package agent

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/ssh/agent"
)

// SSHAgent defines the interface required by the SSH agent server.
// Both XKMSAgent and Agent implement this interface.
type SSHAgent interface {
	agent.ExtendedAgent
	Close() error
}

// Server serves the SSH agent over a Unix domain socket.
type Server struct {
	agent    SSHAgent
	listener net.Listener
	logger   *slog.Logger
	sockPath string

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	closed atomic.Bool
	wg     sync.WaitGroup
}

// ServerConfig configures the SSH agent server.
type ServerConfig struct {
	// SocketPath is the Unix socket path for the agent.
	// Defaults to $XDG_RUNTIME_DIR/xkey/ssh-agent.sock
	SocketPath string

	// Logger is the structured logger.
	Logger *slog.Logger
}

// NewServer creates a new SSH agent server.
// The agent parameter accepts any implementation of SSHAgent,
// including XKMSAgent (server mode) and Agent (standalone/server modes).
func NewServer(ag SSHAgent, cfg *ServerConfig) (*Server, error) {
	if cfg == nil {
		cfg = &ServerConfig{}
	}

	sockPath := cfg.SocketPath
	if sockPath == "" {
		sockPath = DefaultSocketPath()
	}

	logger := cfg.Logger
	if logger == nil {
		logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}

	// Ensure socket directory exists
	sockDir := filepath.Dir(sockPath)
	if err := os.MkdirAll(sockDir, 0700); err != nil {
		return nil, fmt.Errorf("ssh/agent: failed to create socket directory: %w", err)
	}

	// Remove stale socket if it exists
	if _, err := os.Stat(sockPath); err == nil {
		// Check if another agent is running
		conn, err := net.Dial("unix", sockPath)
		if err == nil {
			conn.Close()
			return nil, ErrAgentAlreadyRunning
		}
		// Stale socket, remove it
		os.Remove(sockPath)
	}

	listener, err := net.Listen("unix", sockPath)
	if err != nil {
		return nil, fmt.Errorf("ssh/agent: failed to listen on socket: %w", err)
	}

	// Set socket permissions (owner read/write only)
	if err := os.Chmod(sockPath, 0600); err != nil {
		listener.Close()
		os.Remove(sockPath)
		return nil, fmt.Errorf("ssh/agent: failed to set socket permissions: %w", err)
	}

	return &Server{
		agent:    ag,
		listener: listener,
		logger:   logger,
		sockPath: sockPath,
		conns:    make(map[net.Conn]struct{}),
	}, nil
}

// Serve accepts connections and serves the SSH agent protocol.
// This blocks until the context is cancelled or an error occurs.
func (s *Server) Serve(ctx context.Context) error {
	s.logger.Info("SSH agent listening", "socket", s.sockPath)

	// Create a channel for accept errors
	errCh := make(chan error, 1)

	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				if s.closed.Load() {
					return
				}
				select {
				case errCh <- err:
				default:
				}
				continue
			}

			s.mu.Lock()
			if s.closed.Load() {
				s.mu.Unlock()
				conn.Close()
				return
			}
			s.conns[conn] = struct{}{}
			s.wg.Add(1)
			s.mu.Unlock()

			go s.handleConnection(conn)
		}
	}()

	select {
	case <-ctx.Done():
		s.logger.Info("shutting down SSH agent")
		return s.Close()
	case err := <-errCh:
		return fmt.Errorf("ssh/agent: accept error: %w", err)
	}
}

// handleConnection handles a single client connection.
func (s *Server) handleConnection(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
		s.wg.Done()
	}()

	// agent.ServeAgent handles all protocol details
	if err := agent.ServeAgent(s.agent, conn); err != nil {
		if err != io.EOF {
			s.logger.Debug("client disconnected", "error", err)
		}
	}
}

// SocketPath returns the socket path for SSH_AUTH_SOCK.
func (s *Server) SocketPath() string {
	return s.sockPath
}

// Close stops the server and closes all connections.
func (s *Server) Close() error {
	if !s.closed.CompareAndSwap(false, true) {
		return nil // Already closed
	}

	s.logger.Info("closing SSH agent server")

	// Close the listener first to stop accepting new connections
	s.listener.Close()

	// Close all active connections
	s.mu.Lock()
	for conn := range s.conns {
		conn.Close()
	}
	s.mu.Unlock()

	// Wait for all handlers to finish
	s.wg.Wait()

	// Remove the socket file
	os.Remove(s.sockPath)

	// Close the agent
	return s.agent.Close()
}

// DefaultSocketPath returns the default socket path for the SSH agent.
func DefaultSocketPath() string {
	// Try XDG_RUNTIME_DIR first (standard on Linux)
	if xdgRuntime := os.Getenv("XDG_RUNTIME_DIR"); xdgRuntime != "" {
		return filepath.Join(xdgRuntime, "xkey", "ssh-agent.sock")
	}

	// Fallback to /tmp with user ID for isolation
	return filepath.Join(os.TempDir(), fmt.Sprintf("xkey-%d", os.Getuid()), "ssh-agent.sock")
}

// PrintEnvBash prints the SSH_AUTH_SOCK export command for bash/zsh.
func (s *Server) PrintEnvBash() string {
	return fmt.Sprintf("export SSH_AUTH_SOCK=%s", s.sockPath)
}

// PrintEnvFish prints the SSH_AUTH_SOCK export command for fish shell.
func (s *Server) PrintEnvFish() string {
	return fmt.Sprintf("set -gx SSH_AUTH_SOCK %s", s.sockPath)
}

// PrintEnvCsh prints the SSH_AUTH_SOCK export command for csh/tcsh.
func (s *Server) PrintEnvCsh() string {
	return fmt.Sprintf("setenv SSH_AUTH_SOCK %s", s.sockPath)
}
