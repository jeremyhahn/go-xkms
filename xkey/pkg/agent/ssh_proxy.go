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
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
)

// SSHProxy proxies SSH agent protocol calls to the master xKey process.
// It creates a local Unix socket that SSH clients use transparently via
// SSH_AUTH_SOCK. All cryptographic operations are forwarded over the
// gRPC connection to the master; no key material is stored locally.
// Thread-safe.
type SSHProxy struct {
	socketPath string
	client     *Client
	logger     *slog.Logger
	listener   net.Listener
	running    atomic.Bool
	done       chan struct{}
	conns      map[net.Conn]struct{}
	mu         sync.Mutex
	wg         sync.WaitGroup
}

// NewSSHProxy creates a new SSH proxy that listens on the given Unix
// socket path and forwards requests through the given client.
func NewSSHProxy(socketPath string, client *Client, logger *slog.Logger) (*SSHProxy, error) {
	if socketPath == "" {
		return nil, ErrSocketPath
	}
	if client == nil {
		return nil, ErrNilClient
	}
	if logger == nil {
		return nil, ErrNilLogger
	}
	return &SSHProxy{
		socketPath: socketPath,
		client:     client,
		logger:     logger,
		done:       make(chan struct{}),
		conns:      make(map[net.Conn]struct{}),
	}, nil
}

// Start begins listening on the Unix socket for SSH agent requests.
// Each connection is proxied to the master agent server via the gRPC
// client connection.
func (p *SSHProxy) Start() error {
	if p.running.Load() {
		return ErrServerAlreadyRunning
	}

	// Create the socket directory if it does not exist.
	sockDir := filepath.Dir(p.socketPath)
	if err := os.MkdirAll(sockDir, 0700); err != nil {
		return &AgentError{Operation: "start_ssh_proxy", Err: ErrSocketPath}
	}

	// Remove stale socket.
	if _, err := os.Stat(p.socketPath); err == nil {
		conn, dialErr := net.Dial("unix", p.socketPath)
		if dialErr == nil {
			conn.Close()
			return ErrServerAlreadyRunning
		}
		os.Remove(p.socketPath)
	}

	listener, err := net.Listen("unix", p.socketPath)
	if err != nil {
		return &AgentError{Operation: "start_ssh_proxy", Err: err}
	}

	// Set socket permissions to owner-only.
	if err := os.Chmod(p.socketPath, 0600); err != nil {
		listener.Close()
		os.Remove(p.socketPath)
		return &AgentError{Operation: "start_ssh_proxy", Err: err}
	}

	p.mu.Lock()
	p.listener = listener
	p.done = make(chan struct{})
	p.conns = make(map[net.Conn]struct{})
	p.mu.Unlock()

	p.running.Store(true)
	p.logger.Info("SSH proxy started", "socket", p.socketPath)

	go p.acceptLoop()

	return nil
}

// Stop shuts down the SSH proxy and removes the socket file.
func (p *SSHProxy) Stop() error {
	if !p.running.CompareAndSwap(true, false) {
		return ErrServerNotStarted
	}

	p.logger.Info("stopping SSH proxy")

	p.mu.Lock()
	if p.listener != nil {
		p.listener.Close()
	}
	for conn := range p.conns {
		conn.Close()
	}
	p.mu.Unlock()

	// Wait for all connection handlers to finish.
	p.wg.Wait()
	close(p.done)

	os.Remove(p.socketPath)
	p.logger.Info("SSH proxy stopped")
	return nil
}

// SocketPath returns the path to the SSH agent socket.
func (p *SSHProxy) SocketPath() string {
	return p.socketPath
}

// IsRunning reports whether the SSH proxy is currently listening.
func (p *SSHProxy) IsRunning() bool {
	return p.running.Load()
}

// acceptLoop accepts connections on the Unix socket and spawns a handler
// goroutine for each.
func (p *SSHProxy) acceptLoop() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if !p.running.Load() {
				return
			}
			p.logger.Debug("accept error", "error", err)
			continue
		}

		p.mu.Lock()
		p.conns[conn] = struct{}{}
		p.mu.Unlock()

		p.wg.Add(1)
		go p.handleConnection(conn)
	}
}

// handleConnection proxies a single SSH agent connection to the master.
// The data is forwarded bidirectionally between the local Unix socket
// connection and a new stream on the gRPC connection.
//
// For the initial implementation, this uses a simple byte-level proxy
// pattern. A future iteration will parse the SSH agent wire protocol
// to provide per-operation logging and access control.
func (p *SSHProxy) handleConnection(conn net.Conn) {
	defer func() {
		p.mu.Lock()
		delete(p.conns, conn)
		p.mu.Unlock()
		conn.Close()
		p.wg.Done()
	}()

	if !p.client.IsConnected() {
		p.logger.Warn("master not connected, rejecting SSH agent connection")
		return
	}

	// Create a connection to the master's SSH agent socket over the
	// gRPC transport. In the current implementation, we proxy raw bytes
	// to the master address. A more sophisticated approach using gRPC
	// streaming will be implemented when the agent protocol service
	// definition is available.
	masterConn, err := net.Dial("tcp", p.client.config.MasterAddress)
	if err != nil {
		p.logger.Warn("failed to connect to master SSH agent",
			"error", err)
		return
	}
	defer masterConn.Close()

	// Bidirectional proxy.
	errCh := make(chan error, 2)
	go func() {
		_, copyErr := io.Copy(masterConn, conn)
		errCh <- copyErr
	}()
	go func() {
		_, copyErr := io.Copy(conn, masterConn)
		errCh <- copyErr
	}()

	// Wait for either direction to finish.
	<-errCh
}
