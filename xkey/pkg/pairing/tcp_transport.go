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

package pairing

import (
	"context"
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

// TCP transport constants.
const (
	// DefaultTCPAddress is the default TCP address for ADB-forwarded connections.
	DefaultTCPAddress = "localhost:8444"

	// DefaultTCPConnectTimeout is the default timeout for establishing a TCP connection.
	DefaultTCPConnectTimeout = 10 * time.Second

	// DefaultTCPOperationTimeout is the default timeout for individual send/receive
	// operations. Set to 60 seconds to account for biometric verification on the phone.
	DefaultTCPOperationTimeout = 60 * time.Second

	// MaxTCPMessageSize is the maximum message size supported by the 2-byte
	// big-endian length-prefixed framing protocol.
	MaxTCPMessageSize = 65535

	// tcpFrameHeaderSize is the size of the length-prefix header in bytes.
	tcpFrameHeaderSize = 2
)

// Compile-time interface check.
var _ Transport = (*TCPTransport)(nil)

// TCPTransportConfig configures the TCP transport for phone communication.
type TCPTransportConfig struct {
	// Address is the TCP address to connect to (e.g., "localhost:8444").
	Address string

	// ConnectTimeout is the timeout for establishing the TCP connection.
	ConnectTimeout time.Duration

	// OperationTimeout is the timeout for individual send/receive operations.
	OperationTimeout time.Duration

	// Logger is the structured logger.
	Logger *slog.Logger
}

// DefaultTCPTransportConfig returns default configuration values.
func DefaultTCPTransportConfig() *TCPTransportConfig {
	return &TCPTransportConfig{
		Address:          DefaultTCPAddress,
		ConnectTimeout:   DefaultTCPConnectTimeout,
		OperationTimeout: DefaultTCPOperationTimeout,
		Logger:           slog.Default(),
	}
}

// TCPTransport implements Transport over TCP for USB/ADB connectivity.
// It uses 2-byte big-endian length-prefixed framing for message boundaries.
type TCPTransport struct {
	cfg *TCPTransportConfig
	log *slog.Logger

	// mu protects the net.Conn field.
	mu   sync.Mutex
	conn net.Conn

	connected atomic.Bool
	closed    atomic.Bool
}

// NewTCPTransport creates a new TCP transport with the given configuration.
// The transport is created in a disconnected state; call Connect to establish
// a connection to the phone.
func NewTCPTransport(cfg *TCPTransportConfig) (*TCPTransport, error) {
	if cfg == nil {
		cfg = DefaultTCPTransportConfig()
	}
	if cfg.Address == "" {
		cfg.Address = DefaultTCPAddress
	}
	if cfg.ConnectTimeout == 0 {
		cfg.ConnectTimeout = DefaultTCPConnectTimeout
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = DefaultTCPOperationTimeout
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	return &TCPTransport{
		cfg: cfg,
		log: cfg.Logger.With("component", "tcp_transport"),
	}, nil
}

// Connect establishes a TCP connection to the phone.
func (t *TCPTransport) Connect(ctx context.Context) error {
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if t.connected.Load() {
		return nil
	}

	t.log.Debug("connecting to phone via TCP", "address", t.cfg.Address)

	dialer := net.Dialer{Timeout: t.cfg.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", t.cfg.Address)
	if err != nil {
		t.log.Error("TCP connection failed", "address", t.cfg.Address, "error", err)
		return ErrConnectionFailed
	}

	t.mu.Lock()
	t.conn = conn
	t.mu.Unlock()

	t.connected.Store(true)
	t.log.Info("connected to phone via TCP", "address", t.cfg.Address)
	return nil
}

// Disconnect closes the TCP connection without closing the transport.
// The transport can be reconnected by calling Connect again.
func (t *TCPTransport) Disconnect() error {
	if !t.connected.Swap(false) {
		return nil
	}

	t.mu.Lock()
	conn := t.conn
	t.conn = nil
	t.mu.Unlock()

	if conn != nil {
		t.log.Debug("disconnecting TCP transport")
		return conn.Close()
	}
	return nil
}

// Send transmits a length-prefixed message to the connected phone.
func (t *TCPTransport) Send(ctx context.Context, message []byte) error {
	if t.closed.Load() {
		return ErrBackendClosed
	}
	if !t.connected.Load() {
		return ErrNotConnected
	}
	if len(message) > MaxTCPMessageSize {
		return ErrProtocolError
	}

	// Build the framed message: [2-byte big-endian length][payload]
	frame := make([]byte, tcpFrameHeaderSize+len(message))
	binary.BigEndian.PutUint16(frame[:tcpFrameHeaderSize], uint16(len(message)))
	copy(frame[tcpFrameHeaderSize:], message)

	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return ErrNotConnected
	}

	// Determine the deadline from either the context or the configured operation timeout.
	deadline := t.resolveDeadline(ctx)
	if err := conn.SetWriteDeadline(deadline); err != nil {
		return ErrConnectionFailed
	}

	if _, err := conn.Write(frame); err != nil {
		t.handleWriteError(err)
		if isTimeoutError(err) {
			return ErrTimeout
		}
		return ErrConnectionFailed
	}

	t.log.Debug("sent TCP message", "size", len(message))
	return nil
}

// Receive reads a complete length-prefixed message from the phone.
func (t *TCPTransport) Receive(ctx context.Context) ([]byte, error) {
	if t.closed.Load() {
		return nil, ErrBackendClosed
	}
	if !t.connected.Load() {
		return nil, ErrNotConnected
	}

	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, ErrNotConnected
	}

	// Determine the deadline from either the context or the configured operation timeout.
	deadline := t.resolveDeadline(ctx)
	if err := conn.SetReadDeadline(deadline); err != nil {
		return nil, ErrConnectionFailed
	}

	// Read the 2-byte length header.
	header := make([]byte, tcpFrameHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, t.classifyReadError(err)
	}

	length := binary.BigEndian.Uint16(header)
	if length == 0 {
		return []byte{}, nil
	}

	// Read the payload.
	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, t.classifyReadError(err)
	}

	t.log.Debug("received TCP message", "size", length)
	return payload, nil
}

// SendAndReceive sends a message and waits for the response.
func (t *TCPTransport) SendAndReceive(ctx context.Context, message []byte) ([]byte, error) {
	if err := t.Send(ctx, message); err != nil {
		return nil, err
	}
	return t.Receive(ctx)
}

// IsConnected returns true if the transport is currently connected.
func (t *TCPTransport) IsConnected() bool {
	return t.connected.Load() && !t.closed.Load()
}

// Close closes the transport permanently and releases all resources.
// After Close, the transport cannot be reconnected.
func (t *TCPTransport) Close() error {
	if t.closed.Swap(true) {
		return nil
	}

	t.log.Debug("closing TCP transport")
	return t.Disconnect()
}

// resolveDeadline returns the earlier of the context deadline or the
// configured operation timeout from now.
func (t *TCPTransport) resolveDeadline(ctx context.Context) time.Time {
	opDeadline := time.Now().Add(t.cfg.OperationTimeout)
	if ctxDeadline, ok := ctx.Deadline(); ok && ctxDeadline.Before(opDeadline) {
		return ctxDeadline
	}
	return opDeadline
}

// classifyReadError maps a read error to the appropriate typed error.
func (t *TCPTransport) classifyReadError(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		t.log.Warn("peer disconnected during read")
		t.connected.Store(false)
		return ErrNotConnected
	}
	if isTimeoutError(err) {
		return ErrTimeout
	}
	t.log.Error("TCP read error", "error", err)
	t.connected.Store(false)
	return ErrConnectionFailed
}

// handleWriteError updates connection state on write failures.
func (t *TCPTransport) handleWriteError(err error) {
	if !isTimeoutError(err) {
		t.log.Error("TCP write error", "error", err)
		t.connected.Store(false)
	}
}

// isTimeoutError returns true if the error is a network timeout.
func isTimeoutError(err error) bool {
	netErr, ok := err.(net.Error)
	return ok && netErr.Timeout()
}
