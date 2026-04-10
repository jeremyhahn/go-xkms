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

package phone

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/phone"
)

// TCPTransport implements a BLE-like transport over TCP for integration testing.
// This allows testing the protocol layers without real BLE hardware.
type TCPTransport struct {
	mu      sync.Mutex
	conn    net.Conn
	addr    string
	mtu     int
	closed  bool
	readBuf []byte
	timeout time.Duration
}

// TCPTransportConfig configures the TCP transport.
type TCPTransportConfig struct {
	Address string
	MTU     int
	Timeout time.Duration
}

// NewTCPTransport creates a new TCP transport for testing.
func NewTCPTransport(cfg *TCPTransportConfig) *TCPTransport {
	mtu := cfg.MTU
	if mtu < phone.MinMTU {
		mtu = phone.DefaultMTU
	}
	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = 30 * time.Second
	}
	return &TCPTransport{
		addr:    cfg.Address,
		mtu:     mtu,
		timeout: timeout,
		readBuf: make([]byte, 65536),
	}
}

// Connect establishes a connection to the phone simulator.
func (t *TCPTransport) Connect(ctx context.Context) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.closed {
		return phone.ErrBackendClosed
	}

	dialer := net.Dialer{Timeout: t.timeout}
	conn, err := dialer.DialContext(ctx, "tcp", t.addr)
	if err != nil {
		return fmt.Errorf("%w: %v", phone.ErrConnectionFailed, err)
	}

	t.conn = conn
	return nil
}

// Disconnect closes the connection.
func (t *TCPTransport) Disconnect() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

// Write sends data to the phone simulator.
// Data is prefixed with a 2-byte length header.
func (t *TCPTransport) Write(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.conn == nil {
		return phone.ErrNotConnected
	}

	// Frame: [2-byte length][data]
	frame := make([]byte, 2+len(data))
	frame[0] = byte(len(data) >> 8)
	frame[1] = byte(len(data))
	copy(frame[2:], data)

	t.conn.SetWriteDeadline(time.Now().Add(t.timeout))
	_, err := t.conn.Write(frame)
	return err
}

// Read receives data from the phone simulator.
func (t *TCPTransport) Read() ([]byte, error) {
	t.mu.Lock()
	conn := t.conn
	t.mu.Unlock()

	if conn == nil {
		return nil, phone.ErrNotConnected
	}

	// Read 2-byte length header
	conn.SetReadDeadline(time.Now().Add(t.timeout))
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, lenBuf); err != nil {
		if err == io.EOF {
			return nil, phone.ErrNotConnected
		}
		return nil, err
	}

	length := int(lenBuf[0])<<8 | int(lenBuf[1])
	if length == 0 {
		return []byte{}, nil
	}

	// Read data
	data := make([]byte, length)
	if _, err := io.ReadFull(conn, data); err != nil {
		return nil, err
	}

	return data, nil
}

// MTU returns the configured MTU.
func (t *TCPTransport) MTU() int {
	return t.mtu
}

// Close closes the transport permanently.
func (t *TCPTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	if t.conn != nil {
		err := t.conn.Close()
		t.conn = nil
		return err
	}
	return nil
}

// IsConnected returns whether the transport is connected.
func (t *TCPTransport) IsConnected() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn != nil && !t.closed
}
