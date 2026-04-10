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
	"errors"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Compile-time interface satisfaction checks for both transport types.
// These fail at build time if the types drift from the interface.
var (
	_ Transport = (*TCPTransport)(nil)
)

// startEchoTCPServer starts a local TCP server that echoes back messages using
// the same 2-byte big-endian length-prefixed framing protocol as TCPTransport.
func startEchoTCPServer(t *testing.T) (address string, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return // listener closed
			}
			go handleEchoConnection(conn)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

// handleEchoConnection reads length-prefixed messages and echoes them back.
func handleEchoConnection(conn net.Conn) {
	defer conn.Close()
	for {
		// Read 2-byte length header.
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		length := binary.BigEndian.Uint16(header)
		if length == 0 {
			// Echo back the zero-length frame.
			if _, err := conn.Write(header); err != nil {
				return
			}
			continue
		}
		// Read payload.
		payload := make([]byte, length)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		// Echo back with same framing.
		resp := make([]byte, 2+len(payload))
		binary.BigEndian.PutUint16(resp[:2], uint16(len(payload)))
		copy(resp[2:], payload)
		if _, err := conn.Write(resp); err != nil {
			return
		}
	}
}

// startAcceptOnlyServer starts a TCP server that accepts connections but never
// sends data. Useful for testing receive-side timeouts and peer disconnect.
func startAcceptOnlyServer(t *testing.T) (address string, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	conns := make(chan net.Conn, 10)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conns <- conn
		}
	}()

	return listener.Addr().String(), func() {
		close(conns)
		for c := range conns {
			c.Close()
		}
		listener.Close()
	}
}

// startSilentTCPServer starts a TCP server that accepts connections,
// reads data, but never sends a response. This is useful for testing
// receive-side timeouts.
func startSilentTCPServer(t *testing.T) (address string, cleanup func()) {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			// Read everything but never respond. Hold the connection open.
			go func(c net.Conn) {
				buf := make([]byte, 4096)
				for {
					if _, err := c.Read(buf); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

// ---------------------------------------------------------------------------
// 1. TCPTransportConfig tests
// ---------------------------------------------------------------------------

func TestDefaultTCPTransportConfig(t *testing.T) {
	t.Parallel()

	cfg := DefaultTCPTransportConfig()

	require.NotNil(t, cfg)
	assert.Equal(t, DefaultTCPAddress, cfg.Address)
	assert.Equal(t, DefaultTCPConnectTimeout, cfg.ConnectTimeout)
	assert.Equal(t, DefaultTCPOperationTimeout, cfg.OperationTimeout)
	assert.NotNil(t, cfg.Logger)
}

func TestNewTCPTransport_NilConfig(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(nil)

	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, DefaultTCPAddress, transport.cfg.Address)
	assert.Equal(t, DefaultTCPConnectTimeout, transport.cfg.ConnectTimeout)
	assert.Equal(t, DefaultTCPOperationTimeout, transport.cfg.OperationTimeout)
	assert.NotNil(t, transport.cfg.Logger)
	assert.False(t, transport.IsConnected())

	t.Cleanup(func() { transport.Close() })
}

func TestNewTCPTransport_EmptyAddress(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "",
	})

	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, DefaultTCPAddress, transport.cfg.Address)

	t.Cleanup(func() { transport.Close() })
}

func TestNewTCPTransport_CustomConfig(t *testing.T) {
	t.Parallel()

	customLogger := slog.Default().With("test", true)
	cfg := &TCPTransportConfig{
		Address:          "10.0.0.1:9999",
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 30 * time.Second,
		Logger:           customLogger,
	}

	transport, err := NewTCPTransport(cfg)

	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, "10.0.0.1:9999", transport.cfg.Address)
	assert.Equal(t, 5*time.Second, transport.cfg.ConnectTimeout)
	assert.Equal(t, 30*time.Second, transport.cfg.OperationTimeout)

	t.Cleanup(func() { transport.Close() })
}

func TestNewTCPTransport_ZeroTimeoutsUseDefaults(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          "127.0.0.1:1234",
		ConnectTimeout:   0,
		OperationTimeout: 0,
	})

	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.Equal(t, DefaultTCPConnectTimeout, transport.cfg.ConnectTimeout)
	assert.Equal(t, DefaultTCPOperationTimeout, transport.cfg.OperationTimeout)

	t.Cleanup(func() { transport.Close() })
}

func TestNewTCPTransport_NilLoggerUsesDefault(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:1234",
		Logger:  nil,
	})

	require.NoError(t, err)
	require.NotNil(t, transport)
	assert.NotNil(t, transport.cfg.Logger)
	assert.NotNil(t, transport.log)

	t.Cleanup(func() { transport.Close() })
}

// ---------------------------------------------------------------------------
// 2. Connection lifecycle tests
// ---------------------------------------------------------------------------

func TestTCPTransport_Connect(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	err = transport.Connect(ctx)
	assert.NoError(t, err)
	assert.True(t, transport.IsConnected())
}

func TestTCPTransport_ConnectAlreadyConnected(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())

	// Second connect should be idempotent and return nil.
	err = transport.Connect(ctx)
	assert.NoError(t, err)
	assert.True(t, transport.IsConnected())
}

func TestTCPTransport_ConnectClosed(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)

	// Close the transport first.
	require.NoError(t, transport.Close())

	// Connect after close should return ErrBackendClosed.
	ctx := context.Background()
	err = transport.Connect(ctx)
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestTCPTransport_ConnectFailure(t *testing.T) {
	t.Parallel()

	// Use a listener to get a valid port, then close it immediately so nothing
	// is listening when we try to connect.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	closedAddr := listener.Addr().String()
	listener.Close()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:        closedAddr,
		ConnectTimeout: 1 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	err = transport.Connect(ctx)
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.False(t, transport.IsConnected())
}

func TestTCPTransport_ConnectCancelledContext(t *testing.T) {
	t.Parallel()

	// Bind a listener that accepts to avoid connection refused, but cancel
	// the context immediately so DialContext fails with context error.
	addr, cleanup := startAcceptOnlyServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:        addr,
		ConnectTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	err = transport.Connect(ctx)
	assert.ErrorIs(t, err, ErrConnectionFailed)
	assert.False(t, transport.IsConnected())
}

func TestTCPTransport_Disconnect(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())

	err = transport.Disconnect()
	assert.NoError(t, err)
	assert.False(t, transport.IsConnected())
}

func TestTCPTransport_DisconnectNotConnected(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	// Disconnect when never connected should not return an error.
	err = transport.Disconnect()
	assert.NoError(t, err)
}

func TestTCPTransport_DisconnectThenReconnect(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()

	// Connect, disconnect, and reconnect.
	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())

	require.NoError(t, transport.Disconnect())
	assert.False(t, transport.IsConnected())

	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())
}

func TestTCPTransport_Close(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())

	err = transport.Close()
	assert.NoError(t, err)
	assert.False(t, transport.IsConnected())
}

func TestTCPTransport_CloseIdempotent(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	err = transport.Close()
	assert.NoError(t, err)

	// Second close should return nil.
	err = transport.Close()
	assert.NoError(t, err)
}

func TestTCPTransport_CloseWithoutConnect(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)

	err = transport.Close()
	assert.NoError(t, err)
}

func TestTCPTransport_IsConnected(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	// Initially not connected.
	assert.False(t, transport.IsConnected())

	// Connected after Connect.
	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))
	assert.True(t, transport.IsConnected())

	// Not connected after Disconnect.
	require.NoError(t, transport.Disconnect())
	assert.False(t, transport.IsConnected())

	// Not connected after Close.
	require.NoError(t, transport.Connect(ctx))
	require.NoError(t, transport.Close())
	assert.False(t, transport.IsConnected())
}

// ---------------------------------------------------------------------------
// 3. Send/Receive tests
// ---------------------------------------------------------------------------

func TestTCPTransport_SendReceive(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	message := []byte("hello, phone")
	err = transport.Send(ctx, message)
	assert.NoError(t, err)

	received, err := transport.Receive(ctx)
	assert.NoError(t, err)
	assert.Equal(t, message, received)
}

func TestTCPTransport_SendReceiveEmptyMessage(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Send a zero-length message.
	err = transport.Send(ctx, []byte{})
	assert.NoError(t, err)

	received, err := transport.Receive(ctx)
	assert.NoError(t, err)
	assert.Equal(t, []byte{}, received)
}

func TestTCPTransport_SendLargeMessage(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Send a message at the maximum size (65535 bytes).
	message := make([]byte, MaxTCPMessageSize)
	for i := range message {
		message[i] = byte(i % 256)
	}

	err = transport.Send(ctx, message)
	assert.NoError(t, err)

	received, err := transport.Receive(ctx)
	assert.NoError(t, err)
	assert.Equal(t, message, received)
}

func TestTCPTransport_SendTooLarge(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Message exceeding MaxTCPMessageSize should return ErrProtocolError.
	oversized := make([]byte, MaxTCPMessageSize+1)
	err = transport.Send(ctx, oversized)
	assert.ErrorIs(t, err, ErrProtocolError)
}

func TestTCPTransport_SendNotConnected(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	err = transport.Send(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestTCPTransport_SendClosed(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	require.NoError(t, transport.Close())

	ctx := context.Background()
	err = transport.Send(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrBackendClosed)
}

func TestTCPTransport_SendNilConn(t *testing.T) {
	t.Parallel()

	// Simulate the race condition where connected is true but conn is nil.
	// This exercises the conn == nil guard in Send.
	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	// Force the connected flag without actually connecting.
	transport.connected.Store(true)

	ctx := context.Background()
	err = transport.Send(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrNotConnected)
}

func TestTCPTransport_ReceiveNilConn(t *testing.T) {
	t.Parallel()

	// Simulate the race condition where connected is true but conn is nil.
	// This exercises the conn == nil guard in Receive.
	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	// Force the connected flag without actually connecting.
	transport.connected.Store(true)

	ctx := context.Background()
	data, err := transport.Receive(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, data)
}

func TestTCPTransport_ReceiveNotConnected(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	data, err := transport.Receive(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, data)
}

func TestTCPTransport_ReceiveClosed(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	require.NoError(t, transport.Close())

	ctx := context.Background()
	data, err := transport.Receive(ctx)
	assert.ErrorIs(t, err, ErrBackendClosed)
	assert.Nil(t, data)
}

func TestTCPTransport_ReceivePeerDisconnect(t *testing.T) {
	t.Parallel()

	// Start a server that accepts one connection then immediately closes it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Close immediately to simulate peer disconnect.
		conn.Close()
	}()
	t.Cleanup(func() { listener.Close() })

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 5 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Peer has closed; Receive should detect the EOF and return ErrNotConnected.
	data, err := transport.Receive(ctx)
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, data)
}

func TestTCPTransport_ReceiveTimeout(t *testing.T) {
	t.Parallel()

	// Use a server that accepts but never sends data.
	addr, cleanup := startSilentTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 50 * time.Millisecond,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Send a message to the silent server.
	err = transport.Send(ctx, []byte("hello"))
	require.NoError(t, err)

	// Receive should time out because the server never responds.
	data, err := transport.Receive(ctx)
	assert.ErrorIs(t, err, ErrTimeout)
	assert.Nil(t, data)
}

func TestTCPTransport_SendWriteToClosedConn(t *testing.T) {
	t.Parallel()

	// Start a server that accepts a connection then immediately closes it.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close()
	}()
	t.Cleanup(func() { listener.Close() })

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Give the server time to close the connection.
	time.Sleep(50 * time.Millisecond)

	// Writing to a closed peer connection may either succeed (buffered) or fail.
	// Send multiple large writes to trigger the write error path.
	var lastErr error
	for i := 0; i < 10; i++ {
		lastErr = transport.Send(ctx, make([]byte, 4096))
		if lastErr != nil {
			break
		}
	}
	// Eventually we should get an error since the peer closed.
	assert.Error(t, lastErr)
}

func TestTCPTransport_SendAndReceive(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	message := []byte("round-trip test message")
	response, err := transport.SendAndReceive(ctx, message)
	assert.NoError(t, err)
	assert.Equal(t, message, response)
}

func TestTCPTransport_SendAndReceiveNotConnected(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: "127.0.0.1:0",
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	data, err := transport.SendAndReceive(ctx, []byte("test"))
	assert.ErrorIs(t, err, ErrNotConnected)
	assert.Nil(t, data)
}

func TestTCPTransport_SendAndReceiveTooLarge(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	oversized := make([]byte, MaxTCPMessageSize+1)
	data, err := transport.SendAndReceive(ctx, oversized)
	assert.ErrorIs(t, err, ErrProtocolError)
	assert.Nil(t, data)
}

func TestTCPTransport_MultipleRoundTrips(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	messages := []string{
		"first message",
		"second message",
		"third message with more data",
	}

	for _, msg := range messages {
		response, err := transport.SendAndReceive(ctx, []byte(msg))
		require.NoError(t, err)
		assert.Equal(t, []byte(msg), response)
	}
}

func TestTCPTransport_SendAfterPeerDisconnect(t *testing.T) {
	t.Parallel()

	// Start a server that accepts a connection, reads one message, then closes.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := listener.Addr().String()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		// Read one framed message, then close.
		header := make([]byte, 2)
		if _, err := io.ReadFull(conn, header); err != nil {
			conn.Close()
			return
		}
		length := binary.BigEndian.Uint16(header)
		if length > 0 {
			buf := make([]byte, length)
			io.ReadFull(conn, buf)
		}
		conn.Close()
	}()
	t.Cleanup(func() { listener.Close() })

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 2 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// First send succeeds (server reads it then closes).
	err = transport.Send(ctx, []byte("first"))
	assert.NoError(t, err)

	// Give the server time to close the connection.
	time.Sleep(50 * time.Millisecond)

	// Receive should fail because the peer is gone.
	_, err = transport.Receive(ctx)
	assert.Error(t, err)
}

func TestTCPTransport_ResolveDeadlineWithContextDeadline(t *testing.T) {
	t.Parallel()

	addr, cleanup := startEchoTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Use a context with a deadline shorter than the operation timeout.
	// The resolveDeadline method should pick the context deadline.
	shortCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	// Send and receive should work correctly with the context deadline.
	message := []byte("context deadline test")
	response, err := transport.SendAndReceive(shortCtx, message)
	assert.NoError(t, err)
	assert.Equal(t, message, response)
}

func TestTCPTransport_SendAndReceiveWithContextDeadline(t *testing.T) {
	t.Parallel()

	// Use a silent server so the operation will time out via context.
	addr, cleanup := startSilentTCPServer(t)
	t.Cleanup(cleanup)

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address:          addr,
		OperationTimeout: 30 * time.Second,
	})
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	ctx := context.Background()
	require.NoError(t, transport.Connect(ctx))

	// Use a very short context deadline that will expire before the operation timeout.
	shortCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	data, err := transport.SendAndReceive(shortCtx, []byte("test"))
	// Should timeout (either ErrTimeout from the context deadline or another error).
	assert.Error(t, err)
	assert.Nil(t, data)
}

// ---------------------------------------------------------------------------
// 4. Transport interface compliance
// ---------------------------------------------------------------------------

func TestTCPTransport_ImplementsTransport(t *testing.T) {
	t.Parallel()

	transport, err := NewTCPTransport(nil)
	require.NoError(t, err)
	t.Cleanup(func() { transport.Close() })

	// Verify the concrete type satisfies the Transport interface.
	var iface Transport = transport
	assert.NotNil(t, iface)
}

// ---------------------------------------------------------------------------
// 6. TCP transport constants
// ---------------------------------------------------------------------------

func TestTCPTransportConstants(t *testing.T) {
	t.Parallel()

	assert.Equal(t, "localhost:8444", DefaultTCPAddress)
	assert.Equal(t, 10*time.Second, DefaultTCPConnectTimeout)
	assert.Equal(t, 60*time.Second, DefaultTCPOperationTimeout)
	assert.Equal(t, 65535, MaxTCPMessageSize)
}

// ---------------------------------------------------------------------------
// 7. isTimeoutError tests
// ---------------------------------------------------------------------------

func TestIsTimeoutError_NonTimeout(t *testing.T) {
	t.Parallel()

	assert.False(t, isTimeoutError(io.EOF))
	assert.False(t, isTimeoutError(io.ErrUnexpectedEOF))
	assert.False(t, isTimeoutError(ErrNotConnected))
}

// ---------------------------------------------------------------------------
// 8. Benchmarks
// ---------------------------------------------------------------------------

func BenchmarkTCPTransport_SendReceive(b *testing.B) {
	addr, cleanup := startEchoTCPServerBench(b)
	defer cleanup()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer transport.Close()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		b.Fatal(err)
	}

	message := []byte("benchmark payload for latency measurement")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := transport.SendAndReceive(ctx, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkTCPTransport_SendReceiveLarge(b *testing.B) {
	addr, cleanup := startEchoTCPServerBench(b)
	defer cleanup()

	transport, err := NewTCPTransport(&TCPTransportConfig{
		Address: addr,
	})
	if err != nil {
		b.Fatal(err)
	}
	defer transport.Close()

	ctx := context.Background()
	if err := transport.Connect(ctx); err != nil {
		b.Fatal(err)
	}

	message := make([]byte, 4096)
	for i := range message {
		message[i] = byte(i % 256)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := transport.SendAndReceive(ctx, message)
		if err != nil {
			b.Fatal(err)
		}
	}
}

// startEchoTCPServerBench is a benchmark variant of startEchoTCPServer.
func startEchoTCPServerBench(b *testing.B) (address string, cleanup func()) {
	b.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleEchoConnection(conn)
		}
	}()

	return listener.Addr().String(), func() { listener.Close() }
}

// --- classifyReadError generic error test ---

func TestTCPTransport_ClassifyReadError_GenericError(t *testing.T) {
	t.Parallel()

	cfg := DefaultTCPTransportConfig()
	cfg.Logger = testLogger()

	transport, err := NewTCPTransport(cfg)
	require.NoError(t, err)

	// Directly test classifyReadError with a non-EOF, non-timeout error.
	genericErr := errors.New("generic read error")
	result := transport.classifyReadError(genericErr)
	assert.ErrorIs(t, result, ErrConnectionFailed)
	assert.False(t, transport.IsConnected())
}
