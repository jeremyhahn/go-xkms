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
	"encoding/binary"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/flynn/noise"
)

// TCP server errors.
var (
	// ErrTCPServerAlreadyRunning indicates the TCP server is already listening.
	ErrTCPServerAlreadyRunning = errors.New("phone: TCP server already running")

	// ErrTCPServerNotRunning indicates the TCP server is not running.
	ErrTCPServerNotRunning = errors.New("phone: TCP server not running")

	// ErrTCPServerStartFailed indicates the TCP server failed to start.
	ErrTCPServerStartFailed = errors.New("phone: failed to start TCP server")

	// ErrTCPMaxConnectionsReached indicates the maximum number of concurrent
	// connections has been reached and the connection was rejected.
	ErrTCPMaxConnectionsReached = errors.New("phone: max connections reached")
)

// TCP framing constants matching TCPTransport in pkg/pairing/tcp_transport.go.
const (
	tcpFrameHeaderSize = 2
	maxTCPMessageSize  = 65535
)

// DefaultTCPListenAddr is the default TCP address for the pairing server.
const DefaultTCPListenAddr = ":8444"

// Default timeout and limit values for TCPPairingConfig.
const (
	// DefaultHandshakeTimeout is the default duration for the Noise XX handshake.
	DefaultHandshakeTimeout = 30 * time.Second

	// DefaultIdleTimeout is the default duration after which idle connections are closed.
	DefaultIdleTimeout = 5 * time.Minute

	// DefaultRequestTimeout is the default duration for a single request handler invocation.
	DefaultRequestTimeout = 30 * time.Second

	// DefaultMaxConnections is the default maximum number of concurrent connections.
	DefaultMaxConnections = 64
)

// TCPPairingConfig configures the TCP pairing server.
type TCPPairingConfig struct {
	// ListenAddr is the TCP address to listen on (default ":8444").
	ListenAddr string

	// LocalStaticKey is the persistent Noise static key.
	// If nil, a new key is generated on start.
	LocalStaticKey *noise.DHKey

	// RequestHandler processes incoming JSON-RPC requests.
	RequestHandler PeripheralRequestHandler

	// Logger is the structured logger.
	Logger *slog.Logger

	// HandshakeTimeout limits the duration of the Noise XX handshake.
	// Default: 30 seconds.
	HandshakeTimeout time.Duration

	// IdleTimeout closes connections with no activity after this duration.
	// Default: 5 minutes.
	IdleTimeout time.Duration

	// RequestTimeout limits how long a single request handler invocation may take.
	// Default: 30 seconds.
	RequestTimeout time.Duration

	// MaxConnections limits concurrent connections. 0 means no limit.
	// Default: 64.
	MaxConnections int
}

// TCPPairingServer accepts TCP connections from remote devices.
// Each connection performs a Noise XX handshake then handles
// JSON-RPC requests over the encrypted channel.
type TCPPairingServer struct {
	cfg      *TCPPairingConfig
	listener net.Listener
	log      *slog.Logger
	closed   atomic.Bool
	running  atomic.Bool
	wg       sync.WaitGroup
	connSem  chan struct{}

	localStaticKey *noise.DHKey
}

// NewTCPPairingServer creates a new TCP pairing server with the given configuration.
// If cfg is nil, defaults are applied. If LocalStaticKey is nil, a new key is
// generated. Returns an error if key generation fails.
func NewTCPPairingServer(cfg *TCPPairingConfig) (*TCPPairingServer, error) {
	if cfg == nil {
		cfg = &TCPPairingConfig{}
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultTCPListenAddr
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.HandshakeTimeout == 0 {
		cfg.HandshakeTimeout = DefaultHandshakeTimeout
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = DefaultIdleTimeout
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = DefaultRequestTimeout
	}
	if cfg.MaxConnections == 0 {
		cfg.MaxConnections = DefaultMaxConnections
	}

	// Resolve the static key.
	var localKey *noise.DHKey
	if cfg.LocalStaticKey != nil {
		localKey = cfg.LocalStaticKey
	} else {
		generated, err := GenerateStaticKey()
		if err != nil {
			return nil, ErrTCPServerStartFailed
		}
		localKey = generated
	}

	return &TCPPairingServer{
		cfg:            cfg,
		log:            cfg.Logger.With("component", "tcp_pairing_server"),
		localStaticKey: localKey,
		connSem:        make(chan struct{}, cfg.MaxConnections),
	}, nil
}

// Start begins listening for TCP connections. Returns ErrTCPServerAlreadyRunning
// if the server is already listening.
func (s *TCPPairingServer) Start() error {
	if s.closed.Load() {
		return ErrTCPServerNotRunning
	}
	if s.running.Swap(true) {
		return ErrTCPServerAlreadyRunning
	}

	listener, err := net.Listen("tcp", s.cfg.ListenAddr)
	if err != nil {
		s.running.Store(false)
		s.log.Error("failed to listen", "address", s.cfg.ListenAddr, "error", err)
		return ErrTCPServerStartFailed
	}
	s.listener = listener

	s.log.Info("TCP pairing server started", "address", listener.Addr().String())

	// Accept connections in the background.
	s.wg.Add(1)
	go s.acceptLoop()

	return nil
}

// Stop gracefully stops the server, closing the listener and draining
// active connections. It is safe to call Stop multiple times.
func (s *TCPPairingServer) Stop() error {
	if !s.running.Swap(false) {
		return ErrTCPServerNotRunning
	}
	s.closed.Store(true)

	if s.listener != nil {
		s.listener.Close()
	}

	s.wg.Wait()
	s.log.Info("TCP pairing server stopped")
	return nil
}

// Addr returns the listener address. This is useful when listening on ":0"
// to discover the actual port assigned by the OS.
func (s *TCPPairingServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// LocalStaticPublicKey returns a copy of the server's Noise static public key.
// The returned slice is a defensive copy; callers cannot mutate the server's key.
func (s *TCPPairingServer) LocalStaticPublicKey() []byte {
	if s.localStaticKey == nil {
		return nil
	}
	cp := make([]byte, len(s.localStaticKey.Public))
	copy(cp, s.localStaticKey.Public)
	return cp
}

// acceptLoop runs in its own goroutine and accepts incoming TCP connections.
func (s *TCPPairingServer) acceptLoop() {
	defer s.wg.Done()

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			// Listener closed is expected during shutdown.
			if s.closed.Load() {
				return
			}
			s.log.Error("accept error", "error", err)
			continue
		}

		remoteAddr := conn.RemoteAddr().String()

		// Enforce max connections via semaphore.
		select {
		case s.connSem <- struct{}{}:
			// Acquired a slot.
		default:
			s.log.Warn("max connections reached, rejecting", "remote", remoteAddr)
			conn.Close()
			continue
		}

		s.log.Debug("accepted connection", "remote", remoteAddr)

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

// handleConnection manages a single TCP connection through the full lifecycle:
// Noise XX handshake followed by encrypted JSON-RPC request/response processing.
func (s *TCPPairingServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()
	defer func() { <-s.connSem }()

	remoteAddr := conn.RemoteAddr().String()

	// Set a deadline for the entire handshake phase.
	conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout))

	// Create a Noise session as responder for this connection.
	session, err := NewNoiseSession(&NoiseSessionConfig{
		LocalStaticKey: s.localStaticKey,
		IsInitiator:    false,
	})
	if err != nil {
		s.log.Error("failed to create noise session", "remote", remoteAddr, "error", err)
		return
	}

	if err := session.InitHandshake(); err != nil {
		s.log.Error("failed to init handshake", "remote", remoteAddr, "error", err)
		return
	}

	// Noise XX handshake as responder (3 messages):
	// 1. Receive msg1 (initiator's ephemeral key)
	msg1, err := tcpReceive(conn)
	if err != nil {
		s.log.Error("failed to receive handshake msg1", "remote", remoteAddr, "error", err)
		return
	}

	// 2. Process msg1 and generate msg2 (e, ee, s, es)
	msg2, complete, err := session.HandshakeMessage(msg1)
	if err != nil {
		s.log.Error("failed to process handshake msg1", "remote", remoteAddr, "error", err)
		return
	}
	if complete {
		s.log.Error("unexpected handshake completion after msg1", "remote", remoteAddr)
		return
	}

	// Send msg2 to initiator.
	if err := tcpSend(conn, msg2); err != nil {
		s.log.Error("failed to send handshake msg2", "remote", remoteAddr, "error", err)
		return
	}

	// 3. Receive msg3 (initiator's static key, s, se)
	msg3, err := tcpReceive(conn)
	if err != nil {
		s.log.Error("failed to receive handshake msg3", "remote", remoteAddr, "error", err)
		return
	}

	// Process msg3 to complete the handshake.
	_, complete, err = session.HandshakeMessage(msg3)
	if err != nil {
		s.log.Error("failed to process handshake msg3", "remote", remoteAddr, "error", err)
		return
	}
	if !complete {
		s.log.Error("handshake not complete after msg3", "remote", remoteAddr)
		return
	}

	// Clear the handshake deadline before entering the request loop.
	conn.SetDeadline(time.Time{})

	s.log.Info("noise handshake completed", "remote", remoteAddr)

	// Enter the encrypted request/response loop.
	s.requestLoop(conn, session, remoteAddr)
}

// requestLoop reads encrypted JSON-RPC requests, decrypts them, delegates
// to the RequestHandler, encrypts the response, and sends it back.
func (s *TCPPairingServer) requestLoop(conn net.Conn, session *NoiseSession, remoteAddr string) {
	for {
		// Check if the server is shutting down.
		if s.closed.Load() {
			return
		}

		// Set idle timeout before each read.
		conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout))

		// Read encrypted request.
		ciphertext, err := tcpReceive(conn)
		if err != nil {
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				s.log.Debug("client disconnected", "remote", remoteAddr)
				return
			}
			// Connection closed or network error during shutdown is expected.
			if s.closed.Load() {
				return
			}
			// Deadline exceeded means idle timeout.
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				s.log.Info("idle timeout, closing connection", "remote", remoteAddr)
				return
			}
			s.log.Error("failed to receive request", "remote", remoteAddr, "error", err)
			return
		}

		// Decrypt request.
		plaintext, err := session.Decrypt(ciphertext)
		if err != nil {
			s.log.Error("failed to decrypt request", "remote", remoteAddr, "error", err)
			return
		}

		// Dispatch to handler with request timeout.
		var response []byte
		if s.cfg.RequestHandler != nil {
			ctx, cancel := context.WithTimeout(context.Background(), s.cfg.RequestTimeout)
			response, err = s.cfg.RequestHandler.HandleRequest(ctx, plaintext)
			cancel()
			if err != nil {
				s.log.Error("request handler error", "remote", remoteAddr, "error", err)
				response = []byte(`{"jsonrpc":"2.0","error":{"code":-32603,"message":"Internal error"}}`)
			}
		} else {
			s.log.Warn("no request handler configured", "remote", remoteAddr)
			response = []byte(`{"jsonrpc":"2.0","error":{"code":-32601,"message":"Method not found"}}`)
		}

		// Set write deadline for the response.
		conn.SetWriteDeadline(time.Now().Add(s.cfg.RequestTimeout))

		// Encrypt and send the response.
		encrypted, err := session.Encrypt(response)
		if err != nil {
			s.log.Error("failed to encrypt response", "remote", remoteAddr, "error", err)
			return
		}

		if err := tcpSend(conn, encrypted); err != nil {
			s.log.Error("failed to send response", "remote", remoteAddr, "error", err)
			return
		}
	}
}

// tcpSend writes a message to the connection using 2-byte big-endian
// length-prefixed framing, matching the TCPTransport wire format.
func tcpSend(conn net.Conn, msg []byte) error {
	if len(msg) > maxTCPMessageSize {
		return ErrProtocolError
	}
	frame := make([]byte, tcpFrameHeaderSize+len(msg))
	binary.BigEndian.PutUint16(frame[:tcpFrameHeaderSize], uint16(len(msg)))
	copy(frame[tcpFrameHeaderSize:], msg)
	_, err := conn.Write(frame)
	return err
}

// tcpReceive reads a complete length-prefixed message from the connection.
// It reads the 2-byte big-endian header to determine the payload size,
// then reads exactly that many bytes.
func tcpReceive(conn net.Conn) ([]byte, error) {
	header := make([]byte, tcpFrameHeaderSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	length := binary.BigEndian.Uint16(header)
	if length == 0 {
		return []byte{}, nil
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(conn, payload); err != nil {
		return nil, err
	}
	return payload, nil
}
