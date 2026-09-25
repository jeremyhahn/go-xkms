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

	"github.com/jeremyhahn/go-xkms/xkey/internal/lifecycle"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
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

	// LocalStaticKey is the persistent Noise static key, held in protected
	// memory. If nil, a new key is generated on start.
	LocalStaticKey *pairing.StaticKey

	// OwnsStaticKey transfers ownership of LocalStaticKey to the server, so
	// that Stop releases it — and, just as importantly, RETAINS it when a
	// connection handler cannot be confirmed finished.
	//
	// Set it whenever the key has no other reader. A caller that keeps
	// ownership has to interpret ErrShutdownIncomplete itself and hold the
	// key for the life of the process, and every caller that forgot did the
	// opposite: destroyed a borrowed key while a handler was still using it.
	// Transferring ownership puts that decision in one place.
	OwnsStaticKey bool

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

	// connMu guards conns, the set of accepted connections that have not
	// finished. Stop closes them so blocked reads unblock immediately.
	connMu sync.Mutex
	conns  map[net.Conn]struct{}

	// lifecycleMu serializes Start against Stop. The atomics alone are not
	// enough: Stop could flip running between Start's Swap and its wg.Add,
	// then Wait on an empty group and destroy the static key while Start went
	// on to launch an accept loop that uses it. Holding this for the whole of
	// each transition means shutdown never overlaps startup.
	lifecycleMu sync.RWMutex

	// connJoiner bounds Stop's wait on the connection WaitGroup with a single
	// waiter goroutine for the server's life.
	connJoiner lifecycle.Joiner

	// stopOnce/stopErr latch the shutdown outcome so concurrent and repeat
	// callers see one result and only one of them releases the static key.
	stopOnce sync.Once
	stopErr  error

	localStaticKey *pairing.StaticKey

	// ownsStaticKey records whether the server generated localStaticKey
	// itself. A key supplied by the caller stays the caller's to destroy;
	// destroying a borrowed key would free protected pages another session
	// is still reading from.
	ownsStaticKey bool
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
	localKey := cfg.LocalStaticKey
	owns := false
	switch {
	case localKey == nil:
		generated, err := pairing.GenerateStaticKey()
		if err != nil {
			return nil, ErrTCPServerStartFailed
		}
		localKey = generated
		owns = true
	case cfg.OwnsStaticKey:
		// Consumed from the config for the same reason the phone backend
		// consumes it: a config is an input callers reuse, and one still
		// holding a key this server now owns hands the next construction a
		// second owner for the same protected pages.
		owns = true
		cfg.LocalStaticKey = nil
	}

	return &TCPPairingServer{
		cfg:            cfg,
		log:            cfg.Logger.With("component", "tcp_pairing_server"),
		localStaticKey: localKey,
		ownsStaticKey:  owns,
		connSem:        make(chan struct{}, cfg.MaxConnections),
		conns:          make(map[net.Conn]struct{}),
	}, nil
}

// Start begins listening for TCP connections. Returns ErrTCPServerAlreadyRunning
// if the server is already listening.
func (s *TCPPairingServer) Start() error {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

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

// Stop shuts the server down and releases everything it owns. It is safe to
// call multiple times, and it is the cleanup path whether or not the listener
// ever came up: a Start that failed to bind still leaves the server holding a
// generated key, and Stop is the only operation callers have to release it.
// ErrTCPServerNotRunning reports that there was nothing listening, not that
// cleanup was skipped.
//
// Stop is terminal. A stopped server has no static key left, so Start refuses
// afterwards rather than binding with a destroyed one.
//
// MUST NOT be called from a RequestHandler. Stop waits for handlers to
// finish, and the latch makes a re-entrant caller wait for Stop — so a
// handler that calls it guarantees the full shutdown window elapses and the
// key is retained. This is the classic self-deadlock of any Shutdown that
// drains its own callbacks (net/http.Server.Shutdown behaves the same way),
// and it is bounded rather than permanent because the join has a timeout.
// The alternative — answering a re-entrant caller early — is the defect the
// latch exists to fix: two callers reaching different conclusions about
// whether the protected key is safe to free.
func (s *TCPPairingServer) Stop() error {
	// Latched, so every caller observes the SAME outcome.
	//
	// Without this a second Stop found running already false, skipped the
	// join entirely, kept joined=true, and destroyed a key the FIRST Stop was
	// still waiting on — reintroducing exactly the use-after-free the bounded
	// join exists to prevent. sync.Once also blocks concurrent callers until
	// the first completes, so nobody is told shutdown finished before it did.
	s.stopOnce.Do(func() { s.stopErr = s.stop() })
	return s.stopErr
}

func (s *TCPPairingServer) stop() error {
	s.lifecycleMu.Lock()

	wasRunning := s.running.Swap(false)
	s.closed.Store(true)

	joined := true
	if wasRunning {
		if s.listener != nil {
			if closeErr := s.listener.Close(); closeErr != nil {
				s.log.Warn("failed to close TCP listener", "error", closeErr)
			}
		}

		// Close active connections so handler goroutines blocked on a read
		// return immediately instead of waiting out the idle timeout.
		s.closeAllConns()

		// Released for the wait, and re-taken after.
		//
		// Two reasons, and the second is the one that bites. A connection
		// worker runs a caller-supplied RequestHandler synchronously, so
		// closing the socket does not interrupt a handler that ignores its
		// context — an unbounded wait here is a Stop that never returns. And
		// holding lifecycleMu across the wait deadlocks a handler that calls
		// LocalStaticPublicKey, which takes the read side: Stop waits for the
		// handler and the handler waits for Stop.
		s.lifecycleMu.Unlock()
		joined = s.connJoiner.Join(&s.wg, serverShutdownTimeout)
		s.lifecycleMu.Lock()
	}

	defer s.lifecycleMu.Unlock()

	// Only once every handler has returned. A join that timed out is not
	// proof of that, so the key is retained instead — reachable, not dropped,
	// so that "retained" and "forgotten" do not look the same here.
	if s.ownsStaticKey {
		if joined {
			s.localStaticKey.Destroy()
			s.localStaticKey = nil
		} else {
			s.log.Warn("retaining the TCP pairing server static key: a "+
				"connection handler did not finish within the shutdown window",
				"timeout", serverShutdownTimeout)
		}
	}

	if !wasRunning {
		return ErrTCPServerNotRunning
	}

	s.log.Info("TCP pairing server stopped")

	if !joined {
		return ErrShutdownIncomplete
	}
	return nil
}

// serverShutdownTimeout bounds how long Stop waits for connection handlers to
// finish. A handler is running caller-supplied code that may be waiting on a
// user, so the window is generous; what it must not be is absent.
//
// A var rather than a const so tests can exercise the timeout branch without
// spending the production window on it. Nothing else writes it.
var serverShutdownTimeout = 30 * time.Second

// Addr returns the listener address. This is useful when listening on ":0"
// to discover the actual port assigned by the OS.
func (s *TCPPairingServer) Addr() string {
	if s.listener == nil {
		return ""
	}
	return s.listener.Addr().String()
}

// LocalStaticPublicKey returns a copy of the server's Noise static public key,
// or nil once Stop has released it. The returned slice is a defensive copy;
// callers cannot mutate the server's key.
//
// The read is held under lifecycleMu because Stop destroys the key under the
// write side: without it, a caller could pass the nil check and then copy out
// of pages Stop was in the middle of freeing.
func (s *TCPPairingServer) LocalStaticPublicKey() []byte {
	s.lifecycleMu.RLock()
	defer s.lifecycleMu.RUnlock()

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
			if closeErr := conn.Close(); closeErr != nil {
				s.log.Warn("failed to close rejected connection", "remote", remoteAddr, "error", closeErr)
			}
			continue
		}

		s.log.Debug("accepted connection", "remote", remoteAddr)

		// Register against shutdown as ONE step, the same pairing Start and
		// SendRequest use elsewhere. Accept can return just before Stop
		// closes the listener; without this the WaitGroup could reach zero,
		// Join could report a clean drain, Stop could destroy the static key
		// — and only then would this loop add and launch a handler that
		// reads it. It is also the WaitGroup rule: an Add from zero must
		// happen before any Wait.
		if !s.registerConn(conn) {
			<-s.connSem
			if closeErr := conn.Close(); closeErr != nil {
				s.log.Warn("failed to close connection refused during shutdown", "remote", remoteAddr, "error", closeErr)
			}
			continue
		}

		go s.handleConnection(conn)
	}
}

// registerConn admits an accepted connection, reporting false once shutdown
// has begun. The closed check, the WaitGroup registration and the tracking
// that lets Stop close the socket all happen under lifecycleMu, so a
// connection is either counted before Stop starts waiting or refused
// outright.
func (s *TCPPairingServer) registerConn(conn net.Conn) bool {
	s.lifecycleMu.Lock()
	defer s.lifecycleMu.Unlock()

	if s.closed.Load() {
		return false
	}

	s.wg.Add(1)
	s.trackConn(conn)
	return true
}

// trackConn registers an accepted connection so Stop can close it.
func (s *TCPPairingServer) trackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	if s.conns == nil {
		s.conns = make(map[net.Conn]struct{})
	}
	s.conns[conn] = struct{}{}
}

// untrackConn removes a connection that has finished.
func (s *TCPPairingServer) untrackConn(conn net.Conn) {
	s.connMu.Lock()
	defer s.connMu.Unlock()
	delete(s.conns, conn)
}

// closeAllConns closes every tracked connection.
func (s *TCPPairingServer) closeAllConns() {
	s.connMu.Lock()
	conns := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		conns = append(conns, conn)
	}
	s.connMu.Unlock()

	for _, conn := range conns {
		if closeErr := conn.Close(); closeErr != nil {
			s.log.Warn("failed to close tracked connection", "error", closeErr)
		}
	}
}

// handleConnection manages a single TCP connection through the full lifecycle:
// Noise XX handshake followed by encrypted JSON-RPC request/response processing.
func (s *TCPPairingServer) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer func() {
		s.untrackConn(conn)
		if closeErr := conn.Close(); closeErr != nil {
			s.log.Warn("failed to close connection", "error", closeErr)
		}
	}()
	defer func() { <-s.connSem }()

	remoteAddr := conn.RemoteAddr().String()

	// Set a deadline for the entire handshake phase. A failure here means
	// the connection cannot be bounded, so reads below could block forever
	// instead of honoring HandshakeTimeout; treat it as fatal rather than
	// silently handshaking without a deadline.
	if err := conn.SetDeadline(time.Now().Add(s.cfg.HandshakeTimeout)); err != nil {
		s.log.Error("failed to set handshake deadline", "remote", remoteAddr, "error", err)
		return
	}

	// Create a Noise session as responder for this connection.
	session, err := pairing.NewNoiseSession(&pairing.NoiseSessionConfig{
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

	// Pre-handshake identity exchange. The initiator (pkg/pairing
	// PerformHandshake) always sends [version|publicKey] before the Noise
	// handshake. This reference responder keeps no trusted-device store, so it
	// replies "unknown" (empty prologue, matching the session initialized
	// above). A peer that skips the identity exchange is tolerated by treating
	// its first message as Noise msg1.
	first, err := tcpReceive(conn)
	if err != nil {
		s.log.Error("failed to receive first handshake message", "remote", remoteAddr, "error", err)
		return
	}
	msg1 := first
	if len(first) == pairing.IdentityMsgSize && first[0] == pairing.IdentityMsgVersion {
		if err := tcpSend(conn, []byte{pairing.IdentityAckUnknown}); err != nil {
			s.log.Error("failed to send identity ack", "remote", remoteAddr, "error", err)
			return
		}
		msg1, err = tcpReceive(conn)
		if err != nil {
			s.log.Error("failed to receive handshake msg1", "remote", remoteAddr, "error", err)
			return
		}
	}

	// Process msg1 and generate msg2 (e, ee, s, es)
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

	// Clear the handshake deadline before entering the request loop. Not
	// fatal if it fails: requestLoop sets its own idle-timeout deadline
	// before every read, which unconditionally supersedes this one.
	if err := conn.SetDeadline(time.Time{}); err != nil {
		s.log.Warn("failed to clear handshake deadline", "remote", remoteAddr, "error", err)
	}

	s.log.Info("noise handshake completed", "remote", remoteAddr)

	// Enter the encrypted request/response loop.
	s.requestLoop(conn, session, remoteAddr)
}

// requestLoop reads encrypted JSON-RPC requests, decrypts them, delegates
// to the RequestHandler, encrypts the response, and sends it back.
func (s *TCPPairingServer) requestLoop(conn net.Conn, session *pairing.NoiseSession, remoteAddr string) {
	for {
		// Check if the server is shutting down.
		if s.closed.Load() {
			return
		}

		// Set idle timeout before each read. A failure here means the read
		// below could block forever instead of honoring IdleTimeout; treat
		// it as fatal rather than silently reading without a deadline.
		if err := conn.SetReadDeadline(time.Now().Add(s.cfg.IdleTimeout)); err != nil {
			s.log.Error("failed to set idle read deadline", "remote", remoteAddr, "error", err)
			return
		}

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

		// Set write deadline for the response. A failure here means the
		// write below could block forever instead of honoring
		// RequestTimeout; treat it as fatal rather than silently writing
		// without a deadline.
		if err := conn.SetWriteDeadline(time.Now().Add(s.cfg.RequestTimeout)); err != nil {
			s.log.Error("failed to set write deadline", "remote", remoteAddr, "error", err)
			return
		}

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
