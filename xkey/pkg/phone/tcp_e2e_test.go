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
	"encoding/json"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/pairing"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// rpcTestHandler is a peripheral-side JSON-RPC handler that answers the phone
// protocol methods exercised by PhoneKeyBackend. It records the decoded
// requests so tests can assert on what the backend actually sent over the
// encrypted channel.
type rpcTestHandler struct {
	mu       sync.Mutex
	methods  []string
	rawParam map[string]json.RawMessage

	// failMethod, if set, is answered with a JSON-RPC error response.
	failMethod string
	failCode   int
}

func (h *rpcTestHandler) record(method string, params json.RawMessage) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.methods = append(h.methods, method)
	if h.rawParam == nil {
		h.rawParam = make(map[string]json.RawMessage)
	}
	h.rawParam[method] = params
}

func (h *rpcTestHandler) seenMethods() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.methods...)
}

func (h *rpcTestHandler) paramsFor(method string) json.RawMessage {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.rawParam[method]
}

func (h *rpcTestHandler) HandleRequest(_ context.Context, request []byte) ([]byte, error) {
	req, err := DecodeRequest(request)
	if err != nil {
		return nil, err
	}

	var rawParams json.RawMessage
	if req.Params != nil {
		rawParams, _ = json.Marshal(req.Params)
	}
	h.record(req.Method, rawParams)

	if h.failMethod != "" && req.Method == h.failMethod {
		return EncodeErrorResponse(req.ID, h.failCode, "rejected by test handler", nil)
	}

	switch req.Method {
	case MethodPing:
		return EncodeResponse(req.ID, &PingResult{Pong: true})
	case MethodGetInfo:
		return EncodeResponse(req.ID, &GetInfoResult{
			Version:             "2.0",
			DeviceName:          "tcp-phone",
			SupportedAlgorithms: []int{COSEAlgES256},
			MaxCredentials:      10,
			CurrentCredentials:  1,
		})
	case MethodGenerateKey:
		return EncodeResponse(req.ID, &GenerateKeyResult{PublicKeyCOSE: []byte{0xa5, 0x01, 0x02}})
	case MethodSign:
		return EncodeResponse(req.ID, &SignResult{Signature: []byte{0x30, 0x45, 0x02}})
	case MethodLoadKey:
		return EncodeResponse(req.ID, &LoadKeyResult{Exists: true})
	case MethodDeleteKey:
		return EncodeResponse(req.ID, &DeleteKeyResult{Deleted: true})
	case MethodPairingConfirm:
		return EncodeResponse(req.ID, &PairingConfirmResult{Confirmed: true, DeviceName: "tcp-phone"})
	default:
		return EncodeErrorResponse(req.ID, -32601, "method not found", req.Method)
	}
}

// startTCPPairingServer starts a TCPPairingServer on an ephemeral loopback port
// and registers cleanup.
func startTCPPairingServer(t *testing.T, cfg *TCPPairingConfig) *TCPPairingServer {
	t.Helper()

	if cfg.ListenAddr == "" {
		cfg.ListenAddr = "127.0.0.1:0"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}

	srv, err := NewTCPPairingServer(cfg)
	require.NoError(t, err)
	require.NoError(t, srv.Start())
	t.Cleanup(func() { _ = srv.Stop() })

	return srv
}

// dialPhoneBackend connects a PhoneKeyBackend to the given TCP pairing server
// through the production TCPTransport, completing the identity exchange and
// Noise XX handshake.
func dialPhoneBackend(t *testing.T, srv *TCPPairingServer, cfg *PhoneKeyBackendConfig) *PhoneKeyBackend {
	t.Helper()

	transport, err := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
		Address:          srv.Addr(),
		ConnectTimeout:   5 * time.Second,
		OperationTimeout: 5 * time.Second,
		Logger:           slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	require.NoError(t, transport.Connect(context.Background()))

	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.DiscardHandler)
	}
	if cfg.OperationTimeout == 0 {
		cfg.OperationTimeout = 5 * time.Second
	}

	backend, err := NewPhoneKeyBackendWithTransport(cfg, transport)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, backend.Connect(ctx))

	return backend
}

// TestTCPPairingServer_EndToEndWithPhoneBackend drives the complete production
// path: TCPTransport -> identity exchange -> Noise XX -> encrypted JSON-RPC for
// every PhoneKeyBackend operation, against a real listener.
func TestTCPPairingServer_EndToEndWithPhoneBackend(t *testing.T) {
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})
	backend := dialPhoneBackend(t, srv, &PhoneKeyBackendConfig{TrustNewDevices: true})

	// The Noise handshake must have authenticated the server's advertised
	// static key; a mismatch here means the peer identity was not bound.
	assert.Equal(t, srv.LocalStaticPublicKey(), backend.RemoteStaticPublicKey())
	assert.NotEmpty(t, backend.LocalStaticPublicKey())
	assert.Empty(t, backend.ConnectedAddress(), "a TCP transport exposes no BLE address")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	require.NoError(t, backend.Ping(ctx))

	info, err := backend.GetDeviceInfo(ctx)
	require.NoError(t, err)
	assert.Equal(t, "tcp-phone", info.DeviceName)
	assert.Equal(t, "2.0", info.Version)

	credID := []byte("tcp-credential-id")
	handle, pub, err := backend.GenerateCredentialKey(COSEAlgES256, credID)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa5, 0x01, 0x02}, pub)
	assert.Equal(t, credID, handle.CredentialID())
	assert.Equal(t, COSEAlgES256, handle.Algorithm())

	sig, err := backend.Sign(handle, COSEAlgES256, []byte("digest"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x45, 0x02}, sig)

	// The generate call cached the handle, so LoadKey is served locally.
	cached, err := backend.LoadKey(credID, COSEAlgES256)
	require.NoError(t, err)
	assert.Equal(t, handle, cached)

	// A different credential ID must go over the wire.
	otherID := []byte("other-credential-id")
	loaded, err := backend.LoadKey(otherID, COSEAlgES256)
	require.NoError(t, err)
	assert.Equal(t, otherID, loaded.CredentialID())

	confirm, err := backend.SendPairingConfirm(ctx, "laptop")
	require.NoError(t, err)
	assert.True(t, confirm.Confirmed)
	assert.Equal(t, "tcp-phone", confirm.DeviceName)

	require.NoError(t, backend.DeleteKey(handle))

	assert.Equal(t, []string{
		MethodPing,
		MethodGetInfo,
		MethodGenerateKey,
		MethodSign,
		MethodLoadKey,
		MethodPairingConfirm,
		MethodDeleteKey,
	}, handler.seenMethods())

	// The sign request must carry the credential ID and force user verification.
	var signParams SignParams
	require.NoError(t, json.Unmarshal(handler.paramsFor(MethodSign), &signParams))
	assert.Equal(t, credID, signParams.CredentialID)
	assert.Equal(t, []byte("digest"), signParams.DataHash)
	assert.True(t, signParams.UserVerificationRequired,
		"phone signing must always require biometric verification")
}

// TestTCPPairingServer_RemoteKeyMismatchAbortsHandshake proves the backend
// refuses a server whose static key differs from the pinned one.
func TestTCPPairingServer_RemoteKeyMismatchAbortsHandshake(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	wrongKey, err := GenerateStaticKey()
	require.NoError(t, err)

	transport, err := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
		Address:          srv.Addr(),
		OperationTimeout: 5 * time.Second,
		Logger:           slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	require.NoError(t, transport.Connect(context.Background()))

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		ExpectedRemoteStatic: wrongKey.Public,
		Logger:               slog.New(slog.DiscardHandler),
	}, transport)
	require.NoError(t, err)
	defer func() { _ = backend.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	err = backend.Connect(ctx)
	require.Error(t, err)
	assert.False(t, backend.IsConnected())
}

// TestTCPPairingServer_MidStreamTransportFailure verifies a request issued
// after the peer disappears surfaces a connection error instead of hanging or
// returning a bogus response.
func TestTCPPairingServer_MidStreamTransportFailure(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})
	backend := dialPhoneBackend(t, srv, &PhoneKeyBackendConfig{TrustNewDevices: true})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, backend.Ping(ctx))

	require.NoError(t, srv.Stop())

	err := backend.Ping(ctx)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrNotConnected)
}

// TestTCPPairingServer_PhoneErrorResponseIsMapped verifies a JSON-RPC error
// from the peripheral is mapped to the corresponding typed error.
func TestTCPPairingServer_PhoneErrorResponseIsMapped(t *testing.T) {
	t.Parallel()

	handler := &rpcTestHandler{failMethod: MethodSign, failCode: pairing.ErrorCodeUserCancelled}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})
	backend := dialPhoneBackend(t, srv, &PhoneKeyBackendConfig{TrustNewDevices: true})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, _, err := backend.GenerateCredentialKey(COSEAlgES256, []byte("cred-for-cancel"))
	require.NoError(t, err)

	_, err = backend.Sign(handle, COSEAlgES256, []byte("digest"))
	assert.ErrorIs(t, err, ErrUserCancelled)

	// The channel must remain usable after a protocol-level (non-fatal) error.
	require.NoError(t, backend.Ping(ctx))
}

// TestTCPPairingServer_HandshakeMsg1GarbageClosesConnection ensures the server
// drops a peer that sends a malformed Noise msg1 rather than proceeding.
func TestTCPPairingServer_HandshakeMsg1GarbageClosesConnection(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Perform the identity exchange, then send junk in place of msg1.
	identity := make([]byte, pairing.IdentityMsgSize)
	identity[0] = pairing.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairing.IdentityAckUnknown}, ack)

	require.NoError(t, tcpSend(conn, []byte("not a noise handshake message")))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "server must close the connection on an invalid handshake msg1")
}

// TestTCPPairingServer_HandshakeMsg3GarbageClosesConnection ensures a peer that
// completes msg1/msg2 but sends a corrupt msg3 is dropped.
func TestTCPPairingServer_HandshakeMsg3GarbageClosesConnection(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	require.NoError(t, session.InitHandshake())

	msg1, _, err := session.HandshakeMessage(nil)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, msg1))

	_, err = tcpReceive(conn)
	require.NoError(t, err)

	// Corrupt msg3: the AEAD tag will not verify on the server side.
	require.NoError(t, tcpSend(conn, make([]byte, 64)))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "server must close the connection on an invalid handshake msg3")
}

// TestTCPPairingServer_UndecryptableRequestClosesConnection ensures a forged or
// replayed ciphertext terminates the session instead of being processed.
func TestTCPPairingServer_UndecryptableRequestClosesConnection(t *testing.T) {
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	// A legitimate request first, to prove the channel works.
	req, err := EncodeRequest(NewRequest(MethodPing, nil))
	require.NoError(t, err)
	ciphertext, err := clientSession.Encrypt(req)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, ciphertext))
	respCiphertext, err := tcpReceive(conn)
	require.NoError(t, err)
	respPlain, err := clientSession.Decrypt(respCiphertext)
	require.NoError(t, err)
	resp, err := DecodeResponse(respPlain)
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	// Now replay the same ciphertext: the nonce has advanced, so it must fail
	// to decrypt and the server must drop the connection.
	require.NoError(t, tcpSend(conn, ciphertext))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "server must close the connection when decryption fails")

	assert.Equal(t, []string{MethodPing}, handler.seenMethods(),
		"the replayed frame must never reach the request handler")
}

// TestTCPPairingServer_IdleTimeoutClosesConnection verifies the idle timeout is
// enforced on an established encrypted session.
func TestTCPPairingServer_IdleTimeoutClosesConnection(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{
		RequestHandler: &rpcTestHandler{},
		IdleTimeout:    150 * time.Millisecond,
	})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	clientHandshake(t, conn)

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "an idle connection must be closed by the server")
}

// TestTCPPairingServer_SkipsIdentityExchange verifies the documented tolerance
// for peers that jump straight to Noise msg1 without the identity preamble.
func TestTCPPairingServer_SkipsIdentityExchange(t *testing.T) {
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	req, err := EncodeRequest(NewRequest(MethodGetInfo, nil))
	require.NoError(t, err)
	ciphertext, err := clientSession.Encrypt(req)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, ciphertext))

	respCiphertext, err := tcpReceive(conn)
	require.NoError(t, err)
	respPlain, err := clientSession.Decrypt(respCiphertext)
	require.NoError(t, err)

	resp, err := DecodeResponse(respPlain)
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	info, err := DecodeResult[GetInfoResult](resp)
	require.NoError(t, err)
	assert.Equal(t, "tcp-phone", info.DeviceName)
}

// TestTCPPairingServer_IdentityAckThenDisconnect covers the server's handling
// of a peer that starts the identity exchange and then vanishes.
func TestTCPPairingServer_IdentityAckThenDisconnect(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)

	identity := make([]byte, pairing.IdentityMsgSize)
	identity[0] = pairing.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairing.IdentityAckUnknown}, ack)

	require.NoError(t, conn.Close())

	// The server must reclaim the connection slot; Stop returning promptly
	// proves the handler goroutine exited rather than leaking.
	done := make(chan error, 1)
	go func() { done <- srv.Stop() }()
	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Stop did not drain the abandoned connection")
	}
}

// TestTCPPairingServer_LocalStaticPublicKeyNilKey covers the defensive nil-key
// branch of LocalStaticPublicKey.
func TestTCPPairingServer_LocalStaticPublicKeyNilKey(t *testing.T) {
	t.Parallel()

	srv := &TCPPairingServer{}
	assert.Nil(t, srv.LocalStaticPublicKey())
}

// TestTCPPairingServer_StopClosesIdleConnection is a regression test: Stop must
// close established-but-idle connections rather than blocking until the idle
// timeout expires. Before the fix, Stop blocked for the full IdleTimeout
// (5 minutes by default) whenever a peer stayed connected without sending.
func TestTCPPairingServer_StopClosesIdleConnection(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{
		RequestHandler: &rpcTestHandler{},
		IdleTimeout:    time.Hour,
	})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Complete the handshake so the server is parked in requestLoop's read.
	clientHandshake(t, conn)

	stopped := make(chan error, 1)
	go func() { stopped <- srv.Stop() }()

	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("Stop blocked on an idle connection instead of closing it")
	}

	// The peer must observe the close.
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "the server must have closed the connection")
}

// TestTCPPairingServer_DisconnectBeforeMsg3 covers the server's handling of a
// peer that abandons the handshake after receiving msg2.
func TestTCPPairingServer_DisconnectBeforeMsg3(t *testing.T) {
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)

	identity := make([]byte, pairing.IdentityMsgSize)
	identity[0] = pairing.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairing.IdentityAckUnknown}, ack)

	session, err := NewNoiseSession(&NoiseSessionConfig{IsInitiator: true})
	require.NoError(t, err)
	require.NoError(t, session.InitHandshake())
	msg1, _, err := session.HandshakeMessage(nil)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, msg1))

	_, err = tcpReceive(conn)
	require.NoError(t, err, "server must answer with msg2")

	// Vanish instead of sending msg3.
	require.NoError(t, conn.Close())

	stopped := make(chan error, 1)
	go func() { stopped <- srv.Stop() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server did not reclaim the abandoned handshake")
	}
}

// TestTCPPairingServer_TruncatedRequestFrame verifies the server tears down a
// session whose framing is inconsistent instead of blocking forever on a
// length prefix that will never be satisfied.
func TestTCPPairingServer_TruncatedRequestFrame(t *testing.T) {
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)

	clientHandshake(t, conn)

	// Announce 16 bytes, deliver 3, then close.
	_, err = conn.Write([]byte{0x00, 0x10, 0x01, 0x02, 0x03})
	require.NoError(t, err)
	require.NoError(t, conn.Close())

	stopped := make(chan error, 1)
	go func() { stopped <- srv.Stop() }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("server blocked on a truncated frame")
	}

	assert.Empty(t, handler.seenMethods(), "a truncated frame must never reach the handler")
}
