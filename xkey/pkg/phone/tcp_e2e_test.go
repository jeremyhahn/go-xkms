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
	"errors"
	"log/slog"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pairingproto"
	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
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
	req, err := pairingproto.DecodeRequest(request)
	if err != nil {
		return nil, err
	}

	var rawParams json.RawMessage
	if req.Params != nil {
		rawParams, _ = json.Marshal(req.Params)
	}
	h.record(req.Method, rawParams)

	if h.failMethod != "" && req.Method == h.failMethod {
		return pairingproto.EncodeErrorResponse(req.ID, req.Generation, h.failCode, "rejected by test handler", nil)
	}

	switch req.Method {
	case pairingproto.MethodPing:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.PingResult{Pong: true})
	case pairingproto.MethodGetInfo:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.GetInfoResult{
			Version:             "2.0",
			DeviceName:          "tcp-phone",
			SupportedAlgorithms: []int{pairingproto.COSEAlgES256},
			MaxCredentials:      10,
			CurrentCredentials:  1,
		})
	case pairingproto.MethodGenerateKey:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.GenerateKeyResult{PublicKeyCOSE: []byte{0xa5, 0x01, 0x02}})
	case pairingproto.MethodSign:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.SignResult{Signature: []byte{0x30, 0x45, 0x02}})
	case pairingproto.MethodLoadKey:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.LoadKeyResult{Exists: true})
	case pairingproto.MethodDeleteKey:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.DeleteKeyResult{Deleted: true})
	case pairingproto.MethodPairingConfirm:
		return pairingproto.EncodeResponse(req.ID, req.Generation, &pairingproto.PairingConfirmResult{Confirmed: true, DeviceName: "tcp-phone"})
	default:
		return pairingproto.EncodeErrorResponse(req.ID, req.Generation, -32601, "method not found", req.Method)
	}
}

// alwaysLiveAttestForTest is a pairingproto.LiveAttestFunc stand-in for tests that
// exercise the request-serving loop, not the #129 live-attestation gate that
// now runs ahead of it. It is deliberately local to the test binary: nothing
// in production may treat "no live attestation" as automatically approved.
func alwaysLiveAttestForTest(context.Context, pairingproto.RPCExchange, []byte) error {
	return nil
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
	// A test that wants the gate itself sets cfg.LiveAttest before calling
	// this and is left alone.
	if cfg.LiveAttest == nil {
		cfg.LiveAttest = alwaysLiveAttestForTest
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
	if !noiseOutsideFIPS(t) {
		return
	}
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
	handle, pub, err := backend.GenerateCredentialKey(pairingproto.COSEAlgES256, credID)
	require.NoError(t, err)
	assert.Equal(t, []byte{0xa5, 0x01, 0x02}, pub)
	assert.Equal(t, credID, handle.CredentialID())
	assert.Equal(t, pairingproto.COSEAlgES256, handle.Algorithm())

	sig, err := backend.Sign(handle, pairingproto.COSEAlgES256, []byte("digest"))
	require.NoError(t, err)
	assert.Equal(t, []byte{0x30, 0x45, 0x02}, sig)

	// The generate call cached the handle, so LoadKey is served locally.
	cached, err := backend.LoadKey(credID, pairingproto.COSEAlgES256)
	require.NoError(t, err)
	assert.Equal(t, handle, cached)

	// A different credential ID must go over the wire.
	otherID := []byte("other-credential-id")
	loaded, err := backend.LoadKey(otherID, pairingproto.COSEAlgES256)
	require.NoError(t, err)
	assert.Equal(t, otherID, loaded.CredentialID())

	confirm, err := backend.SendPairingConfirm(ctx, "laptop")
	require.NoError(t, err)
	assert.True(t, confirm.Confirmed)
	assert.Equal(t, "tcp-phone", confirm.DeviceName)

	require.NoError(t, backend.DeleteKey(handle))

	assert.Equal(t, []string{
		pairingproto.MethodPing,
		pairingproto.MethodGetInfo,
		pairingproto.MethodGenerateKey,
		pairingproto.MethodSign,
		pairingproto.MethodLoadKey,
		pairingproto.MethodPairingConfirm,
		pairingproto.MethodDeleteKey,
	}, handler.seenMethods())

	// The sign request must carry the credential ID and force user verification.
	var signParams pairingproto.SignParams
	require.NoError(t, json.Unmarshal(handler.paramsFor(pairingproto.MethodSign), &signParams))
	assert.Equal(t, credID, signParams.CredentialID)
	assert.Equal(t, []byte("digest"), signParams.DataHash)
	assert.True(t, signParams.UserVerificationRequired,
		"phone signing must always require biometric verification")
}

// TestTCPPairingServer_RemoteKeyMismatchAbortsHandshake proves the backend
// refuses a server whose static key differs from the pinned one.
func TestTCPPairingServer_RemoteKeyMismatchAbortsHandshake(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	wrongKey, err := bootstrap.GenerateNoiseStaticKey()
	require.NoError(t, err)

	transport, err := pairing.NewTCPTransport(&pairing.TCPTransportConfig{
		Address:          srv.Addr(),
		OperationTimeout: 5 * time.Second,
		Logger:           slog.New(slog.DiscardHandler),
	})
	require.NoError(t, err)
	require.NoError(t, transport.Connect(context.Background()))

	backend, err := NewPhoneKeyBackendWithTransport(&PhoneKeyBackendConfig{
		ExpectedRemoteStatic: wrongKey.PublicBytes(),
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
//
// It used to assert ErrNotConnected on the FIRST request after the peer went
// away, which is not a property the test can rely on (#85). That error is
// produced by classifyReadError, and only for io.EOF:
//
//	EOF / ErrUnexpectedEOF -> ErrNotConnected
//	any other read error   -> ErrConnectionFailed
//
// Whether a closing peer produces a clean FIN (read returns EOF) or an RST
// (read returns ECONNRESET) is decided by the kernel and the timing of the
// teardown, not by anything this test controls -- so on a loaded runner the
// first call could legitimately come back ErrConnectionFailed and fail an
// assertion about a contract that was never broken.
//
// Both errors mean the same thing to a caller, and that IS the contract worth
// asserting: the request failed, promptly, because the peer is gone.
//
// The specific ErrNotConnected contract is then asserted where it is
// deterministic. classifyReadError and handleWriteError both clear the
// transport's connected flag, so the first failure is itself the state
// transition -- every request after it is refused by Send's own check before
// any I/O. No polling and no sleep: the ordering is established by the
// preceding call, not waited for.
func TestTCPPairingServer_MidStreamTransportFailure(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})
	backend := dialPhoneBackend(t, srv, &PhoneKeyBackendConfig{TrustNewDevices: true})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	require.NoError(t, backend.Ping(ctx))

	require.NoError(t, srv.Stop())

	// A deadline short enough that a Ping which HANGS on a dead peer fails
	// here, which is the "instead of hanging" half of what this test claims.
	failFast, cancelFailFast := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFailFast()

	err := backend.Ping(failFast)
	require.Error(t, err, "a request after the peer disappeared must fail")
	require.NotErrorIs(t, err, context.DeadlineExceeded,
		"the request hung on a dead peer instead of failing")
	require.True(t,
		errors.Is(err, ErrNotConnected) || errors.Is(err, ErrConnectionFailed),
		"want a connection-failure error (FIN gives ErrNotConnected, RST gives "+
			"ErrConnectionFailed; the peer decides which), got %v", err)

	// The call above cleared the transport's connected flag, so this one is
	// refused before any I/O and cannot depend on how the socket died.
	assert.ErrorIs(t, backend.Ping(failFast), ErrNotConnected)
}

// TestTCPPairingServer_PhoneErrorResponseIsMapped verifies a JSON-RPC error
// from the peripheral is mapped to the corresponding typed error.
func TestTCPPairingServer_PhoneErrorResponseIsMapped(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	handler := &rpcTestHandler{failMethod: pairingproto.MethodSign, failCode: pairingproto.ErrorCodeUserCancelled}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})
	backend := dialPhoneBackend(t, srv, &PhoneKeyBackendConfig{TrustNewDevices: true})

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	handle, _, err := backend.GenerateCredentialKey(pairingproto.COSEAlgES256, []byte("cred-for-cancel"))
	require.NoError(t, err)

	_, err = backend.Sign(handle, pairingproto.COSEAlgES256, []byte("digest"))
	assert.ErrorIs(t, err, ErrUserCancelled)

	// The channel must remain usable after a protocol-level (non-fatal) error.
	require.NoError(t, backend.Ping(ctx))
}

// TestTCPPairingServer_HandshakeMsg1GarbageClosesConnection ensures the server
// drops a peer that sends a malformed Noise msg1 rather than proceeding.
func TestTCPPairingServer_HandshakeMsg1GarbageClosesConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	// Perform the identity exchange, then send junk in place of msg1.
	identity := make([]byte, pairingproto.IdentityMsgSize)
	identity[0] = pairingproto.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairingproto.IdentityAckUnknown}, ack)

	require.NoError(t, tcpSend(conn, []byte("not a noise handshake message")))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "server must close the connection on an invalid handshake msg1")
}

// TestTCPPairingServer_HandshakeMsg3GarbageClosesConnection ensures a peer that
// completes msg1/msg2 but sends a corrupt msg3 is dropped.
func TestTCPPairingServer_HandshakeMsg3GarbageClosesConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
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
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	// A legitimate request first, to prove the channel works.
	req, err := pairingproto.EncodeRequest(pairingproto.NewRequest(pairingproto.MethodPing, nil))
	require.NoError(t, err)
	ciphertext, err := clientSession.Encrypt(req)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, ciphertext))
	respCiphertext, err := tcpReceive(conn)
	require.NoError(t, err)
	respPlain, err := clientSession.Decrypt(respCiphertext)
	require.NoError(t, err)
	resp, err := pairingproto.DecodeResponse(respPlain)
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	// Now replay the same ciphertext: the nonce has advanced, so it must fail
	// to decrypt and the server must drop the connection.
	require.NoError(t, tcpSend(conn, ciphertext))

	require.NoError(t, conn.SetReadDeadline(time.Now().Add(5*time.Second)))
	_, err = tcpReceive(conn)
	assert.Error(t, err, "server must close the connection when decryption fails")

	assert.Equal(t, []string{pairingproto.MethodPing}, handler.seenMethods(),
		"the replayed frame must never reach the request handler")
}

// TestTCPPairingServer_IdleTimeoutClosesConnection verifies the idle timeout is
// enforced on an established encrypted session.
func TestTCPPairingServer_IdleTimeoutClosesConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
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
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	handler := &rpcTestHandler{}
	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: handler})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	clientSession := clientHandshake(t, conn)

	req, err := pairingproto.EncodeRequest(pairingproto.NewRequest(pairingproto.MethodGetInfo, nil))
	require.NoError(t, err)
	ciphertext, err := clientSession.Encrypt(req)
	require.NoError(t, err)
	require.NoError(t, tcpSend(conn, ciphertext))

	respCiphertext, err := tcpReceive(conn)
	require.NoError(t, err)
	respPlain, err := clientSession.Decrypt(respCiphertext)
	require.NoError(t, err)

	resp, err := pairingproto.DecodeResponse(respPlain)
	require.NoError(t, err)
	require.Nil(t, resp.Error)

	info, err := pairingproto.DecodeResult[pairingproto.GetInfoResult](resp)
	require.NoError(t, err)
	assert.Equal(t, "tcp-phone", info.DeviceName)
}

// TestTCPPairingServer_IdentityAckThenDisconnect covers the server's handling
// of a peer that starts the identity exchange and then vanishes.
func TestTCPPairingServer_IdentityAckThenDisconnect(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)

	identity := make([]byte, pairingproto.IdentityMsgSize)
	identity[0] = pairingproto.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairingproto.IdentityAckUnknown}, ack)

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
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := &TCPPairingServer{}
	assert.Nil(t, srv.LocalStaticPublicKey())
}

// TestTCPPairingServer_StopClosesIdleConnection is a regression test: Stop must
// close established-but-idle connections rather than blocking until the idle
// timeout expires. Before the fix, Stop blocked for the full IdleTimeout
// (5 minutes by default) whenever a peer stayed connected without sending.
func TestTCPPairingServer_StopClosesIdleConnection(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
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
	if !noiseOutsideFIPS(t) {
		return
	}
	t.Parallel()

	srv := startTCPPairingServer(t, &TCPPairingConfig{RequestHandler: &rpcTestHandler{}})

	conn, err := net.DialTimeout("tcp", srv.Addr(), 5*time.Second)
	require.NoError(t, err)

	identity := make([]byte, pairingproto.IdentityMsgSize)
	identity[0] = pairingproto.IdentityMsgVersion
	require.NoError(t, tcpSend(conn, identity))

	ack, err := tcpReceive(conn)
	require.NoError(t, err)
	require.Equal(t, []byte{pairingproto.IdentityAckUnknown}, ack)

	session, err := bootstrap.NewNoiseSession(&bootstrap.NoiseSessionConfig{IsInitiator: true})
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
	if !noiseOutsideFIPS(t) {
		return
	}
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
