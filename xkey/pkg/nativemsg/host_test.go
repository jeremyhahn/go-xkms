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

package nativemsg

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testLogger returns a discarding logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// startMockIPCServer creates a Unix domain socket server that echoes status
// responses for any IPC message it receives.
func startMockIPCServer(t *testing.T, socketPath string) (net.Listener, func()) {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockConn(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener, cleanup
}

// handleMockConn reads one IPC message and responds with an OK status response.
func handleMockConn(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	var msg ipc.Message
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&msg); err != nil {
		return
	}

	resp := &ipc.Response{
		Status: ipc.StatusOK,
		Action: ipc.ActionDaemonReady,
	}

	encoder := json.NewEncoder(conn)
	encoder.Encode(resp)
}

func TestHost_Handshake_Success(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	_, cleanup := startMockIPCServer(t, socketPath)
	defer cleanup()

	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	// Prepare extension handshake message.
	extCrypto, extPubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	handshakeMsg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(extPubKey),
	}
	require.NoError(t, WriteMessage(hostStdin, handshakeMsg))

	// Run the handshake portion only.
	err = host.handshake()
	require.NoError(t, err)
	assert.True(t, host.crypto.Ready())

	// Read the handshake_ok from stdout.
	resp, err := ReadMessage(hostStdout)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeOK, resp.Type)
	assert.NotEmpty(t, resp.PubKey)

	// Complete the extension side.
	hostPubKey, err := base64.StdEncoding.DecodeString(resp.PubKey)
	require.NoError(t, err)
	err = extCrypto.CompleteHandshake(hostPubKey)
	require.NoError(t, err)
	assert.True(t, extCrypto.Ready())
}

func TestHost_Handshake_InvalidFirstMessage(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	// Write an encrypted message instead of a handshake.
	wrongMsg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      1,
		Ciphertext: "dGVzdA==",
	}
	require.NoError(t, WriteMessage(hostStdin, wrongMsg))

	err := host.handshake()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHandshakeFailed))
}

func TestHost_Handshake_MissingPubKey(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	// Handshake without pubkey.
	msg := &NativeMessage{Type: MsgTypeHandshake}
	require.NoError(t, WriteMessage(hostStdin, msg))

	err := host.handshake()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHandshakeFailed))
}

func TestHost_Handshake_InvalidBase64PubKey(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	msg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: "not-valid-base64!!!",
	}
	require.NoError(t, WriteMessage(hostStdin, msg))

	err := host.handshake()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPublicKey))
}

func TestHost_Handshake_InvalidPubKeySize(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	// Valid base64 but wrong key size (only 16 bytes instead of 32).
	shortKey := make([]byte, 16)
	msg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(shortKey),
	}
	require.NoError(t, WriteMessage(hostStdin, msg))

	err := host.handshake()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidPublicKey))
}

func TestHost_EncryptedRelay_EndToEnd(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	_, cleanup := startMockIPCServer(t, socketPath)
	defer cleanup()

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, nil)

	// Write handshake to host stdin.
	extCrypto, extPubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	handshakeMsg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(extPubKey),
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	// Run host in background.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// Read handshake_ok from stdout.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeOK, resp.Type)

	hostPubKey, err := base64.StdEncoding.DecodeString(resp.PubKey)
	require.NoError(t, err)
	require.NoError(t, extCrypto.CompleteHandshake(hostPubKey))

	// Send an encrypted IPC status request.
	ipcMsg := &ipc.Message{Type: ipc.MessageTypeStatus}
	ipcJSON, err := json.Marshal(ipcMsg)
	require.NoError(t, err)

	nonce, ct, err := extCrypto.Encrypt(ipcJSON)
	require.NoError(t, err)

	encMsg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      nonce,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	require.NoError(t, WriteMessage(stdinW, encMsg))

	// Read the encrypted response from stdout.
	encResp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeEncrypted, encResp.Type)

	// Decrypt the response.
	respCT, err := base64.StdEncoding.DecodeString(encResp.Ciphertext)
	require.NoError(t, err)
	respPlain, err := extCrypto.Decrypt(encResp.Nonce, respCT)
	require.NoError(t, err)

	var ipcResp ipc.Response
	require.NoError(t, json.Unmarshal(respPlain, &ipcResp))
	assert.Equal(t, ipc.StatusOK, ipcResp.Status)
	assert.Equal(t, ipc.ActionDaemonReady, ipcResp.Action)

	// Close stdin to signal the host to stop (simulates browser disconnect).
	stdinW.Close()

	select {
	case err := <-errCh:
		// nil (clean EOF exit) is expected.
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop within timeout")
	}
}

func TestHost_StdinEOF_CleanlyShutsDown(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	_, cleanup := startMockIPCServer(t, socketPath)
	defer cleanup()

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, nil)

	// Write handshake.
	_, extPubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	handshakeMsg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(extPubKey),
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	ctx := context.Background()
	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// Read the handshake response to synchronize.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeOK, resp.Type)

	// Close stdin to simulate browser closing extension.
	stdinW.Close()

	select {
	case err := <-errCh:
		// Should return nil (clean shutdown on EOF).
		assert.NoError(t, err)
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop within timeout after stdin EOF")
	}
}

func TestHost_ContextCancellation_StopsHost(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	_, cleanup := startMockIPCServer(t, socketPath)
	defer cleanup()

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, nil)

	// Write handshake.
	_, extPubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	handshakeMsg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(extPubKey),
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// Read the handshake response to synchronize.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeOK, resp.Type)

	// Cancel the context and close stdin to unblock the blocking ReadMessage.
	cancel()
	stdinW.Close()

	select {
	case err := <-errCh:
		// Either nil (EOF detected first) or context.Canceled is acceptable.
		if err != nil {
			assert.ErrorIs(t, err, context.Canceled)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop within timeout after context cancellation")
	}
}

func TestHost_Handshake_EmptyStdin(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Empty stdin.
	hostStdin := &bytes.Buffer{}
	hostStdout := &bytes.Buffer{}

	host := NewHostWithIO(socketPath, testLogger(), hostStdin, hostStdout, nil)

	err := host.handshake()
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrHandshakeFailed))
}

func TestHost_NewHost_DefaultIO(t *testing.T) {
	h := NewHost("/tmp/test.sock", testLogger(), nil)
	assert.NotNil(t, h)
	assert.Equal(t, "/tmp/test.sock", h.ipcSocketPath)
	assert.Equal(t, os.Stdin, h.stdin)
	assert.Equal(t, os.Stdout, h.stdout)
}

func TestHost_IPCConnectionFailure(t *testing.T) {
	tmpDir := t.TempDir()
	// Use a socket path where no server is listening.
	socketPath := filepath.Join(tmpDir, "nonexistent.sock")

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, nil)

	// Write handshake.
	extCrypto, extPubKey, err := NewSessionCrypto()
	require.NoError(t, err)

	handshakeMsg := &NativeMessage{
		Type:   MsgTypeHandshake,
		PubKey: base64.StdEncoding.EncodeToString(extPubKey),
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// Complete extension handshake.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	hostPubKey, err := base64.StdEncoding.DecodeString(resp.PubKey)
	require.NoError(t, err)
	require.NoError(t, extCrypto.CompleteHandshake(hostPubKey))

	// Send an encrypted message - the IPC forward should fail.
	ipcMsg := &ipc.Message{Type: ipc.MessageTypeStatus}
	ipcJSON, err := json.Marshal(ipcMsg)
	require.NoError(t, err)

	nonce, ct, err := extCrypto.Encrypt(ipcJSON)
	require.NoError(t, err)

	encMsg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      nonce,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	require.NoError(t, WriteMessage(stdinW, encMsg))

	// The host should write an error message back to stdout.
	// Give it a small window to process.
	time.Sleep(100 * time.Millisecond)

	errResp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeError, errResp.Type)
	assert.NotEmpty(t, errResp.Error)

	// Cleanup.
	cancel()
	stdinW.Close()

	select {
	case <-errCh:
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop")
	}
}

// osPipe creates an os.Pipe and registers cleanup.
func osPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	r, w, err := os.Pipe()
	require.NoError(t, err)
	t.Cleanup(func() {
		r.Close()
		w.Close()
	})
	return r, w
}

// handleMockConnWithPairing reads one IPC message and responds with an OK
// response. For pairing messages it includes a PairingResult with
// Acknowledged=true; all other messages get a generic OK/DaemonReady response.
func handleMockConnWithPairing(conn net.Conn) {
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return
	}

	var msg ipc.Message
	if err := json.NewDecoder(conn).Decode(&msg); err != nil {
		return
	}

	var resp *ipc.Response
	if msg.Type == ipc.MessageTypePairing {
		resp = &ipc.Response{
			Status:  ipc.StatusOK,
			Pairing: &ipc.PairingResult{Acknowledged: true},
		}
	} else {
		resp = &ipc.Response{
			Status: ipc.StatusOK,
			Action: ipc.ActionDaemonReady,
		}
	}

	json.NewEncoder(conn).Encode(resp)
}

// startMockIPCServerWithPairing creates a Unix domain socket server that
// handles both regular IPC messages and pairing notification messages.
func startMockIPCServerWithPairing(t *testing.T, socketPath string) (net.Listener, func()) {
	t.Helper()

	listener, err := net.Listen("unix", socketPath)
	require.NoError(t, err)

	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleMockConnWithPairing(conn)
		}
	}()

	cleanup := func() {
		listener.Close()
		<-done
	}

	return listener, cleanup
}

func TestHost_Pairing_FullCeremony(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, pairing.IsPaired())

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, pairing)

	// Generate an Ed25519 identity keypair for the "extension".
	extIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Generate an X25519 ephemeral keypair for the handshake ECDH.
	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Write the handshake message with identity key and origin.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
		Origin:      "chrome-extension://test/",
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	// Run host.handshake() in a goroutine because it blocks waiting for
	// the pairing_confirm message on stdin.
	var hsErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hsErr = host.handshake()
	}()

	// Read the handshake_pair response from stdout.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakePair, resp.Type)
	assert.True(t, resp.PairingRequired)
	assert.NotEmpty(t, resp.PubKey)

	// Retrieve the generated pairing code from the verifier's pending state.
	// This is accessible because the test is in the same package.
	require.NotNil(t, pairing.pending)
	code := pairing.pending.code
	require.Len(t, code, pairingCodeLength)

	// Write the pairing_confirm message with the correct code and identity key.
	confirmMsg := &NativeMessage{
		Type:        MsgTypePairingConfirm,
		Code:        code,
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
	}
	require.NoError(t, WriteMessage(stdinW, confirmMsg))

	// Wait for the handshake goroutine to complete.
	wg.Wait()
	require.NoError(t, hsErr)

	// Read pairing_ok from stdout. The host no longer sends a second
	// handshake_ok after pairing — the extension already received the
	// X25519 pubkey in the initial handshake_pair response.
	pairingOKResp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingOK, pairingOKResp.Type)

	// Verify the extension is now paired.
	assert.True(t, pairing.IsPaired())
	state := pairing.GetStateForOrigin("chrome-extension://test/")
	require.NotNil(t, state)
	assert.Equal(t, []byte(extIdentityPub), state.IdentityKey)
}

func TestHost_Pairing_InvalidCode(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, pairing)

	// Generate an Ed25519 identity keypair for the "extension".
	extIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Generate an X25519 ephemeral keypair for the handshake ECDH.
	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Write the handshake message with identity and origin.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
		Origin:      "chrome-extension://test/",
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	// Run host.handshake() in a goroutine.
	var hsErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hsErr = host.handshake()
	}()

	// Read the handshake_pair response.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakePair, resp.Type)
	assert.True(t, resp.PairingRequired)

	// Submit a wrong pairing code.
	confirmMsg := &NativeMessage{
		Type:        MsgTypePairingConfirm,
		Code:        "000000",
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
	}
	require.NoError(t, WriteMessage(stdinW, confirmMsg))

	// Wait for the handshake goroutine to complete.
	wg.Wait()

	// The handshake should have returned ErrPairingInvalidCode.
	require.Error(t, hsErr)
	assert.ErrorIs(t, hsErr, ErrPairingInvalidCode)

	// Read the pairing_failed message from stdout.
	failedResp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, failedResp.Type)
	assert.NotEmpty(t, failedResp.Error)

	// Verify the extension is NOT paired.
	assert.False(t, pairing.IsPaired())
}

func TestHost_Pairing_IdentityMismatchTriggersRepairing(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	// Create a verifier that is ALREADY paired with identity A.
	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	oldIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pairing.states["chrome-extension://old-ext/"] = &PairingState{
		IdentityKey: oldIdentityPub,
		PairedAt:    time.Now().Add(-24 * time.Hour),
	}
	require.True(t, pairing.IsPaired())

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, pairing)

	// Generate a NEW Ed25519 identity keypair (simulates reinstalled extension).
	newIdentityPub, newIdentityPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)
	require.False(t, ed25519.PublicKey(oldIdentityPub).Equal(newIdentityPub))

	// Generate an X25519 ephemeral keypair for ECDH.
	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Sign the ephemeral key + origin (the host still checks IdentitySig != ""
	// and decodes it before calling VerifyIdentity).
	origin := "chrome-extension://new-ext/"
	signData := computeSignData(extEphemeralPub, origin)
	sig := ed25519.Sign(newIdentityPriv, signData)

	// Send handshake with the NEW identity key.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(newIdentityPub),
		IdentitySig: base64.StdEncoding.EncodeToString(sig),
		Origin:      origin,
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	// Run host.handshake() in a goroutine because it blocks waiting
	// for the pairing_confirm message.
	var hsErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hsErr = host.handshake()
	}()

	// The host should initiate re-pairing (not reject).
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakePair, resp.Type, "expected re-pairing, got %s", resp.Type)
	assert.True(t, resp.PairingRequired)
	assert.NotEmpty(t, resp.PubKey)

	// Get the pairing code from the pending state.
	require.NotNil(t, pairing.pending)
	code := pairing.pending.code
	require.Len(t, code, pairingCodeLength)

	// Complete the re-pairing ceremony with the correct code.
	confirmMsg := &NativeMessage{
		Type:        MsgTypePairingConfirm,
		Code:        code,
		IdentityKey: base64.StdEncoding.EncodeToString(newIdentityPub),
	}
	require.NoError(t, WriteMessage(stdinW, confirmMsg))

	wg.Wait()
	require.NoError(t, hsErr)

	// Read pairing_ok.
	pairingOK, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingOK, pairingOK.Type)

	// Verify the NEW identity is stored (not the old one).
	assert.True(t, pairing.IsPaired())
	state := pairing.GetStateForOrigin(origin)
	require.NotNil(t, state)
	assert.Equal(t, []byte(newIdentityPub), state.IdentityKey)
	assert.False(t, ed25519.PublicKey(state.IdentityKey).Equal(oldIdentityPub),
		"should store new identity, not old")
}

func TestHost_Pairing_BadSignatureRejectsNotRepairs(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	// Create a verifier already paired with identity A.
	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	identityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pairing.states["chrome-extension://test/"] = &PairingState{
		IdentityKey: identityPub,
		PairedAt:    time.Now().Add(-24 * time.Hour),
	}

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, pairing)

	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Use the CORRECT identity key but a FORGED signature (signed with a
	// different private key). This should be ErrIdentitySignature, which
	// is NOT repairable.
	_, wrongPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	origin := "chrome-extension://test/"
	signData := computeSignData(extEphemeralPub, origin)
	badSig := ed25519.Sign(wrongPriv, signData)

	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(identityPub),
		IdentitySig: base64.StdEncoding.EncodeToString(badSig),
		Origin:      origin,
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	err = host.handshake()
	// sendHandshakeRejected writes the rejection message and returns
	// ErrIdentityMismatch to signal the handshake did not succeed.
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrIdentityMismatch)

	// Should get handshake_rejected (not handshake_pair).
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakeRejected, resp.Type,
		"forged signature must be rejected, not trigger re-pairing")
	assert.NotEmpty(t, resp.Error)
}

func TestHost_Pairing_ExtensionDisconnectsDuringPairing(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	// Use io.Pipe so we can close the write side to simulate a disconnect.
	stdinReader, stdinWriter := io.Pipe()
	t.Cleanup(func() {
		stdinReader.Close()
		stdinWriter.Close()
	})
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinReader, stdoutW, pairing)

	// Generate an Ed25519 identity keypair.
	extIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Generate an X25519 ephemeral keypair.
	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Prepare the handshake message.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
		Origin:      "chrome-extension://test/",
	}

	// Run host.handshake() in a goroutine first, since io.Pipe is
	// synchronous and the write will block until the reader is ready.
	var hsErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		hsErr = host.handshake()
	}()

	// Write the handshake message. The goroutine above is now reading from
	// stdinReader, so the pipe write can proceed.
	require.NoError(t, WriteMessage(stdinWriter, handshakeMsg))

	// Read the handshake_pair response to synchronize.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypeHandshakePair, resp.Type)
	assert.True(t, resp.PairingRequired)

	// Close the write side of the pipe to simulate extension disconnect.
	// The host is blocked in awaitPairingConfirmation reading from stdinReader;
	// closing stdinWriter causes the read to return io.EOF.
	stdinWriter.Close()

	// Wait for the handshake goroutine to complete.
	wg.Wait()

	// The handshake should have returned an error wrapping ErrPairingRejected
	// because the stdin reader hit EOF while waiting for pairing_confirm.
	require.Error(t, hsErr)
	assert.ErrorIs(t, hsErr, ErrPairingRejected)

	// Verify the extension is NOT paired.
	assert.False(t, pairing.IsPaired())
}

func TestHost_RelayLoop_RevokedPairing(t *testing.T) {
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")
	statePath := filepath.Join(tmpDir, "pairing.json")

	_, cleanup := startMockIPCServerWithPairing(t, socketPath)
	defer cleanup()

	origin := "chrome-extension://test/"

	// Create a pairing verifier that is already paired for this origin.
	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)

	identityPub, identityPriv, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	pairing.states[origin] = &PairingState{
		IdentityKey: identityPub,
		PairedAt:    time.Now().Add(-1 * time.Hour),
	}
	require.NoError(t, pairing.save())
	require.True(t, pairing.IsPairedForOrigin(origin))

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(socketPath, testLogger(), stdinR, stdoutW, pairing)

	// Generate an X25519 ephemeral keypair for the handshake ECDH.
	extCrypto, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Sign the ephemeral key + origin with the paired identity.
	signData := computeSignData(extEphemeralPub, origin)
	sig := ed25519.Sign(identityPriv, signData)

	// Send handshake with identity verification.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(identityPub),
		IdentitySig: base64.StdEncoding.EncodeToString(sig),
		Origin:      origin,
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// Read handshake_ok from stdout — identity is verified.
	resp, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	require.Equal(t, MsgTypeHandshakeOK, resp.Type)

	// Complete the extension side of the ECDH handshake.
	hostPubKey, err := base64.StdEncoding.DecodeString(resp.PubKey)
	require.NoError(t, err)
	require.NoError(t, extCrypto.CompleteHandshake(hostPubKey))

	// Simulate the GUI revoking the pairing while the session is active.
	require.NoError(t, pairing.UnpairOrigin(origin))
	assert.False(t, pairing.IsPairedForOrigin(origin))

	// Send an encrypted message — the relay loop should detect the revocation.
	ipcMsg := &ipc.Message{Type: ipc.MessageTypeStatus}
	ipcJSON, err := json.Marshal(ipcMsg)
	require.NoError(t, err)

	nonce, ct, err := extCrypto.Encrypt(ipcJSON)
	require.NoError(t, err)

	encMsg := &NativeMessage{
		Type:       MsgTypeEncrypted,
		Nonce:      nonce,
		Ciphertext: base64.StdEncoding.EncodeToString(ct),
	}
	require.NoError(t, WriteMessage(stdinW, encMsg))

	// The host should return ErrPairingRevoked.
	select {
	case runErr := <-errCh:
		require.Error(t, runErr)
		assert.ErrorIs(t, runErr, ErrPairingRevoked)
	case <-time.After(5 * time.Second):
		t.Fatal("host did not stop within timeout after pairing revocation")
	}
}

func TestHost_PairingCodeNotifyFailure(t *testing.T) {
	tmpDir := t.TempDir()
	statePath := filepath.Join(tmpDir, "pairing.json")

	// Use a socket path where NO server is listening. This causes
	// notifyPairingCode to fail because the IPC dial will be refused.
	deadSocketPath := filepath.Join(tmpDir, "nonexistent.sock")

	pairing, err := NewPairingVerifier(statePath)
	require.NoError(t, err)
	assert.False(t, pairing.IsPaired())

	stdinR, stdinW := osPipe(t)
	stdoutR, stdoutW := osPipe(t)

	host := NewHostWithIO(deadSocketPath, testLogger(), stdinR, stdoutW, pairing)

	// Generate an Ed25519 identity keypair for the "extension".
	extIdentityPub, _, err := ed25519.GenerateKey(nil)
	require.NoError(t, err)

	// Generate an X25519 ephemeral keypair for the handshake ECDH.
	_, extEphemeralPub, err := NewSessionCrypto()
	require.NoError(t, err)

	// Write the handshake message with identity and origin.
	// Since the extension is not paired, this will trigger initiatePairing,
	// which calls notifyPairingCode — and that will fail because no IPC server
	// is listening.
	handshakeMsg := &NativeMessage{
		Type:        MsgTypeHandshake,
		PubKey:      base64.StdEncoding.EncodeToString(extEphemeralPub),
		IdentityKey: base64.StdEncoding.EncodeToString(extIdentityPub),
		Origin:      "chrome-extension://test/",
	}
	require.NoError(t, WriteMessage(stdinW, handshakeMsg))

	// Run the handshake. It should fail because notifyPairingCode cannot
	// reach the IPC server, and the host now fails-fast in that case.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errCh := make(chan error, 1)
	go func() {
		errCh <- host.Run(ctx)
	}()

	// The host should return ErrIPCConnection because notifyPairingCode failed.
	select {
	case runErr := <-errCh:
		require.Error(t, runErr)
		assert.ErrorIs(t, runErr, ErrIPCConnection)
	case <-time.After(5 * time.Second):
		t.Fatal("host did not stop within timeout after pairing code notify failure")
	}

	// Verify a pairing_failed message was written to stdout.
	failedMsg, err := ReadMessage(stdoutR)
	require.NoError(t, err)
	assert.Equal(t, MsgTypePairingFailed, failedMsg.Type)
	assert.NotEmpty(t, failedMsg.Error)

	// Verify the extension is NOT paired.
	assert.False(t, pairing.IsPaired())
}
