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

package pkcs11

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/xhome"
)

// mockIPCServer spins up a Unix socket that mimics the xkey IPC server.
// It reads one JSON Message, calls the provided handler func, and writes
// a JSON Response.
type mockIPCServer struct {
	listener net.Listener
	handler  func(msg *ipc.Message) *ipc.Response
	wg       sync.WaitGroup
}

func newMockIPCServer(t *testing.T, handler func(*ipc.Message) *ipc.Response) (*mockIPCServer, string) {
	t.Helper()
	sockPath := filepath.Join(privateTempDir(t), "test.sock")

	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)

	srv := &mockIPCServer{
		listener: listener,
		handler:  handler,
	}

	srv.wg.Add(1)
	go func() {
		defer srv.wg.Done()
		for {
			conn, acceptErr := listener.Accept()
			if acceptErr != nil {
				return
			}
			srv.wg.Add(1)
			go func() {
				defer srv.wg.Done()
				defer conn.Close()

				var msg ipc.Message
				if decErr := json.NewDecoder(conn).Decode(&msg); decErr != nil {
					resp := &ipc.Response{
						Status: ipc.StatusError,
						Error:  decErr.Error(),
					}
					json.NewEncoder(conn).Encode(resp)
					return
				}

				resp := handler(&msg)
				json.NewEncoder(conn).Encode(resp)
			}()
		}
	}()

	// No wait needed: net.Listen above binds the listener synchronously
	// before this function returns, so a dial immediately after queues in
	// the kernel accept backlog even before the accept loop goroutine has
	// started running.
	return srv, sockPath
}

func (s *mockIPCServer) Close() {
	s.listener.Close()
	s.wg.Wait()
}

func TestNewIPCTransport_ExplicitPath(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	assert.Equal(t, "/tmp/test.sock", tr.SocketPath())
}

func TestNewIPCTransport_EnvVar(t *testing.T) {
	t.Setenv(ipc.EnvSocketPath, "/tmp/env-test.sock")
	tr := NewIPCTransport("")
	assert.Equal(t, "/tmp/env-test.sock", tr.SocketPath())
}

// TestNewIPCTransport_DefaultPath verifies that NewIPCTransport resolves
// the default socket path exactly as ipc.DefaultSocketPath does, for both
// an XKEY_HOME-scoped instance and the bare XDG default. This is the same
// resolver the xkey CLI uses (see resolvedSocketPath in
// cmd/xkey/cmd/state_source.go), so the module and the CLI must agree.
func TestNewIPCTransport_DefaultPath(t *testing.T) {
	t.Run("XKEY_HOME set resolves the same path as the CLI", func(t *testing.T) {
		t.Setenv(ipc.EnvSocketPath, "")

		home1 := filepath.Join(t.TempDir(), "a")
		t.Setenv(xhome.EnvHome, home1)
		want1 := ipc.DefaultSocketPath()
		assert.Equal(t, want1, NewIPCTransport("").SocketPath())

		// A different XKEY_HOME must resolve to a different socket, proving
		// the module actually threads XKEY_HOME through rather than
		// returning a fixed value that happens to match once.
		home2 := filepath.Join(t.TempDir(), "b")
		t.Setenv(xhome.EnvHome, home2)
		want2 := ipc.DefaultSocketPath()
		assert.Equal(t, want2, NewIPCTransport("").SocketPath())

		assert.NotEqual(t, want1, want2)
	})

	t.Run("neither variable set uses the XDG default", func(t *testing.T) {
		t.Setenv(ipc.EnvSocketPath, "")
		t.Setenv(xhome.EnvHome, "")
		runtimeDir := t.TempDir()
		t.Setenv("XDG_RUNTIME_DIR", runtimeDir)

		tr := NewIPCTransport("")

		assert.Equal(t, ipc.DefaultSocketPath(), tr.SocketPath())
		assert.Equal(t, filepath.Join(runtimeDir, "xkey", "xkey.sock"), tr.SocketPath())
	})
}

func TestIPCTransport_Connect_SocketNotFound(t *testing.T) {
	tr := NewIPCTransport("/tmp/nonexistent-socket-path.sock")
	err := tr.Connect(context.Background())
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrIPCConnectionFailed))
}

func TestIPCTransport_Connect_Success(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				BarrierStatus: &ipc.BarrierStatusResult{
					Sealed: false,
				},
			},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	err := tr.Connect(context.Background())
	assert.NoError(t, err)
}

func TestIPCTransport_Close_Noop(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	assert.NoError(t, tr.Close())
}

func TestIPCTransport_Sign_Success(t *testing.T) {
	expectedSig := []byte("test-signature-bytes")

	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		assert.Equal(t, ipc.MessageTypePKCS11, msg.Type)
		require.NotNil(t, msg.PKCS11)
		assert.Equal(t, ipc.ActionSign, msg.PKCS11.Action)
		require.NotNil(t, msg.PKCS11.Sign)
		assert.Equal(t, "test-key", msg.PKCS11.Sign.KeyID)
		assert.Equal(t, "software", msg.PKCS11.Sign.Backend)
		assert.Equal(t, []byte("hello world"), msg.PKCS11.Sign.Data)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{Sign: &transport.SignResponse{Signature: expectedSig}},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "test-key",
		Data:    []byte("hello world"),
		Hash:    "SHA-256",
	})

	require.NoError(t, err)
	assert.Equal(t, expectedSig, resp.Signature)
}

func TestIPCTransport_Sign_ServerError(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		return &ipc.Response{
			Status: ipc.StatusError,
			Error:  "key not found in backend",
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "missing-key",
		Data:    []byte("test"),
	})

	assert.Nil(t, resp)
	require.ErrorIs(t, err, ErrSigningFailed)
	assert.ErrorIs(t, err, ipc.ErrPKCS11Operation)
	assert.Contains(t, err.Error(), "key not found in backend")
}

func TestIPCTransport_Sign_ConnectionRefused(t *testing.T) {
	tr := NewIPCTransport(filepath.Join(t.TempDir(), "nonexistent.sock"))
	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "key",
		Data:    []byte("test"),
	})

	assert.Nil(t, resp)
	assert.ErrorIs(t, err, ErrSigningFailed)
	assert.ErrorIs(t, err, ErrIPCConnectionFailed)
}

func TestIPCTransport_ListPIVSlots_Success(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		assert.Equal(t, ipc.ActionListPIVSlots, msg.PKCS11.Action)
		require.NotNil(t, msg.PKCS11.ListPIVSlots)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				ListPIVSlots: &transport.ListPIVSlotsResponse{
					Slots: []transport.PIVSlotStatus{
						{Slot: "9a", Algorithm: "ECDSA-P256", HasCert: true, Subject: "CN=auth"},
						{Slot: "9c", HasCert: false},
					},
				},
			},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	resp, err := tr.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: "software",
	})

	require.NoError(t, err)
	require.Len(t, resp.Slots, 2)
	assert.Equal(t, "9a", resp.Slots[0].Slot)
	assert.True(t, resp.Slots[0].HasCert)
	assert.Equal(t, "CN=auth", resp.Slots[0].Subject)
	assert.Equal(t, "9c", resp.Slots[1].Slot)
	assert.False(t, resp.Slots[1].HasCert)
}

func TestIPCTransport_GetPIVCertificate_Success(t *testing.T) {
	certPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n")

	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		assert.Equal(t, ipc.ActionGetPIVCertificate, msg.PKCS11.Action)
		require.NotNil(t, msg.PKCS11.GetPIVCertificate)
		assert.Equal(t, "9a", msg.PKCS11.GetPIVCertificate.Slot)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				GetPIVCertificate: &transport.GetPIVCertificateResponse{Slot: "9a", Certificate: certPEM, Format: "pem"},
			},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		Format:  "pem",
	})

	require.NoError(t, err)
	assert.Equal(t, "9a", resp.Slot)
	assert.Equal(t, certPEM, resp.Certificate)
}

func TestIPCTransport_PIVCertificate_DefaultFormat(t *testing.T) {
	// Get and Export ask for PEM when the caller names no format, without
	// rewriting the caller's request.
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		result := &transport.GetPIVCertificateResponse{Slot: "9a", Certificate: []byte("cert-data")}
		switch msg.PKCS11.Action {
		case ipc.ActionGetPIVCertificate:
			result.Format = msg.PKCS11.GetPIVCertificate.Format
			return &ipc.Response{Status: ipc.StatusOK, PKCS11: &ipc.PKCS11Result{GetPIVCertificate: result}}
		default:
			result.Format = msg.PKCS11.ExportPIVCertificate.Format
			return &ipc.Response{Status: ipc.StatusOK, PKCS11: &ipc.PKCS11Result{ExportPIVCertificate: result}}
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	calls := map[string]func(context.Context, *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error){
		"get":    tr.GetPIVCertificate,
		"export": tr.ExportPIVCertificate,
	}
	for name, call := range calls {
		req := &transport.GetPIVCertificateRequest{Backend: "software", Slot: "9a"}
		resp, err := call(context.Background(), req)

		require.NoError(t, err, name)
		assert.Equal(t, "pem", resp.Format, name)
		assert.Empty(t, req.Format, "%s must not modify the caller's request", name)
	}
}

// clientCall calls one IPCTransport operation, with its request or with a nil
// one, and returns only the error.
type clientCall func(tr *IPCTransport, withRequest bool) error

func callOf[Req, Resp any](call func(*IPCTransport, context.Context, *Req) (*Resp, error), req *Req) clientCall {
	return func(tr *IPCTransport, withRequest bool) error {
		sent := req
		if !withRequest {
			sent = nil
		}
		resp, err := call(tr, context.Background(), sent)
		if err != nil && resp != nil {
			return errors.New("response returned alongside an error")
		}
		return err
	}
}

func noResultCallOf[Req any](call func(*IPCTransport, context.Context, *Req) error, req *Req) clientCall {
	return func(tr *IPCTransport, withRequest bool) error {
		if !withRequest {
			return call(tr, context.Background(), nil)
		}
		return call(tr, context.Background(), req)
	}
}

// clientOperation is one IPCTransport operation and the sentinel its
// failures carry.
type clientOperation struct {
	call     clientCall
	sentinel error
	noResult bool
}

func clientOperations() map[string]clientOperation {
	type T = IPCTransport
	return map[string]clientOperation{
		ipc.ActionGenerateKey: {callOf((*T).GenerateKey, &transport.GenerateKeyRequest{KeyID: "k"}), ipc.ErrPKCS11Operation, false},
		ipc.ActionSign:        {callOf((*T).Sign, &transport.SignRequest{KeyID: "k", Data: []byte("d")}), ErrSigningFailed, false},
		ipc.ActionVerify:      {callOf((*T).Verify, &transport.VerifyRequest{KeyID: "k"}), ErrVerifyFailed, false},
		ipc.ActionEncrypt:     {callOf((*T).Encrypt, &transport.EncryptRequest{KeyID: "k"}), ErrEncryptionFailed, false},
		ipc.ActionEncryptAsym: {callOf((*T).EncryptAsym, &transport.EncryptAsymRequest{KeyID: "k"}), ErrEncryptionFailed, false},
		ipc.ActionDecrypt:     {callOf((*T).Decrypt, &transport.DecryptRequest{KeyID: "k"}), ErrDecryptionFailed, false},
		ipc.ActionDeriveKey:   {callOf((*T).DeriveKey, &transport.DeriveKeyRequest{Algorithm: "HKDF"}), ErrDerivationFailed, false},
		ipc.ActionDeriveKeyECDH: {callOf((*T).DeriveKeyECDH, &transport.DeriveKeyECDHRequest{KeyID: "k"}),
			ErrDerivationFailed, false},
		ipc.ActionWrapKeyByID: {callOf((*T).WrapKeyByID, &transport.WrapKeyByIDRequest{WrappingKeyID: "w"}),
			ErrWrappingFailed, false},
		ipc.ActionUnwrapKeyByID: {callOf((*T).UnwrapKeyByID, &transport.UnwrapKeyByIDRequest{UnwrappingKeyID: "w"}),
			ErrWrappingFailed, false},
		ipc.ActionExportKeyMaterial: {callOf((*T).ExportKeyMaterial, &transport.ExportKeyMaterialRequest{KeyID: "k"}),
			ErrExportFailed, false},
		ipc.ActionGetImportParameters: {callOf((*T).GetImportParameters, &transport.GetImportParametersRequest{KeyID: "k"}),
			ErrGetImportParamsFailed, false},
		ipc.ActionImportKey: {callOf((*T).ImportKey, &transport.ImportKeyRequest{KeyID: "k"}),
			ErrImportFailed, false},
		ipc.ActionListPIVSlots: {callOf((*T).ListPIVSlots, &transport.ListPIVSlotsRequest{}), ipc.ErrPKCS11Operation, false},
		ipc.ActionGetPIVCertificate: {callOf((*T).GetPIVCertificate, &transport.GetPIVCertificateRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, false},
		ipc.ActionGeneratePIVKey: {callOf((*T).GeneratePIVKey, &transport.GeneratePIVKeyRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, false},
		ipc.ActionStorePIVCertificate: {noResultCallOf((*T).StorePIVCertificate, &transport.StorePIVCertificateRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, true},
		ipc.ActionDeletePIVCertificate: {noResultCallOf((*T).DeletePIVCertificate, &transport.DeletePIVCertificateRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, true},
		ipc.ActionImportPIVCertificate: {noResultCallOf((*T).ImportPIVCertificate, &transport.StorePIVCertificateRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, true},
		ipc.ActionExportPIVCertificate: {callOf((*T).ExportPIVCertificate, &transport.GetPIVCertificateRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, false},
		ipc.ActionGeneratePIVCSR: {callOf((*T).GeneratePIVCSR, &transport.GeneratePIVCSRRequest{Slot: "9a"}),
			ipc.ErrPKCS11Operation, false},
	}
}

func TestIPCTransport_EveryOperation_SendsItsAction(t *testing.T) {
	var got string
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		got = msg.PKCS11.Action
		return &ipc.Response{Status: ipc.StatusError, Error: "refused"}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	for action, op := range clientOperations() {
		err := op.call(tr, true)
		assert.ErrorIs(t, err, op.sentinel, action)
		assert.Equal(t, action, got)
	}
}

// TestIPCTransport_OperationTimeout covers which timeout each action gets:
// the two key generations wait keyGenerationTimeout, long enough for an
// on-card RSA-4096 generation, and every other operation keeps the
// 10-second default.
func TestIPCTransport_OperationTimeout(t *testing.T) {
	assert.Equal(t, 10*time.Second, defaultIPCTimeout)
	assert.Equal(t, 3*time.Minute, keyGenerationTimeout)

	tr := NewIPCTransport(filepath.Join(t.TempDir(), "unused.sock"))
	generations := map[string]bool{ipc.ActionGenerateKey: true, ipc.ActionGeneratePIVKey: true}

	actions := []string{ipc.ActionBarrierStatus}
	for action := range clientOperations() {
		actions = append(actions, action)
	}
	for _, action := range actions {
		want := defaultIPCTimeout
		if generations[action] {
			want = keyGenerationTimeout
		}
		msg := &ipc.Message{Type: ipc.MessageTypePKCS11, PKCS11: &ipc.PKCS11Payload{Action: action}}
		assert.Equal(t, want, tr.operationTimeout(msg), action)
	}

	assert.Equal(t, defaultIPCTimeout, tr.operationTimeout(&ipc.Message{Type: ipc.MessageTypePKCS11}),
		"a message without a PKCS#11 payload")
}

// TestIPCTransport_SlowResponse covers the deadline each timeout sets on the
// connection: against a server slower than the default timeout, a signature
// times out while a key generation, under its own longer timeout, completes.
func TestIPCTransport_SlowResponse(t *testing.T) {
	const serverDelay = 300 * time.Millisecond

	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		time.Sleep(serverDelay)
		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				GenerateKey: &transport.GenerateKeyResponse{KeyID: "slow-key"},
				Sign:        &transport.SignResponse{Signature: []byte("sig")},
			},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	tr.timeout = serverDelay / 3
	tr.keyGenerationTimeout = 10 * serverDelay

	_, err := tr.Sign(context.Background(), &transport.SignRequest{KeyID: "k", Data: []byte("d")})
	var netErr net.Error
	require.ErrorAs(t, err, &netErr)
	assert.True(t, netErr.Timeout(), "Sign() error = %v, want a timeout", err)
	assert.ErrorIs(t, err, ErrSigningFailed)

	resp, err := tr.GenerateKey(context.Background(), &transport.GenerateKeyRequest{KeyID: "slow-key"})
	require.NoError(t, err)
	assert.Equal(t, "slow-key", resp.KeyID)
}

// TestIPCTransport_CanceledInFlight covers a caller giving up while xkey is
// still working: the call returns at once with the cancellation rather than
// waiting out the key-generation timeout.
func TestIPCTransport_CanceledInFlight(t *testing.T) {
	received := make(chan struct{})
	release := make(chan struct{})
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		close(received)
		<-release
		return &ipc.Response{Status: ipc.StatusOK, PKCS11: &ipc.PKCS11Result{GenerateKey: &transport.GenerateKeyResponse{}}}
	})
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		<-received
		cancel()
	}()

	_, err := NewIPCTransport(sockPath).GenerateKey(ctx, &transport.GenerateKeyRequest{KeyID: "k"})
	require.ErrorIs(t, err, ErrIPCRequestCanceled)
	assert.ErrorIs(t, err, context.Canceled)
}

// TestIPCTransport_ContextDeadlineBoundsTheCall covers a caller deadline
// shorter than the operation's own timeout: the caller's deadline wins.
func TestIPCTransport_ContextDeadlineBoundsTheCall(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		time.Sleep(300 * time.Millisecond)
		return &ipc.Response{Status: ipc.StatusOK, PKCS11: &ipc.PKCS11Result{GenerateKey: &transport.GenerateKeyResponse{}}}
	})
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	_, err := NewIPCTransport(sockPath).GenerateKey(ctx, &transport.GenerateKeyRequest{KeyID: "k"})
	require.ErrorIs(t, err, ErrIPCRequestCanceled)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestIPCTransport_EveryOperation_NilRequest(t *testing.T) {
	tr := NewIPCTransport(filepath.Join(t.TempDir(), "never-dialed.sock"))
	for action, op := range clientOperations() {
		assert.ErrorIs(t, op.call(tr, false), ErrNilRequest, action)
	}
}

func TestIPCTransport_EveryOperation_MissingResult(t *testing.T) {
	// A server that answers OK without the operation's result must not be
	// read as success with a nil response.
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		return &ipc.Response{Status: ipc.StatusOK, PKCS11: &ipc.PKCS11Result{}}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	for action, op := range clientOperations() {
		err := op.call(tr, true)
		if op.noResult {
			assert.NoError(t, err, action)
			continue
		}
		require.ErrorIs(t, err, op.sentinel, action)
		assert.Contains(t, err.Error(), "missing "+action+" result", action)
	}
}

func TestIPCTransport_SendMessage_MalformedResponse(t *testing.T) {
	sockPath := filepath.Join(privateTempDir(t), "bad-server.sock")
	listener, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	defer listener.Close()

	// Server that writes garbage instead of JSON
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer conn.Close()
		// Read the request but write non-JSON
		buf := make([]byte, 1024)
		conn.Read(buf)
		conn.Write([]byte("this is not json\n"))
	}()

	// No wait needed: net.Listen above binds the listener synchronously, so
	// a dial immediately after queues in the kernel accept backlog even
	// before the goroutine's Accept call has started running.
	tr := NewIPCTransport(sockPath)
	resp, signErr := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "test",
		Data:    []byte("data"),
	})

	assert.Nil(t, resp)
	assert.Error(t, signErr)
	assert.True(t, errors.Is(signErr, ErrSigningFailed))
}

// privateTempDir returns a fresh temporary directory with mode 0700. The IPC
// client refuses a socket directory with group or other permission bits
// (ipc.Dial), and t.TempDir creates its directory 0777 &^ umask.
func privateTempDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.Chmod(dir, 0o700))
	return dir
}
