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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
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
	sockPath := filepath.Join(t.TempDir(), "test.sock")

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

	// Give the server time to start.
	time.Sleep(20 * time.Millisecond)
	return srv, sockPath
}

func (s *mockIPCServer) Close() {
	s.listener.Close()
	s.wg.Wait()
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestNewIPCTransport_ExplicitPath(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	assert.Equal(t, "/tmp/test.sock", tr.SocketPath())
}

func TestNewIPCTransport_EnvVar(t *testing.T) {
	t.Setenv(envSocketPath, "/tmp/env-test.sock")
	tr := NewIPCTransport("")
	assert.Equal(t, "/tmp/env-test.sock", tr.SocketPath())
}

func TestNewIPCTransport_DefaultPath(t *testing.T) {
	t.Setenv(envSocketPath, "")
	tr := NewIPCTransport("")
	home, _ := os.UserHomeDir()
	expected := home + "/.xkey/run/xkey.sock"
	assert.Equal(t, expected, tr.SocketPath())
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

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				Sign: &ipc.SignResult{
					Signature: base64.StdEncoding.EncodeToString(expectedSig),
				},
			},
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

func TestIPCTransport_Sign_NilRequest(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	resp, err := tr.Sign(context.Background(), nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
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
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSigningFailed))
}

func TestIPCTransport_Sign_ConnectionRefused(t *testing.T) {
	tr := NewIPCTransport(filepath.Join(t.TempDir(), "nonexistent.sock"))
	resp, err := tr.Sign(context.Background(), &transport.SignRequest{
		Backend: "software",
		KeyID:   "key",
		Data:    []byte("test"),
	})

	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrSigningFailed))
}

func TestIPCTransport_ListPIVSlots_Success(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		assert.Equal(t, ipc.ActionListPIVSlots, msg.PKCS11.Action)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				PIVSlots: &ipc.PIVSlotsResult{
					Slots: []ipc.PIVSlotInfo{
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
	assert.Equal(t, "9c", resp.Slots[1].Slot)
	assert.False(t, resp.Slots[1].HasCert)
}

func TestIPCTransport_ListPIVSlots_NilRequest(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	resp, err := tr.ListPIVSlots(context.Background(), nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestIPCTransport_GetPIVCertificate_Success(t *testing.T) {
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n"

	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		assert.Equal(t, ipc.ActionGetPIVCertificate, msg.PKCS11.Action)
		assert.Equal(t, "9a", msg.PKCS11.PIVCert.Slot)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				PIVCert: &ipc.PIVCertResult{
					Certificate: certPEM,
					Slot:        "9a",
					Subject:     "CN=auth",
				},
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
	assert.Equal(t, certPEM, string(resp.Certificate))
}

func TestIPCTransport_GetPIVCertificate_NilRequest(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	resp, err := tr.GetPIVCertificate(context.Background(), nil)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrNilRequest))
}

func TestIPCTransport_GetPIVCertificate_DefaultFormat(t *testing.T) {
	srv, sockPath := newMockIPCServer(t, func(msg *ipc.Message) *ipc.Response {
		// Verify that an empty format defaults to "pem"
		assert.Equal(t, "pem", msg.PKCS11.PIVCert.Format)

		return &ipc.Response{
			Status: ipc.StatusOK,
			PKCS11: &ipc.PKCS11Result{
				PIVCert: &ipc.PIVCertResult{
					Certificate: "cert-data",
					Slot:        "9a",
				},
			},
		}
	})
	defer srv.Close()

	tr := NewIPCTransport(sockPath)
	resp, err := tr.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: "software",
		Slot:    "9a",
		// Format intentionally left empty
	})

	require.NoError(t, err)
	assert.Equal(t, "pem", resp.Format)
}

func TestIPCTransport_NotImplemented_Methods(t *testing.T) {
	tr := NewIPCTransport("/tmp/test.sock")
	ctx := context.Background()

	tests := []struct {
		name string
		fn   func() error
	}{
		{"GenerateKey", func() error { _, err := tr.GenerateKey(ctx, &transport.GenerateKeyRequest{}); return err }},
		{"Verify", func() error { _, err := tr.Verify(ctx, &transport.VerifyRequest{}); return err }},
		{"Encrypt", func() error { _, err := tr.Encrypt(ctx, &transport.EncryptRequest{}); return err }},
		{"Decrypt", func() error { _, err := tr.Decrypt(ctx, &transport.DecryptRequest{}); return err }},
		{"DeriveKey", func() error { _, err := tr.DeriveKey(ctx, &transport.DeriveKeyRequest{}); return err }},
		{"DeriveKeyECDH", func() error { _, err := tr.DeriveKeyECDH(ctx, &transport.DeriveKeyECDHRequest{}); return err }},
		{"WrapKeyByID", func() error { _, err := tr.WrapKeyByID(ctx, &transport.WrapKeyByIDRequest{}); return err }},
		{"UnwrapKeyByID", func() error { _, err := tr.UnwrapKeyByID(ctx, &transport.UnwrapKeyByIDRequest{}); return err }},
		{"ExportKeyMaterial", func() error { _, err := tr.ExportKeyMaterial(ctx, &transport.ExportKeyMaterialRequest{}); return err }},
		{"GeneratePIVKey", func() error { _, err := tr.GeneratePIVKey(ctx, &transport.GeneratePIVKeyRequest{}); return err }},
		{"StorePIVCertificate", func() error { return tr.StorePIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"DeletePIVCertificate", func() error { return tr.DeletePIVCertificate(ctx, &transport.DeletePIVCertificateRequest{}) }},
		{"ImportPIVCertificate", func() error { return tr.ImportPIVCertificate(ctx, &transport.StorePIVCertificateRequest{}) }},
		{"ExportPIVCertificate", func() error {
			_, err := tr.ExportPIVCertificate(ctx, &transport.GetPIVCertificateRequest{})
			return err
		}},
		{"GeneratePIVCSR", func() error { _, err := tr.GeneratePIVCSR(ctx, &transport.GeneratePIVCSRRequest{}); return err }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.fn()
			assert.Error(t, err)
			assert.True(t, errors.Is(err, ErrIPCNotImplemented),
				"expected ErrIPCNotImplemented for %s, got: %v", tt.name, err)
		})
	}
}

func TestIPCTransport_SendMessage_MalformedResponse(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "bad-server.sock")
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

	time.Sleep(20 * time.Millisecond)

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
