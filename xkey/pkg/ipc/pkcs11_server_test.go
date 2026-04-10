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

package ipc

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockPKCS11Handler implements both Handler and PKCS11Handler for testing.
type mockPKCS11Handler struct {
	mockHandler // embed the basic handler

	signResult     *SignResult
	signErr        error
	pivCertResult  *PIVCertResult
	pivCertErr     error
	pivSlotsResult *PIVSlotsResult
	pivSlotsErr    error
	barrierResult  *BarrierStatusResult
	barrierErr     error
}

func (h *mockPKCS11Handler) HandlePKCS11Sign(_ *SignParams) (*SignResult, error) {
	return h.signResult, h.signErr
}

func (h *mockPKCS11Handler) HandlePKCS11GetPIVCertificate(_ *PIVCertParams) (*PIVCertResult, error) {
	return h.pivCertResult, h.pivCertErr
}

func (h *mockPKCS11Handler) HandlePKCS11ListPIVSlots(_ *PIVSlotsParams) (*PIVSlotsResult, error) {
	return h.pivSlotsResult, h.pivSlotsErr
}

func (h *mockPKCS11Handler) HandlePKCS11BarrierStatus() (*BarrierStatusResult, error) {
	return h.barrierResult, h.barrierErr
}

func TestServer_PKCS11_Sign_Success(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		signResult: &SignResult{
			Signature: "c2lnbmF0dXJl",
		},
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionSign,
			Sign: &SignParams{
				Backend: "software",
				KeyID:   "test-key",
				Data:    "dGVzdA==",
				Hash:    "SHA-256",
			},
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.PKCS11)
	require.NotNil(t, resp.PKCS11.Sign)
	assert.Equal(t, "c2lnbmF0dXJl", resp.PKCS11.Sign.Signature)

	cancel()
	srv.Close()
}

func TestServer_PKCS11_Sign_HandlerError(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		signErr: errors.New("key not found"),
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionSign,
			Sign: &SignParams{
				KeyID: "missing-key",
				Data:  "dGVzdA==",
			},
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")

	cancel()
	srv.Close()
}

func TestServer_PKCS11_BarrierStatus_Success(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		barrierResult: &BarrierStatusResult{
			Sealed:         false,
			Strategy:       "software",
			HardwareBacked: false,
		},
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionBarrierStatus,
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.PKCS11)
	require.NotNil(t, resp.PKCS11.BarrierStatus)
	assert.False(t, resp.PKCS11.BarrierStatus.Sealed)
	assert.Equal(t, "software", resp.PKCS11.BarrierStatus.Strategy)

	cancel()
	srv.Close()
}

func TestServer_PKCS11_BarrierStatus_Error(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		barrierErr: errors.New("barrier service unavailable"),
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionBarrierStatus,
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")

	cancel()
	srv.Close()
}

func TestServer_PKCS11_ListPIVSlots_Success(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		pivSlotsResult: &PIVSlotsResult{
			Slots: []PIVSlotInfo{
				{Slot: "9a", Algorithm: "ECDSA-P256", HasCert: true},
				{Slot: "9c", HasCert: false},
			},
		},
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionListPIVSlots,
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.PKCS11)
	require.NotNil(t, resp.PKCS11.PIVSlots)
	require.Len(t, resp.PKCS11.PIVSlots.Slots, 2)
	assert.Equal(t, "9a", resp.PKCS11.PIVSlots.Slots[0].Slot)

	cancel()
	srv.Close()
}

func TestServer_PKCS11_ListPIVSlots_Error(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		pivSlotsErr: errors.New("backend not available"),
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionListPIVSlots,
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")

	cancel()
	srv.Close()
}

func TestServer_PKCS11_GetPIVCertificate_Success(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		pivCertResult: &PIVCertResult{
			Certificate: "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----\n",
			Slot:        "9a",
			Subject:     "CN=test",
			Issuer:      "CN=CA",
			NotAfter:    "2030-01-01T00:00:00Z",
		},
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionGetPIVCertificate,
			PIVCert: &PIVCertParams{
				Backend: "software",
				Slot:    "9a",
				Format:  "pem",
			},
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusOK, resp.Status)
	require.NotNil(t, resp.PKCS11)
	require.NotNil(t, resp.PKCS11.PIVCert)
	assert.Contains(t, resp.PKCS11.PIVCert.Certificate, "BEGIN CERTIFICATE")
	assert.Equal(t, "9a", resp.PKCS11.PIVCert.Slot)
	assert.Equal(t, "CN=test", resp.PKCS11.PIVCert.Subject)

	cancel()
	srv.Close()
}

func TestServer_PKCS11_GetPIVCertificate_Error(t *testing.T) {
	sockPath := testSocketPath(t)
	handler := &mockPKCS11Handler{
		mockHandler: mockHandler{
			statusResp: OKResponse(ActionDaemonReady),
		},
		pivCertErr: errors.New("no certificate in slot"),
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionGetPIVCertificate,
			PIVCert: &PIVCertParams{
				Slot: "9c",
			},
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "handler returned error")

	cancel()
	srv.Close()
}

func TestServer_PKCS11_HandlerDoesNotImplementPKCS11Handler(t *testing.T) {
	sockPath := testSocketPath(t)
	// Use a plain mockHandler that does NOT implement PKCS11Handler.
	handler := &mockHandler{
		statusResp: OKResponse(ActionDaemonReady),
	}

	srv, err := NewServer(sockPath, handler, testLogger())
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go srv.Serve(ctx)
	time.Sleep(50 * time.Millisecond)

	conn, err := net.Dial("unix", sockPath)
	require.NoError(t, err)
	defer conn.Close()

	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionBarrierStatus,
		},
	}
	require.NoError(t, json.NewEncoder(conn).Encode(msg))

	var resp Response
	require.NoError(t, json.NewDecoder(conn).Decode(&resp))

	assert.Equal(t, StatusError, resp.Status)
	assert.Contains(t, resp.Error, "does not implement PKCS11Handler")

	cancel()
	srv.Close()
}

func TestDispatchPKCS11_UnknownAction(t *testing.T) {
	handler := &mockPKCS11Handler{}
	payload := &PKCS11Payload{
		Action: "nonexistent",
	}

	resp, err := dispatchPKCS11(handler, payload)
	assert.Nil(t, resp)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestPkcs11OKResponse(t *testing.T) {
	result := &PKCS11Result{
		BarrierStatus: &BarrierStatusResult{
			Sealed: true,
		},
	}
	resp := pkcs11OKResponse(result)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Empty(t, resp.Action)
	assert.Empty(t, resp.Error)
	require.NotNil(t, resp.PKCS11)
	assert.True(t, resp.PKCS11.BarrierStatus.Sealed)
}
