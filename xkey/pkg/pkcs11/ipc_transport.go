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
	"fmt"
	"net"
	"os"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/pkcs11/module"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

const (
	// defaultIPCTimeout is the default timeout for IPC operations.
	defaultIPCTimeout = 10 * time.Second

	// envSocketPath is the environment variable for the IPC socket path.
	envSocketPath = "XKEY_IPC_SOCKET"
)

// IPCTransport implements module.PKCS11Transport by communicating with
// a running xkey instance over a Unix domain socket. If xkey is not
// running, operations return connection errors.
type IPCTransport struct {
	socketPath string
	timeout    time.Duration
}

// Compile-time interface compliance check.
var _ module.PKCS11Transport = (*IPCTransport)(nil)

// NewIPCTransport creates a new IPC transport. The socketPath can be
// empty, in which case XKEY_IPC_SOCKET env var is checked, then the
// default runtime path (~/.xkey/run/xkey.sock) is used.
func NewIPCTransport(socketPath string) *IPCTransport {
	if socketPath == "" {
		socketPath = os.Getenv(envSocketPath)
	}
	if socketPath == "" {
		home, _ := os.UserHomeDir()
		if home != "" {
			socketPath = home + "/.xkey/run/xkey.sock"
		}
	}
	return &IPCTransport{
		socketPath: socketPath,
		timeout:    defaultIPCTimeout,
	}
}

// SocketPath returns the configured socket path.
func (t *IPCTransport) SocketPath() string {
	return t.socketPath
}

// Connect verifies the IPC socket exists and is reachable. It sends a
// barrier_status request to verify the xkey instance is responding.
func (t *IPCTransport) Connect(_ context.Context) error {
	if _, err := os.Stat(t.socketPath); err != nil {
		return fmt.Errorf("%w: socket not found: %s", ErrIPCConnectionFailed, t.socketPath)
	}
	// Verify connectivity by sending a barrier status request.
	msg := &ipc.Message{
		Type: ipc.MessageTypePKCS11,
		PKCS11: &ipc.PKCS11Payload{
			Action: ipc.ActionBarrierStatus,
		},
	}
	_, err := t.sendMessage(msg)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrIPCConnectionFailed, err)
	}
	return nil
}

// Close is a no-op for the IPC transport. Each request opens and closes
// its own connection.
func (t *IPCTransport) Close() error {
	return nil
}

// Sign signs data with the specified key via the running xkey instance.
func (t *IPCTransport) Sign(_ context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	msg := &ipc.Message{
		Type: ipc.MessageTypePKCS11,
		PKCS11: &ipc.PKCS11Payload{
			Action: ipc.ActionSign,
			Sign: &ipc.SignParams{
				Backend: req.Backend,
				KeyID:   req.KeyID,
				Data:    base64.StdEncoding.EncodeToString(req.Data),
				Hash:    req.Hash,
			},
		},
	}

	resp, err := t.sendMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSigningFailed, err)
	}

	if resp.PKCS11 == nil || resp.PKCS11.Sign == nil {
		return nil, fmt.Errorf("%w: missing sign result in response", ErrSigningFailed)
	}

	sig, err := base64.StdEncoding.DecodeString(resp.PKCS11.Sign.Signature)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode signature: %v", ErrSigningFailed, err)
	}

	return &transport.SignResponse{
		Signature: sig,
	}, nil
}

// ListPIVSlots returns the status of all PIV slots via the running xkey instance.
func (t *IPCTransport) ListPIVSlots(_ context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	msg := &ipc.Message{
		Type: ipc.MessageTypePKCS11,
		PKCS11: &ipc.PKCS11Payload{
			Action: ipc.ActionListPIVSlots,
			PIVSlots: &ipc.PIVSlotsParams{
				Backend: req.Backend,
			},
		},
	}

	resp, err := t.sendMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ipc.ErrPKCS11Operation, err)
	}

	if resp.PKCS11 == nil || resp.PKCS11.PIVSlots == nil {
		return nil, fmt.Errorf("%w: missing piv_slots result in response", ipc.ErrPKCS11Operation)
	}

	slots := make([]transport.PIVSlotStatus, len(resp.PKCS11.PIVSlots.Slots))
	for i, s := range resp.PKCS11.PIVSlots.Slots {
		slots[i] = transport.PIVSlotStatus{
			Slot:      s.Slot,
			Algorithm: s.Algorithm,
			Subject:   s.Subject,
			HasCert:   s.HasCert,
			NotAfter:  s.NotAfter,
		}
	}

	return &transport.ListPIVSlotsResponse{
		Slots: slots,
	}, nil
}

// GetPIVCertificate retrieves a certificate from a PIV slot via the running
// xkey instance.
func (t *IPCTransport) GetPIVCertificate(_ context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	if req == nil {
		return nil, ErrNilRequest
	}

	format := req.Format
	if format == "" {
		format = "pem"
	}

	msg := &ipc.Message{
		Type: ipc.MessageTypePKCS11,
		PKCS11: &ipc.PKCS11Payload{
			Action: ipc.ActionGetPIVCertificate,
			PIVCert: &ipc.PIVCertParams{
				Backend: req.Backend,
				Slot:    req.Slot,
				Format:  format,
			},
		},
	}

	resp, err := t.sendMessage(msg)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ipc.ErrPKCS11Operation, err)
	}

	if resp.PKCS11 == nil || resp.PKCS11.PIVCert == nil {
		return nil, fmt.Errorf("%w: missing piv_cert result in response", ipc.ErrPKCS11Operation)
	}

	return &transport.GetPIVCertificateResponse{
		Slot:        resp.PKCS11.PIVCert.Slot,
		Certificate: []byte(resp.PKCS11.PIVCert.Certificate),
		Format:      format,
	}, nil
}

// GenerateKey is not implemented in the IPC transport MVP.
func (t *IPCTransport) GenerateKey(_ context.Context, _ *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return nil, ErrIPCNotImplemented
}

// Verify is not implemented in the IPC transport MVP.
func (t *IPCTransport) Verify(_ context.Context, _ *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return nil, ErrIPCNotImplemented
}

// Encrypt is not implemented in the IPC transport MVP.
func (t *IPCTransport) Encrypt(_ context.Context, _ *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return nil, ErrIPCNotImplemented
}

// Decrypt is not implemented in the IPC transport MVP.
func (t *IPCTransport) Decrypt(_ context.Context, _ *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return nil, ErrIPCNotImplemented
}

// DeriveKey is not implemented in the IPC transport MVP.
func (t *IPCTransport) DeriveKey(_ context.Context, _ *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return nil, ErrIPCNotImplemented
}

// DeriveKeyECDH is not implemented in the IPC transport MVP.
func (t *IPCTransport) DeriveKeyECDH(_ context.Context, _ *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return nil, ErrIPCNotImplemented
}

// WrapKeyByID is not implemented in the IPC transport MVP.
func (t *IPCTransport) WrapKeyByID(_ context.Context, _ *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return nil, ErrIPCNotImplemented
}

// UnwrapKeyByID is not implemented in the IPC transport MVP.
func (t *IPCTransport) UnwrapKeyByID(_ context.Context, _ *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return nil, ErrIPCNotImplemented
}

// ExportKeyMaterial is not implemented in the IPC transport MVP.
func (t *IPCTransport) ExportKeyMaterial(_ context.Context, _ *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return nil, ErrIPCNotImplemented
}

// GeneratePIVKey is not implemented in the IPC transport MVP.
func (t *IPCTransport) GeneratePIVKey(_ context.Context, _ *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return nil, ErrIPCNotImplemented
}

// StorePIVCertificate is not implemented in the IPC transport MVP.
func (t *IPCTransport) StorePIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return ErrIPCNotImplemented
}

// DeletePIVCertificate is not implemented in the IPC transport MVP.
func (t *IPCTransport) DeletePIVCertificate(_ context.Context, _ *transport.DeletePIVCertificateRequest) error {
	return ErrIPCNotImplemented
}

// ImportPIVCertificate is not implemented in the IPC transport MVP.
func (t *IPCTransport) ImportPIVCertificate(_ context.Context, _ *transport.StorePIVCertificateRequest) error {
	return ErrIPCNotImplemented
}

// ExportPIVCertificate is not implemented in the IPC transport MVP.
func (t *IPCTransport) ExportPIVCertificate(_ context.Context, _ *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return nil, ErrIPCNotImplemented
}

// GeneratePIVCSR is not implemented in the IPC transport MVP.
func (t *IPCTransport) GeneratePIVCSR(_ context.Context, _ *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return nil, ErrIPCNotImplemented
}

// sendMessage opens a Unix socket connection, sends the JSON message, reads
// the JSON response, and returns it. Each call is a fresh connection.
func (t *IPCTransport) sendMessage(msg *ipc.Message) (*ipc.Response, error) {
	conn, err := net.DialTimeout("unix", t.socketPath, t.timeout)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnectionFailed, err)
	}
	defer conn.Close()

	if err := conn.SetDeadline(time.Now().Add(t.timeout)); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrIPCConnectionFailed, err)
	}

	encoder := json.NewEncoder(conn)
	if err := encoder.Encode(msg); err != nil {
		return nil, fmt.Errorf("%w: %v", ipc.ErrProtocolError, err)
	}

	var resp ipc.Response
	decoder := json.NewDecoder(conn)
	if err := decoder.Decode(&resp); err != nil {
		return nil, fmt.Errorf("%w: %v", ipc.ErrProtocolError, err)
	}

	if resp.Status == ipc.StatusError {
		return nil, fmt.Errorf("%w: %s", ipc.ErrPKCS11Operation, resp.Error)
	}

	return &resp, nil
}
