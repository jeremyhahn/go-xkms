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

package services

import (
	"context"
	"encoding/base64"
	"fmt"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	pkcs11svc "github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

// PKCS11IPCHandler implements ipc.PKCS11Handler by delegating to the
// embedded PKCS#11 transport and checking barrier seal status before
// each operation that requires unsealed keys.
type PKCS11IPCHandler struct {
	transport *pkcs11svc.EmbeddedTransport
	logger    *slog.Logger
	isSealed  func() bool
}

// Compile-time interface compliance check.
var _ ipc.PKCS11Handler = (*PKCS11IPCHandler)(nil)

// NewPKCS11IPCHandler creates a new PKCS#11 IPC handler. The isSealed
// callback returns true when the barrier is sealed, preventing access
// to protected keys.
func NewPKCS11IPCHandler(
	transport *pkcs11svc.EmbeddedTransport,
	logger *slog.Logger,
	isSealed func() bool,
) *PKCS11IPCHandler {
	return &PKCS11IPCHandler{
		transport: transport,
		logger:    logger,
		isSealed:  isSealed,
	}
}

// HandlePKCS11Sign delegates signing to the embedded transport after
// checking barrier status and decoding base64 data.
func (h *PKCS11IPCHandler) HandlePKCS11Sign(params *ipc.SignParams) (*ipc.SignResult, error) {
	if err := h.checkBarrier(); err != nil {
		return nil, err
	}
	if h.transport == nil {
		return nil, fmt.Errorf("%w: embedded transport not initialized", ipc.ErrPKCS11Operation)
	}

	data, err := base64.StdEncoding.DecodeString(params.Data)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to decode sign data: %v", ipc.ErrPKCS11Operation, err)
	}

	resp, err := h.transport.Sign(context.Background(), &transport.SignRequest{
		Backend: params.Backend,
		KeyID:   params.KeyID,
		Data:    data,
		Hash:    params.Hash,
	})
	if err != nil {
		h.logger.Error("pkcs11 ipc sign failed", "key_id", params.KeyID, "error", err)
		return nil, fmt.Errorf("%w: %v", ipc.ErrPKCS11Operation, err)
	}

	return &ipc.SignResult{
		Signature: base64.StdEncoding.EncodeToString(resp.Signature),
	}, nil
}

// HandlePKCS11GetPIVCertificate retrieves a certificate from a PIV slot
// via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11GetPIVCertificate(params *ipc.PIVCertParams) (*ipc.PIVCertResult, error) {
	if err := h.checkBarrier(); err != nil {
		return nil, err
	}
	if h.transport == nil {
		return nil, fmt.Errorf("%w: embedded transport not initialized", ipc.ErrPKCS11Operation)
	}

	format := params.Format
	if format == "" {
		format = "pem"
	}

	resp, err := h.transport.GetPIVCertificate(context.Background(), &transport.GetPIVCertificateRequest{
		Backend: params.Backend,
		Slot:    params.Slot,
		Format:  format,
	})
	if err != nil {
		h.logger.Error("pkcs11 ipc get_piv_certificate failed", "slot", params.Slot, "error", err)
		return nil, fmt.Errorf("%w: %v", ipc.ErrPKCS11Operation, err)
	}

	return &ipc.PIVCertResult{
		Certificate: string(resp.Certificate),
		Slot:        resp.Slot,
	}, nil
}

// HandlePKCS11ListPIVSlots lists all PIV slots via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11ListPIVSlots(params *ipc.PIVSlotsParams) (*ipc.PIVSlotsResult, error) {
	if err := h.checkBarrier(); err != nil {
		return nil, err
	}
	if h.transport == nil {
		return nil, fmt.Errorf("%w: embedded transport not initialized", ipc.ErrPKCS11Operation)
	}

	resp, err := h.transport.ListPIVSlots(context.Background(), &transport.ListPIVSlotsRequest{
		Backend: params.Backend,
	})
	if err != nil {
		h.logger.Error("pkcs11 ipc list_piv_slots failed", "error", err)
		return nil, fmt.Errorf("%w: %v", ipc.ErrPKCS11Operation, err)
	}

	slots := make([]ipc.PIVSlotInfo, len(resp.Slots))
	for i, s := range resp.Slots {
		slots[i] = ipc.PIVSlotInfo{
			Slot:      s.Slot,
			Algorithm: s.Algorithm,
			Subject:   s.Subject,
			HasCert:   s.HasCert,
			NotAfter:  s.NotAfter,
		}
	}

	return &ipc.PIVSlotsResult{
		Slots: slots,
	}, nil
}

// HandlePKCS11BarrierStatus returns the current barrier seal status.
// This operation does not require the barrier to be unsealed.
func (h *PKCS11IPCHandler) HandlePKCS11BarrierStatus() (*ipc.BarrierStatusResult, error) {
	return &ipc.BarrierStatusResult{
		Sealed: h.isSealed(),
	}, nil
}

// checkBarrier returns ErrBarrierSealed if the barrier is currently sealed.
func (h *PKCS11IPCHandler) checkBarrier() error {
	if h.isSealed() {
		return ipc.ErrBarrierSealed
	}
	return nil
}
