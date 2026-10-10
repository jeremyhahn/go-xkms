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

// embeddedCall is an EmbeddedTransport operation as a method expression,
// for example (*pkcs11svc.EmbeddedTransport).Sign.
type embeddedCall[Req, Resp any] func(*pkcs11svc.EmbeddedTransport, context.Context, *Req) (*Resp, error)

// invokePKCS11 runs one operation on the embedded transport under ctx, the
// IPC request's context, so a client that abandons the request cancels the
// operation. It refuses while the barrier is sealed, without a transport,
// or without a request, and otherwise returns the transport's own result.
// Key material crosses the socket only where the transport operation itself
// returns it, under that operation's policy.
func invokePKCS11[Req, Resp any](ctx context.Context, h *PKCS11IPCHandler, action string, req *Req, call embeddedCall[Req, Resp]) (*Resp, error) {
	if err := h.checkBarrier(); err != nil {
		return nil, err
	}
	if h.transport == nil {
		return nil, &DetailError{Err: ipc.ErrPKCS11Operation, Detail: ": embedded transport not initialized"}
	}
	if req == nil {
		return nil, &DetailError{Err: ipc.ErrInvalidMessage, Detail: ": " + action + " request required"}
	}

	resp, err := call(h.transport, ctx, req)
	if err != nil {
		h.logger.Error("pkcs11 ipc operation failed", "action", action, "error", err)
		return nil, &SentinelCauseError{Sentinel: ipc.ErrPKCS11Operation, Cause: err}
	}
	return resp, nil
}

// invokePKCS11NoResult is invokePKCS11 for an operation that returns only
// an error.
func invokePKCS11NoResult[Req any](ctx context.Context, h *PKCS11IPCHandler, action string, req *Req, call func(*pkcs11svc.EmbeddedTransport, context.Context, *Req) error) error {
	_, err := invokePKCS11(ctx, h, action, req, func(t *pkcs11svc.EmbeddedTransport, ctx context.Context, r *Req) (*struct{}, error) {
		return &struct{}{}, call(t, ctx, r)
	})
	return err
}

// HandlePKCS11GenerateKey generates a key via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11GenerateKey(ctx context.Context, req *transport.GenerateKeyRequest) (*transport.GenerateKeyResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionGenerateKey, req, (*pkcs11svc.EmbeddedTransport).GenerateKey)
}

// HandlePKCS11Sign signs data via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11Sign(ctx context.Context, req *transport.SignRequest) (*transport.SignResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionSign, req, (*pkcs11svc.EmbeddedTransport).Sign)
}

// HandlePKCS11Verify verifies a signature via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11Verify(ctx context.Context, req *transport.VerifyRequest) (*transport.VerifyResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionVerify, req, (*pkcs11svc.EmbeddedTransport).Verify)
}

// HandlePKCS11Encrypt encrypts via the embedded transport, which delegates
// to the xkms service so every cipher parameter (mode, IV or nonce, AAD,
// tag size) is honoured.
func (h *PKCS11IPCHandler) HandlePKCS11Encrypt(ctx context.Context, req *transport.EncryptRequest) (*transport.EncryptResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionEncrypt, req, (*pkcs11svc.EmbeddedTransport).Encrypt)
}

// HandlePKCS11EncryptAsym encrypts with an RSA key under OAEP via the
// embedded transport, which delegates to the xkms service so the OAEP hash
// and label are honoured.
func (h *PKCS11IPCHandler) HandlePKCS11EncryptAsym(ctx context.Context, req *transport.EncryptAsymRequest) (*transport.EncryptAsymResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionEncryptAsym, req, (*pkcs11svc.EmbeddedTransport).EncryptAsym)
}

// HandlePKCS11Decrypt decrypts via the embedded transport, which delegates
// to the xkms service: symmetric mode, IV, AAD, nonce mode and tag size, and
// RSA PKCS#1 v1.5 or OAEP with its hash and label.
func (h *PKCS11IPCHandler) HandlePKCS11Decrypt(ctx context.Context, req *transport.DecryptRequest) (*transport.DecryptResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionDecrypt, req, (*pkcs11svc.EmbeddedTransport).Decrypt)
}

// HandlePKCS11DeriveKey derives key material via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11DeriveKey(ctx context.Context, req *transport.DeriveKeyRequest) (*transport.DeriveKeyResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionDeriveKey, req, (*pkcs11svc.EmbeddedTransport).DeriveKey)
}

// HandlePKCS11DeriveKeyECDH performs ECDH key agreement via the embedded
// transport.
func (h *PKCS11IPCHandler) HandlePKCS11DeriveKeyECDH(ctx context.Context, req *transport.DeriveKeyECDHRequest) (*transport.DeriveKeyECDHResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionDeriveKeyECDH, req, (*pkcs11svc.EmbeddedTransport).DeriveKeyECDH)
}

// HandlePKCS11WrapKeyByID wraps a key via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11WrapKeyByID(ctx context.Context, req *transport.WrapKeyByIDRequest) (*transport.WrapKeyByIDResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionWrapKeyByID, req, (*pkcs11svc.EmbeddedTransport).WrapKeyByID)
}

// HandlePKCS11UnwrapKeyByID unwraps a key via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11UnwrapKeyByID(ctx context.Context, req *transport.UnwrapKeyByIDRequest) (*transport.UnwrapKeyByIDResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionUnwrapKeyByID, req, (*pkcs11svc.EmbeddedTransport).UnwrapKeyByID)
}

// HandlePKCS11ExportKeyMaterial exports key material via the embedded
// transport, which applies its own export policy.
func (h *PKCS11IPCHandler) HandlePKCS11ExportKeyMaterial(ctx context.Context, req *transport.ExportKeyMaterialRequest) (*transport.ExportKeyMaterialResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionExportKeyMaterial, req, (*pkcs11svc.EmbeddedTransport).ExportKeyMaterial)
}

// HandlePKCS11GetImportParameters begins a key import ceremony via the
// embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11GetImportParameters(ctx context.Context, req *transport.GetImportParametersRequest) (*transport.GetImportParametersResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionGetImportParameters, req, (*pkcs11svc.EmbeddedTransport).GetImportParameters)
}

// HandlePKCS11ImportKey imports a key via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11ImportKey(ctx context.Context, req *transport.ImportKeyRequest) (*transport.ImportKeyResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionImportKey, req, (*pkcs11svc.EmbeddedTransport).ImportKey)
}

// HandlePKCS11ListPIVSlots lists all PIV slots via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11ListPIVSlots(ctx context.Context, req *transport.ListPIVSlotsRequest) (*transport.ListPIVSlotsResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionListPIVSlots, req, (*pkcs11svc.EmbeddedTransport).ListPIVSlots)
}

// HandlePKCS11GetPIVCertificate retrieves a certificate from a PIV slot
// via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11GetPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionGetPIVCertificate, req, (*pkcs11svc.EmbeddedTransport).GetPIVCertificate)
}

// HandlePKCS11GeneratePIVKey generates a key in a PIV slot via the embedded
// transport.
func (h *PKCS11IPCHandler) HandlePKCS11GeneratePIVKey(ctx context.Context, req *transport.GeneratePIVKeyRequest) (*transport.GeneratePIVKeyResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionGeneratePIVKey, req, (*pkcs11svc.EmbeddedTransport).GeneratePIVKey)
}

// HandlePKCS11StorePIVCertificate stores a certificate in a PIV slot via
// the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11StorePIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return invokePKCS11NoResult(ctx, h, ipc.ActionStorePIVCertificate, req, (*pkcs11svc.EmbeddedTransport).StorePIVCertificate)
}

// HandlePKCS11DeletePIVCertificate removes the certificate from a PIV slot
// via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11DeletePIVCertificate(ctx context.Context, req *transport.DeletePIVCertificateRequest) error {
	return invokePKCS11NoResult(ctx, h, ipc.ActionDeletePIVCertificate, req, (*pkcs11svc.EmbeddedTransport).DeletePIVCertificate)
}

// HandlePKCS11ImportPIVCertificate imports a certificate into a PIV slot
// via the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11ImportPIVCertificate(ctx context.Context, req *transport.StorePIVCertificateRequest) error {
	return invokePKCS11NoResult(ctx, h, ipc.ActionImportPIVCertificate, req, (*pkcs11svc.EmbeddedTransport).ImportPIVCertificate)
}

// HandlePKCS11ExportPIVCertificate exports the certificate of a PIV slot via
// the embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11ExportPIVCertificate(ctx context.Context, req *transport.GetPIVCertificateRequest) (*transport.GetPIVCertificateResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionExportPIVCertificate, req, (*pkcs11svc.EmbeddedTransport).ExportPIVCertificate)
}

// HandlePKCS11GeneratePIVCSR generates a CSR for a PIV slot key via the
// embedded transport.
func (h *PKCS11IPCHandler) HandlePKCS11GeneratePIVCSR(ctx context.Context, req *transport.GeneratePIVCSRRequest) (*transport.GeneratePIVCSRResponse, error) {
	return invokePKCS11(ctx, h, ipc.ActionGeneratePIVCSR, req, (*pkcs11svc.EmbeddedTransport).GeneratePIVCSR)
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
