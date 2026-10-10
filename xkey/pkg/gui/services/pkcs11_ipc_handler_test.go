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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	pkcs11svc "github.com/jeremyhahn/go-xkms/xkey/pkg/pkcs11"
)

// handlerOp calls one PKCS11IPCHandler operation, with its request or with a
// nil one, and returns only the error.
type handlerOp func(h *PKCS11IPCHandler, withRequest bool) error

func opOf[Req, Resp any](call func(*PKCS11IPCHandler, context.Context, *Req) (*Resp, error), req *Req) handlerOp {
	return func(h *PKCS11IPCHandler, withRequest bool) error {
		sent := req
		if !withRequest {
			sent = nil
		}
		resp, err := call(h, context.Background(), sent)
		if err == nil && resp == nil {
			return errors.New("nil response without an error")
		}
		return err
	}
}

func noResultOpOf[Req any](call func(*PKCS11IPCHandler, context.Context, *Req) error, req *Req) handlerOp {
	return func(h *PKCS11IPCHandler, withRequest bool) error {
		if !withRequest {
			return call(h, context.Background(), nil)
		}
		return call(h, context.Background(), req)
	}
}

// handlerOps holds every operation that needs unsealed keys, each with a
// request naming a key that does not exist.
func handlerOps() map[string]handlerOp {
	return map[string]handlerOp{
		ipc.ActionGenerateKey: opOf((*PKCS11IPCHandler).HandlePKCS11GenerateKey,
			&transport.GenerateKeyRequest{Backend: "missing", KeyID: "k", Algorithm: "ECDSA"}),
		ipc.ActionSign: opOf((*PKCS11IPCHandler).HandlePKCS11Sign,
			&transport.SignRequest{Backend: "missing", KeyID: "k", Data: []byte("d")}),
		ipc.ActionVerify: opOf((*PKCS11IPCHandler).HandlePKCS11Verify,
			&transport.VerifyRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionEncrypt: opOf((*PKCS11IPCHandler).HandlePKCS11Encrypt,
			&transport.EncryptRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionEncryptAsym: opOf((*PKCS11IPCHandler).HandlePKCS11EncryptAsym,
			&transport.EncryptAsymRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionDecrypt: opOf((*PKCS11IPCHandler).HandlePKCS11Decrypt,
			&transport.DecryptRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionDeriveKey: opOf((*PKCS11IPCHandler).HandlePKCS11DeriveKey,
			&transport.DeriveKeyRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionDeriveKeyECDH: opOf((*PKCS11IPCHandler).HandlePKCS11DeriveKeyECDH,
			&transport.DeriveKeyECDHRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionWrapKeyByID: opOf((*PKCS11IPCHandler).HandlePKCS11WrapKeyByID,
			&transport.WrapKeyByIDRequest{WrappingKeyBackend: "missing", WrappingKeyID: "w"}),
		ipc.ActionUnwrapKeyByID: opOf((*PKCS11IPCHandler).HandlePKCS11UnwrapKeyByID,
			&transport.UnwrapKeyByIDRequest{UnwrappingKeyBackend: "missing", UnwrappingKeyID: "w"}),
		ipc.ActionExportKeyMaterial: opOf((*PKCS11IPCHandler).HandlePKCS11ExportKeyMaterial,
			&transport.ExportKeyMaterialRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionGetImportParameters: opOf((*PKCS11IPCHandler).HandlePKCS11GetImportParameters,
			&transport.GetImportParametersRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionImportKey: opOf((*PKCS11IPCHandler).HandlePKCS11ImportKey,
			&transport.ImportKeyRequest{Backend: "missing", KeyID: "k"}),
		ipc.ActionListPIVSlots: opOf((*PKCS11IPCHandler).HandlePKCS11ListPIVSlots,
			&transport.ListPIVSlotsRequest{Backend: "missing"}),
		ipc.ActionGetPIVCertificate: opOf((*PKCS11IPCHandler).HandlePKCS11GetPIVCertificate,
			&transport.GetPIVCertificateRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionGeneratePIVKey: opOf((*PKCS11IPCHandler).HandlePKCS11GeneratePIVKey,
			&transport.GeneratePIVKeyRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionStorePIVCertificate: noResultOpOf((*PKCS11IPCHandler).HandlePKCS11StorePIVCertificate,
			&transport.StorePIVCertificateRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionDeletePIVCertificate: noResultOpOf((*PKCS11IPCHandler).HandlePKCS11DeletePIVCertificate,
			&transport.DeletePIVCertificateRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionImportPIVCertificate: noResultOpOf((*PKCS11IPCHandler).HandlePKCS11ImportPIVCertificate,
			&transport.StorePIVCertificateRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionExportPIVCertificate: opOf((*PKCS11IPCHandler).HandlePKCS11ExportPIVCertificate,
			&transport.GetPIVCertificateRequest{Backend: "missing", Slot: "9a"}),
		ipc.ActionGeneratePIVCSR: opOf((*PKCS11IPCHandler).HandlePKCS11GeneratePIVCSR,
			&transport.GeneratePIVCSRRequest{Backend: "missing", Slot: "9a"}),
	}
}

func TestNewPKCS11IPCHandler(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })
	assert.NotNil(t, handler)
}

func TestPKCS11IPCHandler_ImplementsInterface(t *testing.T) {
	var _ ipc.PKCS11Handler = (*PKCS11IPCHandler)(nil)
}

func TestPKCS11IPCHandler_HandlerOpsCoverEveryOperation(t *testing.T) {
	// barrier_status is the one operation that must answer while sealed.
	assert.Len(t, handlerOps(), 21)
}

func TestPKCS11IPCHandler_BarrierStatus_Unsealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11BarrierStatus()
	require.NoError(t, err)
	assert.False(t, result.Sealed)
}

func TestPKCS11IPCHandler_BarrierStatus_Sealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })

	result, err := handler.HandlePKCS11BarrierStatus()
	require.NoError(t, err)
	assert.True(t, result.Sealed)
}

func TestPKCS11IPCHandler_EveryOperation_BarrierSealed(t *testing.T) {
	// The transport is real but the barrier refuses first, so not even a
	// nil request reaches it.
	handler := NewPKCS11IPCHandler(&pkcs11svc.EmbeddedTransport{}, testLogger(), func() bool { return true })
	for action, op := range handlerOps() {
		for _, withRequest := range []bool{true, false} {
			err := op(handler, withRequest)
			assert.ErrorIs(t, err, ipc.ErrBarrierSealed, "%s (request: %v)", action, withRequest)
		}
	}
}

func TestPKCS11IPCHandler_EveryOperation_NilTransport(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })
	for action, op := range handlerOps() {
		err := op(handler, true)
		require.ErrorIs(t, err, ipc.ErrPKCS11Operation, action)
		assert.Contains(t, err.Error(), "embedded transport not initialized", action)
	}
}

func TestPKCS11IPCHandler_EveryOperation_NilRequest(t *testing.T) {
	handler := NewPKCS11IPCHandler(&pkcs11svc.EmbeddedTransport{}, testLogger(), func() bool { return false })
	for action, op := range handlerOps() {
		err := op(handler, false)
		require.ErrorIs(t, err, ipc.ErrInvalidMessage, action)
		assert.Contains(t, err.Error(), action+" request required")
	}
}

func TestPKCS11IPCHandler_EveryOperation_EmbeddedFailureWrapped(t *testing.T) {
	// The xkms service is not initialized here, so every embedded call
	// fails; the handler must report the operation sentinel and keep the
	// embedded cause reachable for the log, never a bare cause.
	handler := NewPKCS11IPCHandler(&pkcs11svc.EmbeddedTransport{}, testLogger(), func() bool { return false })
	for action, op := range handlerOps() {
		err := op(handler, true)
		assert.ErrorIs(t, err, ipc.ErrPKCS11Operation, action)
	}
}

func TestPKCS11IPCHandler_CheckBarrier_Unsealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })
	assert.NoError(t, handler.checkBarrier())
}

func TestPKCS11IPCHandler_CheckBarrier_Sealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })
	err := handler.checkBarrier()
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}
