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
	"encoding/base64"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

func TestNewPKCS11IPCHandler(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })
	assert.NotNil(t, handler)
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

func TestPKCS11IPCHandler_Sign_BarrierSealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })

	result, err := handler.HandlePKCS11Sign(&ipc.SignParams{
		KeyID: "test-key",
		Data:  base64.StdEncoding.EncodeToString([]byte("test")),
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}

func TestPKCS11IPCHandler_Sign_NilTransport(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11Sign(&ipc.SignParams{
		KeyID: "test-key",
		Data:  base64.StdEncoding.EncodeToString([]byte("test")),
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
	assert.Contains(t, err.Error(), "embedded transport not initialized")
}

func TestPKCS11IPCHandler_Sign_InvalidBase64_WithSealedBarrier(t *testing.T) {
	// When barrier is sealed, the base64 decode error is never reached.
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })
	result, err := handler.HandlePKCS11Sign(&ipc.SignParams{
		KeyID: "test-key",
		Data:  "!!!invalid-base64!!!",
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}

func TestPKCS11IPCHandler_GetPIVCertificate_BarrierSealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })

	result, err := handler.HandlePKCS11GetPIVCertificate(&ipc.PIVCertParams{
		Slot: "9a",
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}

func TestPKCS11IPCHandler_GetPIVCertificate_NilTransport(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11GetPIVCertificate(&ipc.PIVCertParams{
		Slot: "9a",
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
	assert.Contains(t, err.Error(), "embedded transport not initialized")
}

func TestPKCS11IPCHandler_ListPIVSlots_BarrierSealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })

	result, err := handler.HandlePKCS11ListPIVSlots(&ipc.PIVSlotsParams{
		Backend: "software",
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}

func TestPKCS11IPCHandler_ListPIVSlots_NilTransport(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })

	result, err := handler.HandlePKCS11ListPIVSlots(&ipc.PIVSlotsParams{
		Backend: "software",
	})

	assert.Nil(t, result)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrPKCS11Operation))
	assert.Contains(t, err.Error(), "embedded transport not initialized")
}

func TestPKCS11IPCHandler_CheckBarrier_Unsealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return false })
	assert.NoError(t, handler.checkBarrier())
}

func TestPKCS11IPCHandler_CheckBarrier_Sealed(t *testing.T) {
	handler := NewPKCS11IPCHandler(nil, testLogger(), func() bool { return true })
	err := handler.checkBarrier()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ipc.ErrBarrierSealed))
}

func TestPKCS11IPCHandler_ImplementsInterface(t *testing.T) {
	// Verify compile-time interface compliance.
	var _ ipc.PKCS11Handler = (*PKCS11IPCHandler)(nil)
}
