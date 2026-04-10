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

package pairing

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsPIVMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	pivMethods := []string{
		MethodRemotePIVListSlots,
		MethodRemotePIVSign,
		MethodRemotePIVGetCert,
	}

	for _, method := range pivMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for PIV method %s", method)
	}
}

// --- handlePIVListSlots tests ---

func TestBridge_HandlePIVListSlots_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVListSlots, RemotePIVListSlotsParams{
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemotePIVListSlotsResult](t, resp)
	assert.Empty(t, result.Slots)
}

func TestBridge_HandlePIVListSlots_NilParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// ListSlots does not require params, should still succeed.
	req := newRemoteRequest(MethodRemotePIVListSlots, nil)
	resp := b.HandleRequest(context.Background(), req)

	// The handler accepts nil/empty params gracefully.
	require.Nil(t, resp.Error, "expected success but got error: %v", resp.Error)
	result := decodeResult[RemotePIVListSlotsResult](t, resp)
	assert.Empty(t, result.Slots)
}

func TestBridge_HandlePIVListSlots_EmptyParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVListSlots, RemotePIVListSlotsParams{})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemotePIVListSlotsResult](t, resp)
	assert.Empty(t, result.Slots)
}

// --- handlePIVSign tests ---

func TestBridge_HandlePIVSign_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVSign, RemotePIVSignParams{
		Slot:      PIVSlotAuthentication,
		Data:      []byte("data to sign"),
		Algorithm: "SHA256withECDSA",
		Backend:   "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemotePIVSignResult](t, resp)
	assert.Nil(t, result.Signature)
	assert.Equal(t, "SHA256withECDSA", result.Algorithm)
}

func TestBridge_HandlePIVSign_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemotePIVSign, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandlePIVSign_EmptySlot(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVSign, RemotePIVSignParams{
		Data: []byte("data to sign"),
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodePIVInvalidSlot)
}

func TestBridge_HandlePIVSign_EmptyData(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVSign, RemotePIVSignParams{
		Slot: PIVSlotAuthentication,
		Data: []byte{},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handlePIVGetCert tests ---

func TestBridge_HandlePIVGetCert_Success(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVGetCert, RemotePIVGetCertParams{
		Slot:    PIVSlotAuthentication,
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemotePIVGetCertResult](t, resp)
	assert.Nil(t, result.CertificateDER)
}

func TestBridge_HandlePIVGetCert_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemotePIVGetCert, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandlePIVGetCert_EmptySlot(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemotePIVGetCert, RemotePIVGetCertParams{
		Backend: "pkcs11",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodePIVInvalidSlot)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_PIVSlotNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(ErrPIVSlotNotFound)
	assert.Equal(t, ErrorCodePIVSlotNotFound, code)
	assert.Contains(t, msg, "PIV slot not found")
}

func TestMapErrorToRPC_PIVSlotOccupied(t *testing.T) {
	code, msg := mapErrorToRPC(ErrPIVSlotOccupied)
	assert.Equal(t, ErrorCodePIVSlotOccupied, code)
	assert.Contains(t, msg, "PIV slot already occupied")
}

func TestMapErrorToRPC_PIVSignFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrPIVSignFailed)
	assert.Equal(t, ErrorCodePIVSignFailed, code)
	assert.Contains(t, msg, "PIV signing failed")
}

func TestMapErrorToRPC_PIVInvalidSlot(t *testing.T) {
	code, msg := mapErrorToRPC(ErrPIVInvalidSlot)
	assert.Equal(t, ErrorCodePIVInvalidSlot, code)
	assert.Contains(t, msg, "invalid PIV slot")
}

// --- Nil params tests for PIV handlers ---

func TestBridge_NilParams_PIVHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// pivSign and pivGetCert require params.
	methodsRequiringParams := []string{
		MethodRemotePIVSign,
		MethodRemotePIVGetCert,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
		})
	}
}
