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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// --- Dispatch map tests ---

func TestBridge_DispatchMap_ContainsOATHMethods(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	oathMethods := []string{
		MethodRemoteOATHAdd,
		MethodRemoteOATHGenerate,
	}

	for _, method := range oathMethods {
		_, ok := b.handlers[method]
		assert.True(t, ok, "handler not registered for OATH method %s", method)
	}
}

func TestBridge_DispatchMap_TotalHandlerCount_WithOATH(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// 16 original + 3 sharing + 3 backup + 2 OATH + 3 PIV + 5 sync
	// + 1 enrollment-certificate store = 33 total handlers.
	assert.Len(t, b.handlers, 33)
}

// --- handleOATHAdd tests ---

// TestBridge_HandleOATHAdd_NotConfigured verifies that without an OATH store
// wired into the Bridge, remote.oathAdd reports the feature as unavailable
// rather than fabricating success.
func TestBridge_HandleOATHAdd_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHAdd, RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:      "GitHub",
			Issuer:    "GitHub",
			Secret:    "JBSWY3DPEHPK3PXP",
			Type:      "totp",
			Algorithm: "SHA1",
			Digits:    6,
			Period:    30,
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleOATHAdd_Success verifies the real round trip through the
// dispatch path: a credential added via remote.oathAdd is stored in the
// configured oath.Store and can be retrieved back out of it.
func TestBridge_HandleOATHAdd_Success(t *testing.T) {
	store := oath.NewMemoryStore()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), OATHStore: store})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHAdd, RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:        "GitHub",
			Issuer:      "GitHub",
			AccountName: "alice@example.com",
			Secret:      "JBSWY3DPEHPK3PXP",
			Type:        "totp",
			Algorithm:   "SHA1",
			Digits:      6,
			Period:      30,
		},
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteOATHAddResult](t, resp)
	assert.True(t, result.Success)
	assert.NotEmpty(t, result.CredentialID)
	assert.Equal(t, "credential stored", result.Message)

	stored, err := store.Get(result.CredentialID)
	require.NoError(t, err)
	assert.Equal(t, "GitHub", stored.Name)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", stored.SecretString())
}

// TestBridge_HandleOATHAdd_Duplicate verifies that adding the same credential
// twice through dispatch reports a key-exists error rather than silently
// overwriting it.
func TestBridge_HandleOATHAdd_Duplicate(t *testing.T) {
	store := oath.NewMemoryStore()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), OATHStore: store})
	require.NoError(t, err)

	params := RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:   "GitHub",
			Issuer: "GitHub",
			Secret: "JBSWY3DPEHPK3PXP",
			Type:   "totp",
		},
	}

	first := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteOATHAdd, params))
	decodeResult[RemoteOATHAddResult](t, first)

	second := b.HandleRequest(context.Background(), newRemoteRequest(MethodRemoteOATHAdd, params))
	assertErrorResponse(t, second, 1, ErrorCodeKeyExists)
}

func TestBridge_HandleOATHAdd_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemoteOATHAdd, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleOATHAdd_EmptyName(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHAdd, RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:   "",
			Secret: "JBSWY3DPEHPK3PXP",
			Type:   "totp",
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleOATHAdd_EmptySecret(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHAdd, RemoteOATHAddParams{
		Credential: OATHCredentialInfo{
			Name:   "GitHub",
			Secret: "",
			Type:   "totp",
		},
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- handleOATHGenerate tests ---

// TestBridge_HandleOATHGenerate_NotConfigured verifies that without an OATH
// store wired into the Bridge, remote.oathGenerate reports the feature as
// unavailable rather than returning an empty code as if it succeeded.
func TestBridge_HandleOATHGenerate_NotConfigured(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHGenerate, RemoteOATHGenerateParams{
		CredentialID: "cred-001",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeFeatureUnavailable)
}

// TestBridge_HandleOATHGenerate_NotFound verifies that a credential ID absent
// from the configured store is reported as OATH-not-found, not a silent
// empty code.
func TestBridge_HandleOATHGenerate_NotFound(t *testing.T) {
	store := oath.NewMemoryStore()
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), OATHStore: store})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHGenerate, RemoteOATHGenerateParams{
		CredentialID: "cred-001",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeOATHNotFound)
}

// TestBridge_HandleOATHGenerate_Success verifies the real round trip through
// the dispatch path: a credential added to the store produces a well-formed
// 6-digit TOTP code with a sane expiry window.
func TestBridge_HandleOATHGenerate_Success(t *testing.T) {
	store := oath.NewMemoryStore()
	cred, err := oath.NewCredentialFromManualEntry("alice@example.com", "GitHub", "JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	require.NoError(t, store.Add(cred))

	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger(), OATHStore: store})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHGenerate, RemoteOATHGenerateParams{
		CredentialID: cred.ID,
	})
	resp := b.HandleRequest(context.Background(), req)

	result := decodeResult[RemoteOATHGenerateResult](t, resp)
	assert.Len(t, result.Code, 6)
	assert.Greater(t, result.ExpiresIn, 0)
	assert.LessOrEqual(t, result.ExpiresIn, 30)
}

func TestBridge_HandleOATHGenerate_InvalidParams(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Nil params
	req := newRemoteRequest(MethodRemoteOATHGenerate, nil)
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

func TestBridge_HandleOATHGenerate_EmptyCredentialID(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	req := newRemoteRequest(MethodRemoteOATHGenerate, RemoteOATHGenerateParams{
		CredentialID: "",
	})
	resp := b.HandleRequest(context.Background(), req)
	assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
}

// --- Error mapping tests ---

func TestMapErrorToRPC_OATHCredentialNotFound(t *testing.T) {
	code, msg := mapErrorToRPC(ErrOATHCredentialNotFound)
	assert.Equal(t, ErrorCodeOATHNotFound, code)
	assert.Contains(t, msg, "OATH credential not found")
}

func TestMapErrorToRPC_OATHGenerateFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrOATHGenerateFailed)
	assert.Equal(t, ErrorCodeOATHGenerate, code)
	assert.Contains(t, msg, "OATH code generation failed")
}

func TestMapErrorToRPC_OATHStoreFailed(t *testing.T) {
	code, msg := mapErrorToRPC(ErrOATHStoreFailed)
	assert.Equal(t, ErrorCodeOATHStore, code)
	assert.Contains(t, msg, "OATH store operation failed")
}

// --- Nil params tests for OATH handlers ---

func TestBridge_NilParams_OATHHandlers(t *testing.T) {
	client := &mockTransportClient{}
	b, err := NewBridge(client, &BridgeConfig{Logger: testLogger()})
	require.NoError(t, err)

	// Both OATH handlers require params.
	methodsRequiringParams := []string{
		MethodRemoteOATHAdd,
		MethodRemoteOATHGenerate,
	}

	for _, method := range methodsRequiringParams {
		t.Run(method, func(t *testing.T) {
			req := newRemoteRequest(method, nil)
			resp := b.HandleRequest(context.Background(), req)
			assertErrorResponse(t, resp, req.ID, ErrorCodeInvalidParams)
		})
	}
}
