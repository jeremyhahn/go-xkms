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

package mcp

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// TestInvokeMethod_Credentials_NotConfigured proves credentials.submit and
// credentials.strategy report Service unavailable through the real
// InvokeMethod dispatch when no credential service is wired.
func TestInvokeMethod_Credentials_NotConfigured(t *testing.T) {
	methods := []struct {
		method string
		params string
	}{
		{"credentials.submit", `{"name":"test-cred","value":"c2VjcmV0"}`},
		{"credentials.strategy", `{}`},
	}

	for _, tc := range methods {
		t.Run(tc.method, func(t *testing.T) {
			server := createTestServer(t)
			defer cleanupXKMS()

			_, err := server.InvokeMethod(context.Background(), tc.method, json.RawMessage(tc.params))
			require.Error(t, err)

			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
			assert.ErrorIs(t, err, xkms.ErrNotConfigured)
		})
	}
}

// TestInvokeMethod_Credentials_DomainSentinels proves
// credentialSentinelCodes' classification of the credential service's
// sentinels reaches the caller as the matching JSON-RPC code through the
// real InvokeMethod dispatch, using the real manual-strategy
// pkg/server/credentials.Service (not a fake) so the assertions exercise the
// same validation and duplicate-submission paths production wiring uses.
func TestInvokeMethod_Credentials_DomainSentinels(t *testing.T) {
	newManualCredentialServer := func(t *testing.T) *Server {
		t.Helper()
		server := createTestServer(t)
		svc, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, nil)
		require.NoError(t, err)
		server.xkmsService.SetCredentialService(svc)
		return server
	}

	t.Run("empty name", func(t *testing.T) {
		server := newManualCredentialServer(t)
		defer cleanupXKMS()

		_, err := server.InvokeMethod(context.Background(), "credentials.submit", json.RawMessage(`{"name":"","value":"c2VjcmV0"}`))
		require.Error(t, err)

		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
		assert.ErrorIs(t, err, credentialspkg.ErrEmptyCredentialName)
	})

	t.Run("empty value", func(t *testing.T) {
		server := newManualCredentialServer(t)
		defer cleanupXKMS()

		_, err := server.InvokeMethod(context.Background(), "credentials.submit", json.RawMessage(`{"name":"test-cred","value":""}`))
		require.Error(t, err)

		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
		assert.ErrorIs(t, err, credentialspkg.ErrEmptyCredentialValue)
	})

	t.Run("invalid base64 value", func(t *testing.T) {
		server := newManualCredentialServer(t)
		defer cleanupXKMS()

		_, err := server.InvokeMethod(context.Background(), "credentials.submit", json.RawMessage(`{"name":"test-cred","value":"not-base64!!"}`))
		require.Error(t, err)

		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, ErrCodeInvalidParams, keyErr.Code)
		assert.ErrorIs(t, err, xkms.ErrInvalidEncoding)
	})

	t.Run("already submitted", func(t *testing.T) {
		server := newManualCredentialServer(t)
		defer cleanupXKMS()

		params := json.RawMessage(`{"name":"test-cred","value":"c2VjcmV0"}`)
		_, firstErr := server.InvokeMethod(context.Background(), "credentials.submit", params)
		require.NoError(t, firstErr)

		_, err := server.InvokeMethod(context.Background(), "credentials.submit", params)
		require.Error(t, err)

		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr)
		assert.Equal(t, sdkssh.JSONRPCCodeDuplicate, keyErr.Code)
		assert.ErrorIs(t, err, credentialspkg.ErrCredentialAlreadySubmitted)
	})
}

// TestInvokeMethod_Credentials_Success proves credentials.submit and
// credentials.strategy's happy paths reach the credential service and
// return a usable result through the real InvokeMethod dispatch.
func TestInvokeMethod_Credentials_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()
	svc, err := credentialspkg.New(&credentialspkg.Config{Strategy: credentialspkg.StrategyManual}, nil, nil, nil)
	require.NoError(t, err)
	server.xkmsService.SetCredentialService(svc)

	t.Run("submit", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "credentials.submit", json.RawMessage(`{"name":"test-cred","value":"c2VjcmV0"}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.CredentialSubmitResponse)
		require.True(t, ok)
		assert.Equal(t, "accepted", resp.Status)
	})

	t.Run("strategy", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "credentials.strategy", json.RawMessage(`{}`))
		require.NoError(t, err)
		resp, ok := result.(*transport.CredentialStrategyResponse)
		require.True(t, ok)
		assert.Equal(t, credentialspkg.StrategyManual, resp.Strategy)
	})
}

func TestErrXKMSServiceUnavailable(t *testing.T) {
	assert.EqualError(t, ErrXKMSServiceUnavailable, "xkms service unavailable")
}
