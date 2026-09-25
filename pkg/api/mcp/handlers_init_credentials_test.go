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
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	credentialspkg "github.com/jeremyhahn/go-xkms/pkg/server/credentials"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

// errCeremony implements transport.InitCeremonyService, returning err
// unconditionally from every method, so tests can drive each of
// ceremonySentinelCodes' sentinels through the real InvokeMethod dispatch
// instead of only through the transport-level "not configured" nil check.
type errCeremony struct {
	err error
}

var _ transport.InitCeremonyService = (*errCeremony)(nil)

func (c *errCeremony) GetInitStatus(context.Context) (*transport.InitStatusResponse, error) {
	return nil, c.err
}

func (c *errCeremony) ClaimCertBegin(context.Context, *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return nil, c.err
}

func (c *errCeremony) ClaimCertComplete(context.Context, *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return nil, c.err
}

func (c *errCeremony) ClaimShareBegin(context.Context, *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	return nil, c.err
}

func (c *errCeremony) ClaimShareComplete(context.Context, *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	return nil, c.err
}

func (c *errCeremony) SignCSRInit(context.Context, *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return nil, c.err
}

// TestInvokeMethod_Ceremony_XKMSServiceNil proves every ceremony handler
// reaches the caller as Service unavailable, through the real InvokeMethod
// dispatch, when no xkms service is wired at all (createTestServer is not
// used here for this exact reason: it always injects one).
func TestInvokeMethod_Ceremony_XKMSServiceNil(t *testing.T) {
	bare := &Server{}
	ctx := context.Background()

	for _, method := range []string{
		"init.getStatus",
		"init.claimCertBegin",
		"init.claimCertComplete",
		"init.claimShareBegin",
		"init.claimShareComplete",
		"init.signCSR",
		"credentials.submit",
		"credentials.strategy",
	} {
		t.Run(method, func(t *testing.T) {
			handler, ok := rpcMethodHandlers[method]
			require.True(t, ok, "%s must be dispatchable", method)

			req := &JSONRPCRequest{JSONRPC: "2.0", Method: method, ID: 1}
			_, err := handler(bare, ctx, req)
			require.Error(t, err)

			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code)
			assert.ErrorIs(t, err, ErrXKMSServiceUnavailable)
		})
	}
}

// TestInvokeMethod_Ceremony_NotConfigured proves every ceremony handler
// reaches the caller as Service unavailable when the xkms service is wired
// but no ceremony service is (createTestServer's fixture carries none),
// matching this package's own xkms.ErrNotConfigured floor since no gRPC
// transport exists for this domain (go-xkms#921).
func TestInvokeMethod_Ceremony_NotConfigured(t *testing.T) {
	methods := []struct {
		method string
		params string
	}{
		{"init.getStatus", `{}`},
		{"init.claimCertBegin", `{"username":"officer-A"}`},
		{"init.claimCertComplete", `{"username":"officer-A","nonce":"abcd","signature":"c2ln"}`},
		{"init.signCSR", `{"username":"officer-A","so_pin":"1234","csr_pem":"x","role":"admin"}`},
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

// TestInvokeMethod_Ceremony_ShareClaimSentinels proves the two share-claim
// methods classify a ceremony domain sentinel through the real InvokeMethod
// dispatch, once the peer-certificate precondition is satisfied.
func TestInvokeMethod_Ceremony_ShareClaimSentinels(t *testing.T) {
	for _, method := range []string{"init.claimShareBegin", "init.claimShareComplete"} {
		t.Run(method, func(t *testing.T) {
			server := createTestServer(t)
			defer cleanupXKMS()
			server.xkmsService.SetCeremonyService(&errCeremony{err: initialize.ErrOfficerNotFound})

			ctx := mcpCtxWithPeerCert(t)
			_, err := server.InvokeMethod(ctx, method, json.RawMessage(`{"username":"officer-A"}`))
			require.Error(t, err)

			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, sdkssh.JSONRPCCodeNotFound, keyErr.Code)
			assert.ErrorIs(t, err, initialize.ErrOfficerNotFound)
		})
	}
}

// TestInvokeMethod_Ceremony_DomainSentinels proves ceremonySentinelCodes'
// classification of the init.claimCertBegin/Complete and init.signCSR
// conditions reaches the caller as the matching JSON-RPC code through the
// real InvokeMethod dispatch.
func TestInvokeMethod_Ceremony_DomainSentinels(t *testing.T) {
	tests := []struct {
		name   string
		method string
		params string
		err    error
		code   int
	}{
		{"claimCertBegin pending cert not found", "init.claimCertBegin", `{"username":"officer-A"}`, initialize.ErrPendingCertNotFound, sdkssh.JSONRPCCodeNotFound},
		{"claimCertComplete already claimed", "init.claimCertComplete", `{"username":"officer-A","nonce":"abcd","signature":"c2ln"}`, initialize.ErrCertAlreadyClaimed, sdkssh.JSONRPCCodeDuplicate},
		{"claimCertComplete challenge verification failed", "init.claimCertComplete", `{"username":"officer-A","nonce":"abcd","signature":"c2ln"}`, initialize.ErrChallengeVerificationFailed, ErrCodeUnauthorized},
		{"signCSR invalid SO PIN", "init.signCSR", `{"username":"officer-A","so_pin":"1234","csr_pem":"x","role":"admin"}`, initialize.ErrInvalidSOPIN, ErrCodeInvalidParams},
		{"signCSR SO PIN mismatch", "init.signCSR", `{"username":"officer-A","so_pin":"1234","csr_pem":"x","role":"admin"}`, initialize.ErrSOPINMismatch, ErrCodeUnauthorized},
		{"signCSR CA not initialized", "init.signCSR", `{"username":"officer-A","so_pin":"1234","csr_pem":"x","role":"admin"}`, initialize.ErrCANotInitialized, ErrCodeServiceUnavailable},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := createTestServer(t)
			defer cleanupXKMS()
			server.xkmsService.SetCeremonyService(&errCeremony{err: tc.err})

			_, err := server.InvokeMethod(context.Background(), tc.method, json.RawMessage(tc.params))
			require.Error(t, err)

			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tc.code, keyErr.Code)
			assert.ErrorIs(t, err, tc.err)
		})
	}
}

// TestInvokeMethod_Ceremony_Success proves each ceremony handler's happy
// path reaches the ceremony service and returns a usable result through the
// real InvokeMethod dispatch.
func TestInvokeMethod_Ceremony_Success(t *testing.T) {
	server := createTestServer(t)
	defer cleanupXKMS()
	server.xkmsService.SetCeremonyService(&stateOnlyCeremony{state: string(initialize.StateEnrolling)})

	t.Run("getStatus", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "init.getStatus", json.RawMessage(`{}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("claimCertBegin", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "init.claimCertBegin", json.RawMessage(`{"username":"officer-A"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("claimCertComplete", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "init.claimCertComplete", json.RawMessage(`{"username":"officer-A","nonce":"abcd","signature":"c2ln"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("claimShareBegin", func(t *testing.T) {
		result, err := server.InvokeMethod(mcpCtxWithPeerCert(t), "init.claimShareBegin", json.RawMessage(`{"username":"officer-A"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("claimShareComplete", func(t *testing.T) {
		result, err := server.InvokeMethod(mcpCtxWithPeerCert(t), "init.claimShareComplete", json.RawMessage(`{"username":"officer-A"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("signCSR", func(t *testing.T) {
		result, err := server.InvokeMethod(context.Background(), "init.signCSR", json.RawMessage(`{"username":"officer-A","so_pin":"1234","csr_pem":"x","role":"admin"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})
}

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
