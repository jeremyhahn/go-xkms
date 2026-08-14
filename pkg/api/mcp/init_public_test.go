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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// stateOnlyCeremony reports a fixed ceremony state and answers each claim
// method with a marker payload. The ceremony protocol itself is exercised
// end-to-end against the real service in pkg/api/rest; this double isolates
// the MCP authorization gate's state condition.
type stateOnlyCeremony struct {
	state string
}

var _ transport.InitCeremonyService = (*stateOnlyCeremony)(nil)

func (c *stateOnlyCeremony) GetInitStatus(context.Context) (*transport.InitStatusResponse, error) {
	return &transport.InitStatusResponse{State: c.state}, nil
}

func (c *stateOnlyCeremony) ClaimCertBegin(context.Context, *transport.ClaimCertBeginRequest) (*transport.ClaimCertBeginResponse, error) {
	return &transport.ClaimCertBeginResponse{Nonce: "abcd", Username: "officer-A"}, nil
}

func (c *stateOnlyCeremony) ClaimCertComplete(context.Context, *transport.ClaimCertCompleteRequest) (*transport.ClaimCertCompleteResponse, error) {
	return &transport.ClaimCertCompleteResponse{CertPEM: "cert", CACertPEM: "ca"}, nil
}

func (c *stateOnlyCeremony) ClaimShareBegin(_ context.Context, req *transport.ClaimShareBeginRequest) (*transport.ClaimShareBeginResponse, error) {
	if req.CallerCertThumbprint == "" {
		return nil, errMCPNoCallerThumbprint
	}
	return &transport.ClaimShareBeginResponse{Nonce: "abcd", Username: "officer-A"}, nil
}

func (c *stateOnlyCeremony) ClaimShareComplete(_ context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	if req.CallerCertThumbprint == "" {
		return nil, errMCPNoCallerThumbprint
	}
	return &transport.ClaimShareCompleteResponse{ShareIndex: 1, Share: json.RawMessage(`{"index":1}`)}, nil
}

func (c *stateOnlyCeremony) SignCSRInit(context.Context, *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return &transport.SignCSRInitResponse{CertPEM: "cert"}, nil
}

// errMCPNoCallerThumbprint is returned by the stub when a share-claim request
// reaches the service without a caller certificate thumbprint. Its presence in
// a response proves the handler skipped the peer-certificate check.
var errMCPNoCallerThumbprint = errors.New("caller certificate thumbprint missing")

// newCeremonyMCPServer builds an RBAC-enforcing MCP server whose RBAC client
// grants nothing and whose ceremony reports the given state.
func newCeremonyMCPServer(t *testing.T, state string) *Server {
	t.Helper()
	svc := setupTestXKMS(t)
	t.Cleanup(cleanupXKMS)
	svc.SetCeremonyService(&stateOnlyCeremony{state: state})
	return newRBACServer(t, svc, newFakeRBAC())
}

// claimMethods is the init surface an officer must be able to invoke without a
// credential. init.signCSR is deliberately excluded.
var claimMethods = []string{
	"init.getStatus",
	"init.claimCertBegin",
	"init.claimCertComplete",
	"init.claimShareBegin",
	"init.claimShareComplete",
}

// TestMCPInitCeremony_ClaimMethodsPublicWhileEnrolling verifies the MCP
// authorization gate lets a credential-less officer invoke the claim methods
// while the ceremony is enrolling. Without this the ceremony deadlocks on MCP
// the same way it did on REST.
func TestMCPInitCeremony_ClaimMethodsPublicWhileEnrolling(t *testing.T) {
	s := newCeremonyMCPServer(t, string(initialize.StateEnrolling))

	for _, method := range claimMethods {
		t.Run(method, func(t *testing.T) {
			// No identity in the context: this is the officer's situation.
			require.NoError(t, s.authorizeMethod(context.Background(), method))
		})
	}
}

// TestMCPInitCeremony_ClaimMethodsGatedWhenOperational verifies the exemption
// is conditioned on ceremony state, not on the method name alone.
func TestMCPInitCeremony_ClaimMethodsGatedWhenOperational(t *testing.T) {
	s := newCeremonyMCPServer(t, string(initialize.StateOperational))

	for _, method := range claimMethods {
		t.Run(method, func(t *testing.T) {
			err := s.authorizeMethod(context.Background(), method)
			require.Error(t, err, "%s must be gated once the ceremony is operational", method)

			var opErr *KeyOpError
			require.ErrorAs(t, err, &opErr)
			assert.Equal(t, ErrCodeUnauthorized, opErr.Code)
		})
	}
}

// TestMCPInitCeremony_SignCSRAlwaysGated verifies init.signCSR never inherits
// the exemption: it carries the SO PIN and belongs to an enrolled operator.
func TestMCPInitCeremony_SignCSRAlwaysGated(t *testing.T) {
	for _, state := range []string{
		string(initialize.StateAwaitingInit),
		string(initialize.StateEnrolling),
		string(initialize.StateOperational),
	} {
		t.Run(state, func(t *testing.T) {
			s := newCeremonyMCPServer(t, state)
			err := s.authorizeMethod(context.Background(), "init.signCSR")
			require.Error(t, err, "init.signCSR must always require authorization")
		})
	}
}

// TestMCPInitCeremony_ExemptionDoesNotWiden verifies no method outside the
// claim allowlist becomes public while the ceremony is enrolling.
func TestMCPInitCeremony_ExemptionDoesNotWiden(t *testing.T) {
	s := newCeremonyMCPServer(t, string(initialize.StateEnrolling))

	for _, method := range []string{
		"init.signCSR",
		"xkms.listKeys",
		"xkms.generateKey",
		"barrier.unseal",
		"credentials.submit",
		"xkms.ca.sign-csr",
	} {
		t.Run(method, func(t *testing.T) {
			assert.Error(t, s.authorizeMethod(context.Background(), method),
				"%s must not inherit the init ceremony exemption", method)
		})
	}
}

// TestMCPIsPublicCeremonyMethod_FailsClosed covers the predicate's fail-closed
// paths: an unknown state string and a server with no ceremony wired.
func TestMCPIsPublicCeremonyMethod_FailsClosed(t *testing.T) {
	t.Run("unknown state", func(t *testing.T) {
		s := newCeremonyMCPServer(t, "some-future-state")
		for _, method := range claimMethods {
			assert.False(t, s.isPublicCeremonyMethod(context.Background(), method))
		}
	})

	t.Run("no ceremony wired", func(t *testing.T) {
		svc := setupTestXKMS(t)
		t.Cleanup(cleanupXKMS)
		s := newRBACServer(t, svc, newFakeRBAC())
		for _, method := range claimMethods {
			assert.False(t, s.isPublicCeremonyMethod(context.Background(), method))
		}
	})

	t.Run("no xkms service", func(t *testing.T) {
		s := &Server{}
		assert.False(t, s.isPublicCeremonyMethod(context.Background(), "init.getStatus"))
	})
}

// TestMCPInitCeremony_ShareClaimRequiresClientCert proves the two share-claim
// methods refuse a session that carries no verified mTLS peer certificate, and
// that no share material comes back on the refusal path.
func TestMCPInitCeremony_ShareClaimRequiresClientCert(t *testing.T) {
	s := newCeremonyMCPServer(t, string(initialize.StateEnrolling))

	for _, method := range []string{"init.claimShareBegin", "init.claimShareComplete"} {
		t.Run(method+" without peer certificate", func(t *testing.T) {
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`1`),
				Method:  method,
				Params:  json.RawMessage(`{"username":"officer-A"}`),
			}
			result, err := rpcMethodHandlers[method](s, context.Background(), req)
			require.ErrorIs(t, err, ErrClientCertRequired)
			assert.Nil(t, result, "no share material may accompany a refusal")
		})

		t.Run(method+" with peer certificate", func(t *testing.T) {
			req := &JSONRPCRequest{
				JSONRPC: "2.0",
				ID:      json.RawMessage(`1`),
				Method:  method,
				Params:  json.RawMessage(`{"username":"officer-A"}`),
			}
			result, err := rpcMethodHandlers[method](s, mcpCtxWithPeerCert(t), req)
			require.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// TestMCPInitCeremony_ShareClaimThumbprintNotFromWire proves a client cannot
// assert a thumbprint through the JSON-RPC params: the handler overwrites the
// field with the value derived from the session's peer certificate.
func TestMCPInitCeremony_ShareClaimThumbprintNotFromWire(t *testing.T) {
	s := newCeremonyMCPServer(t, string(initialize.StateEnrolling))

	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      json.RawMessage(`1`),
		Method:  "init.claimShareBegin",
		Params:  json.RawMessage(`{"username":"officer-A","CallerCertThumbprint":"forged"}`),
	}

	// Without a peer certificate the forged field must not rescue the call.
	_, err := s.handleClaimShareBegin(context.Background(), req)
	require.ErrorIs(t, err, ErrClientCertRequired)
}

// mcpCtxWithPeerCert returns a context carrying a throwaway self-signed leaf
// as the mTLS peer certificate, mirroring what the MCP server installs after a
// successful handshake.
func mcpCtxWithPeerCert(t *testing.T) context.Context {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "officer-A"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	leaf, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return auth.WithTLSState(context.Background(), &tls.ConnectionState{
		PeerCertificates: []*x509.Certificate{leaf},
	})
}

// TestMCPInitCeremony_PublicMethodsHaveNoOverlapWithPermissions guards a
// registration invariant: every publicly reachable ceremony method must still
// carry a permission mapping so it is enforced the moment the state condition
// stops holding.
func TestMCPInitCeremony_PublicMethodsHaveNoOverlapWithPermissions(t *testing.T) {
	for method := range publicCeremonyMethods {
		_, mapped := methodPermissions[method]
		assert.True(t, mapped,
			"%s is conditionally public but has no permission mapping to fall back on", method)
		assert.True(t, isDispatchable(method), "%s must be dispatchable", method)
	}
}

// TestMCPInitCeremony_OperationParity asserts the MCP transport dispatches the
// same ceremony operation set as REST (pkg/api/rest: initCeremonyOperations)
// and QUIC (pkg/api/quic: TestQUICInitCeremony_OperationParity).
func TestMCPInitCeremony_OperationParity(t *testing.T) {
	operations := map[string]string{
		"status":               "init.getStatus",
		"claim-cert begin":     "init.claimCertBegin",
		"claim-cert complete":  "init.claimCertComplete",
		"claim-share begin":    "init.claimShareBegin",
		"claim-share complete": "init.claimShareComplete",
		"sign-csr":             "init.signCSR",
	}

	for operation, method := range operations {
		t.Run(operation, func(t *testing.T) {
			_, ok := rpcMethodHandlers[method]
			assert.True(t, ok, "MCP must dispatch the %s ceremony operation (%s)", operation, method)
			_, mapped := methodPermissions[method]
			assert.True(t, mapped, "%s must carry a permission mapping", method)
		})
	}
}
