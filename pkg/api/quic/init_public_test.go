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

package quic

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	initialize "github.com/jeremyhahn/go-xkms/pkg/init"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/metadata"
)

// errQUICNoCredential stands in for what a real mTLS authenticator returns to
// an officer who has not yet claimed their first certificate.
var errQUICNoCredential = errors.New("no credential presented")

// quicDenyAllAuthenticator rejects every request, which is the situation an
// officer running the enrollment ceremony is actually in.
type quicDenyAllAuthenticator struct{}

var _ auth.Authenticator = (*quicDenyAllAuthenticator)(nil)

func (quicDenyAllAuthenticator) AuthenticateHTTP(*http.Request) (*auth.Identity, error) {
	return nil, errQUICNoCredential
}

func (quicDenyAllAuthenticator) AuthenticateGRPC(context.Context, metadata.MD) (*auth.Identity, error) {
	return nil, errQUICNoCredential
}

func (quicDenyAllAuthenticator) Name() string { return "deny-all" }

// stateOnlyCeremony reports a fixed ceremony state and answers each claim
// operation with a marker payload. The ceremony protocol itself is covered
// end-to-end against the real service in pkg/api/rest; what this double
// isolates is the transport's state-gated authentication exemption.
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
	// The transport must have derived the thumbprint from the peer chain
	// before reaching the service. A blank value here means the handler
	// forwarded an unauthenticated request.
	if req.CallerCertThumbprint == "" {
		return nil, errQUICNoCallerThumbprint
	}
	return &transport.ClaimShareBeginResponse{Nonce: "abcd", Username: "officer-A"}, nil
}

func (c *stateOnlyCeremony) ClaimShareComplete(_ context.Context, req *transport.ClaimShareCompleteRequest) (*transport.ClaimShareCompleteResponse, error) {
	if req.CallerCertThumbprint == "" {
		return nil, errQUICNoCallerThumbprint
	}
	return &transport.ClaimShareCompleteResponse{ShareIndex: 1, Share: json.RawMessage(`{"index":1}`)}, nil
}

func (c *stateOnlyCeremony) SignCSRInit(context.Context, *transport.SignCSRInitRequest) (*transport.SignCSRInitResponse, error) {
	return &transport.SignCSRInitResponse{CertPEM: "cert"}, nil
}

// errQUICNoCallerThumbprint is returned by the stub when a share-claim request
// reaches the service without a caller certificate thumbprint. Its presence in
// a response proves the handler skipped the peer-certificate check.
var errQUICNoCallerThumbprint = errors.New("caller certificate thumbprint missing")

// newCeremonyQUICServer builds a QUIC server whose authenticator rejects every
// caller and whose ceremony reports the given state.
func newCeremonyQUICServer(t *testing.T, state string) *Server {
	t.Helper()
	xkms.Reset()

	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "software",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)
	svc.SetCeremonyService(&stateOnlyCeremony{state: state})

	server, err := NewServer(&Config{
		Addr:          "localhost:0",
		Authenticator: quicDenyAllAuthenticator{},
		Logger:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		XKMSService:   svc,
	})
	require.NoError(t, err)
	t.Cleanup(func() { xkms.Reset() })
	return server
}

// doQUIC drives the full server handler chain (correlation, auth, logging,
// mux) so the authentication middleware is genuinely exercised.
func doQUIC(t *testing.T, s *Server, method, path string, body any) int {
	t.Helper()
	code, _ := doQUICWithCert(t, s, method, path, body, nil)
	return code
}

// doQUICWithCert drives the full handler chain with an optional mTLS peer
// certificate on the request, returning the status code and body.
func doQUICWithCert(t *testing.T, s *Server, method, path string, body any, leaf *x509.Certificate) (int, string) {
	t.Helper()
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		require.NoError(t, err)
		reader = bytes.NewReader(encoded)
	}
	req := httptest.NewRequest(method, path, reader)
	if leaf != nil {
		req.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
	}
	rec := httptest.NewRecorder()
	s.handler.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String()
}

// quicTestLeaf returns a throwaway self-signed leaf to stand in for an
// officer's mTLS client certificate.
func quicTestLeaf(t *testing.T) *x509.Certificate {
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
	return leaf
}

// TestQUICInitCeremony_ClaimEndpointsOpenWhileEnrolling verifies the QUIC
// transport lets a credential-less officer reach the same claim surface the
// REST transport exempts. Without this the ceremony deadlocks on QUIC exactly
// as it did on REST.
func TestQUICInitCeremony_ClaimEndpointsOpenWhileEnrolling(t *testing.T) {
	s := newCeremonyQUICServer(t, string(initialize.StateEnrolling))

	tests := []struct {
		name   string
		method string
		path   string
		body   any
	}{
		{"status", http.MethodGet, "/api/v1/init/status", nil},
		{"claim-cert begin", http.MethodPost, "/api/v1/init/claim-cert/begin", transport.ClaimCertBeginRequest{Username: "officer-A"}},
		{"claim-cert complete", http.MethodPost, "/api/v1/init/claim-cert/complete", transport.ClaimCertCompleteRequest{Username: "officer-A", Nonce: "abcd", Signature: "AA=="}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, http.StatusOK, doQUIC(t, s, tc.method, tc.path, tc.body),
				"%s must be reachable without a credential while enrolling", tc.path)
		})
	}

	// The two claim-share routes are reachable without an *account* but still
	// require a client certificate: they are the routes that release quorum
	// material.
	leaf := quicTestLeaf(t)
	for _, tc := range []struct {
		name string
		path string
		body any
	}{
		{"claim-share begin", "/api/v1/init/claim-share/begin", transport.ClaimShareBeginRequest{Username: "officer-A"}},
		{"claim-share complete", "/api/v1/init/claim-share/complete", transport.ClaimShareCompleteRequest{Username: "officer-A", Nonce: "abcd", Signature: "AA=="}},
	} {
		t.Run(tc.name+" with client cert", func(t *testing.T) {
			code, body := doQUICWithCert(t, s, http.MethodPost, tc.path, tc.body, leaf)
			assert.Equal(t, http.StatusOK, code, "%s must be reachable with a client certificate: %s", tc.path, body)
		})

		t.Run(tc.name+" without client cert", func(t *testing.T) {
			code, body := doQUICWithCert(t, s, http.MethodPost, tc.path, tc.body, nil)
			assert.Equal(t, http.StatusUnauthorized, code,
				"%s must refuse a caller with no client certificate", tc.path)
			assert.NotContains(t, body, `"share"`, "share material leaked on refusal: %s", body)
		})
	}
}

// TestQUICInitCeremony_ClaimEndpointsClosedWhenOperational verifies the
// exemption is gated on ceremony state, not on path alone.
func TestQUICInitCeremony_ClaimEndpointsClosedWhenOperational(t *testing.T) {
	s := newCeremonyQUICServer(t, string(initialize.StateOperational))

	for _, path := range []string{
		"/api/v1/init/status",
		"/api/v1/init/claim-cert/begin",
		"/api/v1/init/claim-cert/complete",
		"/api/v1/init/claim-share/begin",
		"/api/v1/init/claim-share/complete",
	} {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, doQUIC(t, s, http.MethodPost, path, map[string]string{}),
				"%s must require authentication once the ceremony is operational", path)
		})
	}
}

// TestQUICInitCeremony_ExemptionIsNotAPrefixMatch verifies sign-csr and
// unrelated routes do not inherit the ceremony exemption.
func TestQUICInitCeremony_ExemptionIsNotAPrefixMatch(t *testing.T) {
	s := newCeremonyQUICServer(t, string(initialize.StateEnrolling))

	for _, path := range []string{
		"/api/v1/init/sign-csr",
		"/api/v1/initialize",
		"/api/v1/init/claim-share",
		"/api/v1/init/claim-share/begin/extra",
		"/api/v1/backends",
		"/api/v1/credentials/submit",
	} {
		t.Run(path, func(t *testing.T) {
			assert.Equal(t, http.StatusUnauthorized, doQUIC(t, s, http.MethodPost, path, map[string]string{}),
				"%s must not inherit the init exemption", path)
		})
	}
}

// TestQUICIsPublicCeremonyRequest_FailsClosed covers the predicate's
// fail-closed paths directly.
func TestQUICIsPublicCeremonyRequest_FailsClosed(t *testing.T) {
	enrolling := newCeremonyQUICServer(t, string(initialize.StateEnrolling))

	t.Run("unknown ceremony state", func(t *testing.T) {
		unknown := newCeremonyQUICServer(t, "some-future-state")
		req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
		assert.False(t, unknown.isPublicCeremonyRequest(req))
	})

	t.Run("no ceremony wired", func(t *testing.T) {
		bare := &Server{}
		req := httptest.NewRequest(http.MethodGet, "/api/v1/init/status", nil)
		assert.False(t, bare.isPublicCeremonyRequest(req))
	})

	t.Run("percent encoded path", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim%2Dshare/begin", nil)
		assert.False(t, enrolling.isPublicCeremonyRequest(req))
	})

	t.Run("bare claim-share is not allowlisted", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share", nil)
		assert.False(t, enrolling.isPublicCeremonyRequest(req))
	})

	t.Run("allowlisted path while enrolling", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/init/claim-share/begin", nil)
		assert.True(t, enrolling.isPublicCeremonyRequest(req))
	})
}

// TestQUICInitCeremony_OperationParity asserts the QUIC transport mounts the
// same ceremony operation set as REST (pkg/api/rest: initCeremonyOperations)
// and MCP (pkg/api/mcp: TestMCPInitCeremony_OperationParity).
func TestQUICInitCeremony_OperationParity(t *testing.T) {
	s := newCeremonyQUICServer(t, string(initialize.StateEnrolling))

	operations := []struct {
		operation string
		method    string
		path      string
	}{
		{"status", http.MethodGet, "/api/v1/init/status"},
		{"claim-cert begin", http.MethodPost, "/api/v1/init/claim-cert/begin"},
		{"claim-cert complete", http.MethodPost, "/api/v1/init/claim-cert/complete"},
		{"claim-share begin", http.MethodPost, "/api/v1/init/claim-share/begin"},
		{"claim-share complete", http.MethodPost, "/api/v1/init/claim-share/complete"},
		{"sign-csr", http.MethodPost, "/api/v1/init/sign-csr"},
	}

	for _, op := range operations {
		t.Run(op.operation, func(t *testing.T) {
			assert.NotEqual(t, http.StatusNotFound, doQUIC(t, s, op.method, op.path, map[string]string{}),
				"QUIC must expose the %s ceremony operation", op.operation)
		})
	}
}
