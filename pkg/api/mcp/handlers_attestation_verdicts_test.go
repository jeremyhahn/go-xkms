// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	sdkssh "github.com/jeremyhahn/go-xkms/sdk/go/client/ssh"
)

type verdictSource struct{}

func (verdictSource) Collect(context.Context, string, string, []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return &appraisal.AppraiseQuoteRequest{}, nil
}

type verdictAppraiser struct{}

func (verdictAppraiser) AppraiseQuote(context.Context, string, *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return &appraisal.AttestationResult{Verified: true}, nil
}

// newVerdictMCP returns a Server whose XKMSService has continuous
// attestation wired, on a clock that advances one second per call.
func newVerdictMCP(t *testing.T) *Server {
	t.Helper()
	server := createTestServer(t)
	store, err := continuous.NewStore(continuous.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	var mu sync.Mutex
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	clock := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Second)
		return now
	}
	engine, err := continuous.NewEngine(continuous.Config{Store: store, Source: verdictSource{}, Appraiser: verdictAppraiser{}, Now: clock})
	require.NoError(t, err)
	server.xkmsService.SetContinuousAttestation(engine, store)
	return server
}

// TestVerdictTools_ReattestLatestList proves the tools act in the caller's
// tenant: a re-attestation is the latest verdict and the one listed.
func TestVerdictTools_ReattestLatestList(t *testing.T) {
	s := newVerdictMCP(t)
	req := transport.AttestationVerdictRequest{DeviceID: "dev-1"}

	var fresh transport.AttestationVerdict
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.verdict.reattest", req, &fresh))
	assert.Equal(t, "acme", fresh.Tenant)
	assert.Equal(t, "dev-1", fresh.DeviceID)
	assert.True(t, fresh.Verified)

	var latest transport.AttestationVerdict
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.verdict.latest", req, &latest))
	assert.True(t, fresh.At.Equal(latest.At))

	var list transport.ListAttestationVerdictsResponse
	require.NoError(t, invokeOIDC(t, s, "acme", "alice", "attestation.verdict.list", req, &list))
	require.Len(t, list.Verdicts, 1)
	assert.Equal(t, "acme", list.Verdicts[0].Tenant)
}

// TestVerdictTools_MapErrors proves the verdict errors reach the wire with
// the codes apierrors.VerdictClassOf assigns.
func TestVerdictTools_MapErrors(t *testing.T) {
	s := newVerdictMCP(t)
	tests := []struct {
		name, method string
		params       any
		code         int
	}{
		{"malformed params", "attestation.verdict.list", "not an object", ErrCodeInvalidParams},
		{"empty device", "attestation.verdict.reattest", transport.AttestationVerdictRequest{}, ErrCodeInvalidParams},
		{"no verdict yet", "attestation.verdict.latest", transport.AttestationVerdictRequest{DeviceID: "dev-1"}, sdkssh.JSONRPCCodeNotFound},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var out map[string]any
			err := invokeOIDC(t, s, "acme", "alice", tt.method, tt.params, &out)
			var keyErr *KeyOpError
			require.ErrorAs(t, err, &keyErr)
			assert.Equal(t, tt.code, keyErr.Code)
		})
	}
}

// TestVerdictTools_WithoutTheSubsystem proves every tool fails on a server
// with no continuous attestation wired.
func TestVerdictTools_WithoutTheSubsystem(t *testing.T) {
	s := createTestServer(t)
	for _, method := range []string{"attestation.verdict.list", "attestation.verdict.latest", "attestation.verdict.reattest"} {
		var out map[string]any
		err := invokeOIDC(t, s, "acme", "alice", method, transport.AttestationVerdictRequest{DeviceID: "dev-1"}, &out)
		var keyErr *KeyOpError
		require.ErrorAs(t, err, &keyErr, method)
		assert.Equal(t, ErrCodeServiceUnavailable, keyErr.Code, method)
	}
}
