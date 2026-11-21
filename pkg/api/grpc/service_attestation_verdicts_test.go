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

package grpc

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/continuous"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// verdictSource returns a fixed quote request for every device.
type verdictSource struct{}

func (verdictSource) Collect(context.Context, string, string, []byte) (*appraisal.AppraiseQuoteRequest, error) {
	return &appraisal.AppraiseQuoteRequest{}, nil
}

// verdictAppraiser verifies every quote.
type verdictAppraiser struct{}

func (verdictAppraiser) AppraiseQuote(context.Context, string, *appraisal.AppraiseQuoteRequest) (*appraisal.AttestationResult, error) {
	return &appraisal.AttestationResult{Verified: true}, nil
}

// verdictClock advances one second on every call.
func verdictClock() func() time.Time {
	var mu sync.Mutex
	now := time.Date(2026, 11, 12, 8, 0, 0, 0, time.UTC)
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now = now.Add(time.Second)
		return now
	}
}

// newVerdictGRPC returns a Service over an XKMSService with continuous
// attestation wired, gated by authorizer, and a context for a caller of
// tenant acme.
func newVerdictGRPC(t *testing.T, authorizer *auth.Authorizer) (*Service, context.Context) {
	t.Helper()
	store, err := continuous.NewStore(continuous.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	engine, err := continuous.NewEngine(continuous.Config{Store: store, Source: verdictSource{}, Appraiser: verdictAppraiser{}, Now: verdictClock()})
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetContinuousAttestation(engine, store)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "operator", TenantID: "acme"})
	return NewService(authorizer, nil, svc), ctx
}

// TestVerdictRPCs_ReattestLatestList proves a re-attestation is the latest
// verdict and the one listed, in the caller's tenant.
func TestVerdictRPCs_ReattestLatestList(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newVerdictGRPC(t, authorizer)
	req := &pb.AttestationVerdictRequest{DeviceId: "dev-1"}

	v, err := s.ReattestDevice(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, "acme", v.GetTenant())
	assert.Equal(t, "dev-1", v.GetDeviceId())
	assert.True(t, v.GetVerified())
	assert.True(t, v.GetResult().GetVerified())
	assert.NotNil(t, v.GetAt())

	latest, err := s.GetLatestAttestationVerdict(ctx, req)
	require.NoError(t, err)
	assert.Equal(t, v.GetAt().AsTime(), latest.GetAt().AsTime())
	assert.Equal(t, "acme", latest.GetTenant())

	list, err := s.ListAttestationVerdicts(ctx, req)
	require.NoError(t, err)
	require.Len(t, list.GetVerdicts(), 1)
	assert.Equal(t, "dev-1", list.GetVerdicts()[0].GetDeviceId())
}

// TestVerdictRPCs_Errors proves the RPCs map the service's errors to their
// gRPC codes.
func TestVerdictRPCs_Errors(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newVerdictGRPC(t, authorizer)

	_, err := s.ReattestDevice(ctx, &pb.AttestationVerdictRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.GetLatestAttestationVerdict(ctx, &pb.AttestationVerdictRequest{DeviceId: "dev-1"})
	assert.Equal(t, codes.NotFound, status.Code(err))

	empty := NewService(authorizer, nil, nil)
	_, err = empty.ListAttestationVerdicts(ctx, &pb.AttestationVerdictRequest{DeviceId: "dev-1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	unconfigured := NewService(authorizer, nil, &xkms.XKMSService{})
	for name, call := range map[string]func() error{
		"list": func() error {
			_, err := unconfigured.ListAttestationVerdicts(ctx, &pb.AttestationVerdictRequest{DeviceId: "dev-1"})
			return err
		},
		"latest": func() error {
			_, err := unconfigured.GetLatestAttestationVerdict(ctx, &pb.AttestationVerdictRequest{DeviceId: "dev-1"})
			return err
		},
		"reattest": func() error {
			_, err := unconfigured.ReattestDevice(ctx, &pb.AttestationVerdictRequest{DeviceId: "dev-1"})
			return err
		},
	} {
		assert.Equal(t, codes.Unavailable, status.Code(call()), name)
	}
}

// TestVerdictRPCs_GateEachPermission proves each RPC is refused without its
// attestation_verdicts pair, naming the device it asked for.
func TestVerdictRPCs_GateEachPermission(t *testing.T) {
	authorizer, rbac := denyAuthorizer("denied")
	s, ctx := newVerdictGRPC(t, authorizer)
	req := &pb.AttestationVerdictRequest{DeviceId: "dev-1"}
	calls := map[string]struct {
		action string
		call   func() error
	}{
		"list": {auth.ActionList, func() error {
			_, err := s.ListAttestationVerdicts(ctx, req)
			return err
		}},
		"latest": {auth.ActionGet, func() error {
			_, err := s.GetLatestAttestationVerdict(ctx, req)
			return err
		}},
		"reattest": {auth.ActionCreate, func() error {
			_, err := s.ReattestDevice(ctx, req)
			return err
		}},
	}
	for name, c := range calls {
		audit := &mockAuditLogger{}
		s.auditLogger = audit
		err := c.call()
		assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
		_, resource, action, seen := rbac.Last()
		require.True(t, seen, name)
		assert.Equal(t, auth.ResourceAttestationVerdicts, resource, name)
		assert.Equal(t, c.action, action, name)
		event := audit.LastEvent()
		require.NotNil(t, event, name)
		assert.Equal(t, "dev-1", event.ResourceID, name)
	}
}
