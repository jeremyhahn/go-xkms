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
	"errors"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/tpmpolicytest"
	tpmpolicy "github.com/jeremyhahn/go-xkms/pkg/tpm2/policy"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// errTPMPolicyUnclassified stands in for an error no table classifies.
var errTPMPolicyUnclassified = errors.New("test: unclassified")

// newTPMPolicyGRPC returns a Service over an XKMSService whose TPM policy
// service has no TPM, and that policy service. The TPM-backed RPCs are
// exercised end to end over the simulator in pkg/server.
func newTPMPolicyGRPC(t *testing.T) (*Service, *tpmpolicy.Service) {
	t.Helper()
	policies, _ := tpmpolicytest.NewOffline(t)
	svc := &xkms.XKMSService{}
	svc.SetTPMPolicyService(policies)
	return NewService(nil, nil, svc), policies
}

// TestTPMPolicyRPCs_ServeTheCallersTenant proves the RPCs reach the policy
// service in the caller's tenant: a tenant lists its own (empty) scope and
// reads the policy its key was created under.
func TestTPMPolicyRPCs_ServeTheCallersTenant(t *testing.T) {
	s, policies := newTPMPolicyGRPC(t)
	require.NoError(t, policies.Assign(context.Background(), "acme", tpmpolicy.ObjectKey, "signer", "", []byte{0x01}))
	ctx := platformScopeCtx("acme")

	list, err := s.TPMPolicyList(ctx, &pb.TPMPolicyListRequest{})
	require.NoError(t, err)
	assert.Empty(t, list.GetPolicies())

	obj, err := s.TPMObjectPolicy(ctx, &pb.TPMObjectPolicyRequest{KeyId: "signer"})
	require.NoError(t, err)
	assert.Equal(t, "key/signer", obj.GetObjectId())
	assert.Equal(t, tpmpolicy.PlatformPolicy, obj.GetPolicy())
	assert.Equal(t, "01", obj.GetAuthPolicy())

	objects, err := s.TPMPolicyObjects(ctx, &pb.TPMPolicyRequest{Name: tpmpolicy.PlatformPolicy})
	require.NoError(t, err)
	assert.Equal(t, []string{"key/signer"}, objects.GetObjects())
}

// TestTPMPolicyRPCs_MapErrors proves the service's errors reach the wire
// with the codes apierrors.TPMPolicyClassOf assigns.
func TestTPMPolicyRPCs_MapErrors(t *testing.T) {
	s, policies := newTPMPolicyGRPC(t)
	require.NoError(t, policies.Assign(context.Background(), "initech", tpmpolicy.ObjectKey, "signer", "", nil))
	sys := platformScopeCtx(qrdbsdk.SystemTenantID)

	tests := []struct {
		name string
		call func() error
		code codes.Code
	}{
		{"unknown policy", func() error {
			_, err := s.TPMObjectPolicy(platformScopeCtx("acme"), &pb.TPMObjectPolicyRequest{KeyId: "missing"})
			return err
		}, codes.NotFound},
		{"invalid bank", func() error {
			_, err := s.TPMPolicyCreate(sys, &pb.TPMPolicyCreateRequest{Name: "boot", Branches: []*pb.TPMPolicyBranch{{Conditions: []*pb.TPMPolicyCondition{{Type: "pcr", Bank: "md5", Pcrs: []uint32{7}}}}}})
			return err
		}, codes.InvalidArgument},
		{"reserved name", func() error {
			_, err := s.TPMPolicyCreate(sys, &pb.TPMPolicyCreateRequest{Name: tpmpolicy.PlatformPolicy, Branches: []*pb.TPMPolicyBranch{{Conditions: []*pb.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", Pcrs: []uint32{7}}}}}})
			return err
		}, codes.InvalidArgument},
		{"invalid kind", func() error {
			_, err := s.TPMObjectPolicy(sys, &pb.TPMObjectPolicyRequest{KeyId: "signer", Kind: "blob"})
			return err
		}, codes.InvalidArgument},
		{"another tenant", func() error {
			_, err := s.TPMPolicyList(platformScopeCtx("acme"), &pb.TPMPolicyListRequest{TenantId: "globex"})
			return err
		}, codes.NotFound},
		{"tenant mode is system scope", func() error {
			_, err := s.GetTenantTPMMode(platformScopeCtx("acme"), &pb.TenantTPMModeRequest{TenantId: "acme"})
			return err
		}, codes.NotFound},
		{"vtpm unavailable", func() error {
			_, err := s.TenantVTPMStart(sys, &pb.TenantVTPMRequest{TenantId: "acme"})
			return err
		}, codes.FailedPrecondition},
		{"invalid mode", func() error {
			_, err := s.SetTenantTPMMode(sys, &pb.SetTenantTPMModeRequest{TenantId: "acme", Mode: "cloud"})
			return err
		}, codes.InvalidArgument},
		{"scope in use", func() error {
			_, err := s.SetTenantTPMMode(sys, &pb.SetTenantTPMModeRequest{TenantId: "initech", Mode: "none"})
			return err
		}, codes.FailedPrecondition},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.code, status.Code(tt.call()))
		})
	}
}

// TestTPMPolicyRPCs_TenantModeLifecycle proves the system caller reads and
// changes a tenant's mode, after which the tenant's policy RPCs refuse with
// FailedPrecondition.
func TestTPMPolicyRPCs_TenantModeLifecycle(t *testing.T) {
	s, _ := newTPMPolicyGRPC(t)
	sys := platformScopeCtx(qrdbsdk.SystemTenantID)

	mode, err := s.GetTenantTPMMode(sys, &pb.TenantTPMModeRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.Equal(t, "shared", mode.GetMode())

	set, err := s.SetTenantTPMMode(sys, &pb.SetTenantTPMModeRequest{TenantId: "acme", Mode: "none"})
	require.NoError(t, err)
	assert.Equal(t, "none", set.GetMode())

	_, err = s.TPMPolicyList(platformScopeCtx("acme"), &pb.TPMPolicyListRequest{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	st, err := s.TenantVTPMStatus(sys, &pb.TenantVTPMRequest{TenantId: "acme"})
	require.NoError(t, err)
	assert.False(t, st.GetRunning())
}

// TestTPMPolicyRPCs_WithoutAServiceAreUnavailable proves every RPC answers
// Unavailable on a server with no XKMSService.
func TestTPMPolicyRPCs_WithoutAServiceAreUnavailable(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()
	_, err := s.TPMPolicyGet(ctx, &pb.TPMPolicyRequest{Name: "boot"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
	_, err = s.TenantVTPMStop(ctx, &pb.TenantVTPMRequest{TenantId: "acme"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestMapTPMPolicyError_ListsTheObjectsInUse proves a refused delete carries
// the assigned objects in its message, and an unclassified error is
// Internal.
func TestMapTPMPolicyError_ListsTheObjectsInUse(t *testing.T) {
	err := mapTPMPolicyError(&tpmpolicy.PolicyInUseError{Policy: "boot", Objects: []string{"key/a", "key/b"}})
	st := status.Convert(err)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Contains(t, st.Message(), "key/a, key/b")

	assert.Equal(t, codes.Internal, status.Code(mapTPMPolicyError(errTPMPolicyUnclassified)))
}

// tpmPolicyRPCs returns the policy RPCs of s that act on one named policy or
// on the scope's authority, each naming the policy "boot" in tenant.
func tpmPolicyRPCs(s *Service, tenant string) map[string]func(context.Context) error {
	req := &pb.TPMPolicyRequest{TenantId: tenant, Name: "boot"}
	return map[string]func(context.Context) error{
		"TPMPolicyGet": func(ctx context.Context) error {
			_, err := s.TPMPolicyGet(ctx, req)
			return err
		},
		"TPMPolicyUpdate": func(ctx context.Context) error {
			_, err := s.TPMPolicyUpdate(ctx, &pb.TPMPolicyUpdateRequest{TenantId: tenant, Name: "boot"})
			return err
		},
		"TPMPolicyRevoke": func(ctx context.Context) error {
			_, err := s.TPMPolicyRevoke(ctx, req)
			return err
		},
		"TPMPolicyVerify": func(ctx context.Context) error {
			_, err := s.TPMPolicyVerify(ctx, req)
			return err
		},
		"TPMPolicyDelete": func(ctx context.Context) error {
			_, err := s.TPMPolicyDelete(ctx, &pb.TPMPolicyDeleteRequest{TenantId: tenant, Name: "boot"})
			return err
		},
		"TPMPolicySetAutoUnseal": func(ctx context.Context) error {
			_, err := s.TPMPolicySetAutoUnseal(ctx, &pb.TPMPolicyAutoUnsealRequest{TenantId: tenant, Name: "boot", Enabled: true})
			return err
		},
		"TPMPolicySetDescription": func(ctx context.Context) error {
			_, err := s.TPMPolicySetDescription(ctx, &pb.TPMPolicyDescriptionRequest{TenantId: tenant, Name: "boot", Description: "firmware"})
			return err
		},
		"TPMPolicyRotateAuthority": func(ctx context.Context) error {
			_, err := s.TPMPolicyRotateAuthority(ctx, &pb.TPMAuthorityRotateRequest{TenantId: tenant})
			return err
		},
	}
}

// TestTPMPolicyRPCs_ReachTheCallersScope proves every policy RPC acts in the
// caller's own scope: once the system caller sets a tenant's mode to none,
// each of the tenant's RPCs answers FailedPrecondition from that scope. The
// TPM-backed success paths run over the simulator in pkg/server.
func TestTPMPolicyRPCs_ReachTheCallersScope(t *testing.T) {
	s, _ := newTPMPolicyGRPC(t)
	_, err := s.SetTenantTPMMode(platformScopeCtx(qrdbsdk.SystemTenantID), &pb.SetTenantTPMModeRequest{TenantId: "acme", Mode: "none"})
	require.NoError(t, err)

	for name, call := range tpmPolicyRPCs(s, "") {
		t.Run(name, func(t *testing.T) {
			err := call(platformScopeCtx("acme"))
			assert.Equal(t, codes.FailedPrecondition, status.Code(err))
			assert.Contains(t, err.Error(), tpmpolicy.ErrTPMModeNone.Error())
		})
	}
}

// TestTPMPolicyRPCs_RefuseAnotherTenant proves no policy RPC lets a tenant
// caller reach another tenant's scope.
func TestTPMPolicyRPCs_RefuseAnotherTenant(t *testing.T) {
	s, _ := newTPMPolicyGRPC(t)

	for name, call := range tpmPolicyRPCs(s, "globex") {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, codes.NotFound, status.Code(call(platformScopeCtx("acme"))))
		})
	}
}
