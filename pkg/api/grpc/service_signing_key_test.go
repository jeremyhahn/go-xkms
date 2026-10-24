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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/appraisal"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newSigningKeyGRPC returns a Service over an XKMSService with a Verifier
// wired, gated by authorizer, and a context for a caller of tenant acme.
func newSigningKeyGRPC(t *testing.T, authorizer *auth.Authorizer) (*Service, context.Context) {
	t.Helper()
	store, err := appraisal.NewStore(appraisal.StoreConfig{DAOs: testutil.NewMemoryDAOFactory()})
	require.NoError(t, err)
	appraiser, err := appraisal.NewAppraiser(store)
	require.NoError(t, err)
	svc := &xkms.XKMSService{}
	svc.SetAttestationAppraiser(appraiser)
	ctx := auth.WithIdentity(context.Background(), &auth.Identity{Subject: "release-manager", TenantID: "acme"})
	return NewService(authorizer, nil, svc), ctx
}

// TestSigningKeyRPCs_BindResolveRemove proves the five RPCs round-trip a
// binding: a repository resolves to the release key until it is bound, to
// its bound key while bound, and back to the release key once removed.
func TestSigningKeyRPCs_BindResolveRemove(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	resolved, err := s.ResolveSigningKey(ctx, &pb.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, appraisal.ReleaseSigningKeyID, resolved.GetKeyId())
	assert.True(t, resolved.GetDefault())

	bound, err := s.SetSigningKeyBinding(ctx, &pb.SetSigningKeyBindingRequest{Repository: "acme/app", KeyId: "app-release", Backend: "software"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", bound.GetKeyId())
	assert.NotNil(t, bound.GetUpdatedAt())

	got, err := s.GetSigningKeyBinding(ctx, &pb.GetSigningKeyBindingRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "software", got.GetBackend())

	list, err := s.ListSigningKeyBindings(ctx, &pb.ListSigningKeyBindingsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetBindings(), 1)
	assert.Equal(t, "acme/app", list.GetBindings()[0].GetRepository())

	resolved, err = s.ResolveSigningKey(ctx, &pb.ResolveSigningKeyRequest{Repository: "acme/app"})
	require.NoError(t, err)
	assert.Equal(t, "app-release", resolved.GetKeyId())
	assert.False(t, resolved.GetDefault())

	_, err = s.DeleteSigningKeyBinding(ctx, &pb.DeleteSigningKeyBindingRequest{Repository: "acme/app"})
	require.NoError(t, err)
	_, err = s.GetSigningKeyBinding(ctx, &pb.GetSigningKeyBindingRequest{Repository: "acme/app"})
	assert.Equal(t, codes.NotFound, status.Code(err))
}

// TestSigningKeyRPCs_Errors proves the RPCs map the service's errors to
// their gRPC codes: a malformed repository or key is InvalidArgument, and a
// server with no service is Unavailable.
func TestSigningKeyRPCs_Errors(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	_, err := s.ResolveSigningKey(ctx, &pb.ResolveSigningKeyRequest{Repository: "Acme/App"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.SetSigningKeyBinding(ctx, &pb.SetSigningKeyBindingRequest{Repository: "acme/app", KeyId: "a/b"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	empty := NewService(authorizer, nil, nil)
	_, err = empty.ListSigningKeyBindings(ctx, &pb.ListSigningKeyBindingsRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	unconfigured := NewService(authorizer, nil, &xkms.XKMSService{})
	_, err = unconfigured.GetSigningKeyBinding(ctx, &pb.GetSigningKeyBindingRequest{Repository: "acme/app"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

// TestSigningKeyRPCs_GateEachPermission proves every RPC refuses a caller
// the gate denies, on the attestation_signing_keys:* pair it declares, and
// changes nothing.
func TestSigningKeyRPCs_GateEachPermission(t *testing.T) {
	authorizer, rbac := denyAuthorizer("denied")
	s, ctx := newSigningKeyGRPC(t, authorizer)
	calls := map[string]struct {
		action string
		call   func() error
	}{
		"set": {auth.ActionBind, func() error {
			_, err := s.SetSigningKeyBinding(ctx, &pb.SetSigningKeyBindingRequest{Repository: "acme/app", KeyId: "k"})
			return err
		}},
		"get": {auth.ActionGet, func() error {
			_, err := s.GetSigningKeyBinding(ctx, &pb.GetSigningKeyBindingRequest{Repository: "acme/app"})
			return err
		}},
		"list": {auth.ActionList, func() error {
			_, err := s.ListSigningKeyBindings(ctx, &pb.ListSigningKeyBindingsRequest{})
			return err
		}},
		"delete": {auth.ActionBind, func() error {
			_, err := s.DeleteSigningKeyBinding(ctx, &pb.DeleteSigningKeyBindingRequest{Repository: "acme/app"})
			return err
		}},
		"resolve": {auth.ActionGet, func() error {
			_, err := s.ResolveSigningKey(ctx, &pb.ResolveSigningKeyRequest{Repository: "acme/app"})
			return err
		}},
	}
	for name, c := range calls {
		err := c.call()
		assert.Equal(t, codes.PermissionDenied, status.Code(err), name)
		_, resource, action, seen := rbac.Last()
		require.True(t, seen, name)
		assert.Equal(t, auth.ResourceAttestationSigningKeys, resource, name)
		assert.Equal(t, c.action, action, name)
	}
}

// TestMapSigningKeyError_Unclassified proves an error outside the
// signing-key model is an internal fault.
func TestMapSigningKeyError_Unclassified(t *testing.T) {
	assert.Equal(t, codes.Internal, status.Code(mapSigningKeyError(errOIDCUnclassified)))
	assert.Equal(t, codes.PermissionDenied, status.Code(mapSigningKeyError(xkms.ErrSigningKeyForbidden)))
}
