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
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
)

// TestSignImageRPC_Errors proves SignImage's refusals reach the caller as
// classified status codes, and that the registry password the request
// carried is wiped even when the service refuses it.
func TestSignImageRPC_Errors(t *testing.T) {
	authorizer, _ := allowAuthorizer()
	s, ctx := newSigningKeyGRPC(t, authorizer)

	req := &pb.SignImageRequest{
		Reference: "not a reference",
		Registry:  &pb.ImageRegistryCredentials{Username: "ci", Password: []byte("registry-password")},
	}
	_, err := s.SignImage(ctx, req)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	assert.Equal(t, make([]byte, len("registry-password")), req.GetRegistry().GetPassword(), "the password is wiped")

	_, err = s.SignImage(ctx, &pb.SignImageRequest{Reference: "registry.example.com/acme/app:v1"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "a service without a CA cannot sign images")

	system := auth.WithIdentity(t.Context(), &auth.Identity{Subject: "operator", TenantID: qrdbsdk.SystemTenantID})
	_, err = s.SignImage(system, &pb.SignImageRequest{Reference: "registry.example.com/acme/app:v1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))

	empty := NewService(authorizer, nil, nil)
	_, err = empty.SignImage(ctx, &pb.SignImageRequest{Reference: "registry.example.com/acme/app:v1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
