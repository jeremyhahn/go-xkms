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

package unix

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-xkms/pkg/api/grpc/pbconv"
	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// OIDCCredentialGet echoes the requested credential as active, so a client
// test can see the request's reference arrive.
func (s *mockKeystoreServer) OIDCCredentialGet(_ context.Context, req *pb.OIDCCredentialRef) (*pb.OIDCCredential, error) {
	return &pb.OIDCCredential{Ref: req, Status: transport.OIDCCredentialStatusActive, Refreshable: true}, nil
}

// TestOIDCCredential_ReachesTheServer proves a connected transport serves
// the OIDC credential API over its connection: the request's reference
// reaches the server and its credential is decoded, and an RPC the server
// does not serve reaches the caller as its status. The conversions
// themselves are tested once, in pkg/api/grpc/pbconv.
func TestOIDCCredential_ReachesTheServer(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	ref := transport.OIDCCredentialRef{TenantID: "acme", Scope: transport.OIDCCredentialScopeUser, Owner: "alice", Name: "codex"}

	c, err := tr.OIDCCredentialGet(context.Background(), &ref)
	require.NoError(t, err)
	assert.Equal(t, ref, c.OIDCCredentialRef)
	assert.Equal(t, transport.OIDCCredentialStatusActive, c.Status)
	assert.True(t, c.Refreshable)

	_, err = tr.OIDCCredentialGetAccessToken(context.Background(), &ref)
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// TestOIDCCredential_RefusesNilRequests proves a connected transport
// refuses a nil request without calling the server.
func TestOIDCCredential_RefusesNilRequests(t *testing.T) {
	tr, cleanup := newBufconnTransport(t)
	defer cleanup()
	_, err := tr.OIDCCredentialGet(context.Background(), nil)
	assert.ErrorIs(t, err, pbconv.ErrNilRequest)
}

// TestOIDCCredential_NotConnected proves every OIDC credential method
// refuses before the transport is connected.
func TestOIDCCredential_NotConnected(t *testing.T) {
	tr := newDisconnected(t)
	ctx := context.Background()
	ref := &transport.OIDCCredentialRef{Scope: transport.OIDCCredentialScopeTenant, Name: "ci"}
	calls := map[string]func() error{
		"OIDCCredentialCreate": func() error {
			_, err := tr.OIDCCredentialCreate(ctx, &transport.OIDCCredentialCreateRequest{OIDCCredentialRef: *ref})
			return err
		},
		"OIDCCredentialImport": func() error {
			_, err := tr.OIDCCredentialImport(ctx, &transport.OIDCCredentialImportRequest{OIDCCredentialRef: *ref})
			return err
		},
		"OIDCCredentialGet": func() error { _, err := tr.OIDCCredentialGet(ctx, ref); return err },
		"OIDCCredentialList": func() error {
			_, err := tr.OIDCCredentialList(ctx, &transport.OIDCCredentialListRequest{})
			return err
		},
		"OIDCCredentialDelete":  func() error { return tr.OIDCCredentialDelete(ctx, ref) },
		"OIDCCredentialRefresh": func() error { _, err := tr.OIDCCredentialRefresh(ctx, ref); return err },
		"OIDCCredentialGetAccessToken": func() error {
			_, err := tr.OIDCCredentialGetAccessToken(ctx, ref)
			return err
		},
		"OIDCCredentialDeviceStart": func() error { _, err := tr.OIDCCredentialDeviceStart(ctx, ref); return err },
		"OIDCCredentialDevicePoll":  func() error { _, err := tr.OIDCCredentialDevicePoll(ctx, ref); return err },
	}
	for name, call := range calls {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, call(), ErrNotConnected)
		})
	}
}
