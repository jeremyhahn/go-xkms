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
	"google.golang.org/protobuf/types/known/emptypb"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newBootstrapTestService builds a real *xkms.XKMSService, since
// BootstrapListenerKeys reads s.xkmsService directly rather than the
// package-level xkms singleton the other grpc tests exercise.
func newBootstrapTestService(t *testing.T) *xkms.XKMSService {
	t.Helper()
	t.Cleanup(xkms.Reset)

	backend, err := software.NewBackend(&software.Config{KeyStorage: storage.New()})
	require.NoError(t, err)

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: storage.New(),
	})
	require.NoError(t, err)

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"software": ks},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)
	return xkmsSvc
}

// TestBootstrapListenerKeys_Success proves a published key set is reported
// over the wire with its hex encoding intact.
func TestBootstrapListenerKeys_Success(t *testing.T) {
	xkmsSvc := newBootstrapTestService(t)
	xkmsSvc.SetBootstrapListenerKeys(&transport.BootstrapListenerKeysResponse{
		NoisePublicKey: "aa",
		P256PublicKey:  "cc",
	})

	svc := NewService(auth.NewAuthorizer(nil), nil, xkmsSvc)

	resp, err := svc.BootstrapListenerKeys(context.Background(), &emptypb.Empty{})
	require.NoError(t, err)
	assert.Equal(t, "aa", resp.NoisePublicKey)
	assert.Equal(t, "cc", resp.P256PublicKey)
}

// TestBootstrapListenerKeys_NotEnabled proves an xkmsService that never had
// keys published (the listener is not configured, or has not finished
// starting) reports Unavailable rather than a response with empty fields.
func TestBootstrapListenerKeys_NotEnabled(t *testing.T) {
	xkmsSvc := newBootstrapTestService(t)
	svc := NewService(auth.NewAuthorizer(nil), nil, xkmsSvc)

	resp, err := svc.BootstrapListenerKeys(context.Background(), &emptypb.Empty{})
	require.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
}

// TestBootstrapListenerKeys_Unauthorized proves an identity the authorizer
// denies never reaches the servicer, regardless of whether keys are published.
func TestBootstrapListenerKeys_Unauthorized(t *testing.T) {
	svc := newDeniedService()
	ctx := deniedCtx()

	resp, err := svc.BootstrapListenerKeys(ctx, &emptypb.Empty{})
	require.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.PermissionDenied, st.Code())
}
