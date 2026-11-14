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

package grpc

import (
	"context"
	"testing"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// setupTestWithPasswordStore initializes xkms with a software backend and a
// static password store, returning a gRPC service ready for password tests.
func setupTestWithPasswordStore(t *testing.T) *Service {
	t.Helper()
	xkms.Reset()

	keyStorage := storage.New()
	certStorage := storage.New()

	backend, err := software.NewBackend(&software.Config{
		KeyStorage: keyStorage,
	})
	require.NoError(t, err)

	ks, err := xkms.New(&xkms.BackendConfig{
		Backend:     backend,
		CertStorage: certStorage,
	})
	require.NoError(t, err)

	err = xkms.Initialize(&xkms.ServiceConfig{
		Backends: map[string]xkms.Backend{
			"software": ks,
		},
		DefaultBackend: "software",
	})
	require.NoError(t, err)

	xkmsSvc, err := xkms.Get()
	require.NoError(t, err)

	xkmsSvc.SetPasswordStore(newTestPasswordStore(t))

	return NewService(nil, nil, xkmsSvc)
}

// ---- AttestKey with initialized backend ----

// ---- Seal/Unseal with initialized backend ----

// ---- WrapKeyByID / UnwrapKeyByID with non-existent backend ----

// ---- Password CRUD with initialized store ----

// ---- PIV operations with non-PIV backend ----

// ---- mapPIVError tests ----

// ---- DeriveKeyECDH with non-existent backend ----

// ---- Proto conversion helpers ----

// ---- Password operations with xkms not initialized ----

func TestPasswordOps_XKMSNotInitialized(t *testing.T) {
	xkms.Reset()
	svc := NewService(nil, nil, nil)
	ctx := context.Background()

	_, err := svc.PasswordAdd(ctx, &pb.PasswordAddRequest{Name: "t", Password: "p"})
	st, _ := status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordGet(ctx, &pb.PasswordGetRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordUpdate(ctx, &pb.PasswordUpdateRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordDelete(ctx, &pb.PasswordDeleteRequest{Id: "t"})
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())

	_, err = svc.PasswordStoreLock(ctx, nil)
	st, _ = status.FromError(err)
	assert.Equal(t, codes.Unavailable, st.Code())
}
