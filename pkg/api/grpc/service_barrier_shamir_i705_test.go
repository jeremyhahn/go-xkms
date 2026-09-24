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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers two service_barrier_shamir.go RPCs (go-xkms #705, batch
// A) that shipped without a test: BarrierHasRecoveryKeys and
// BarrierEnableEncryption.

func TestServiceBarrierHasRecoveryKeys_NotConfigured(t *testing.T) {
	old := GetBarrier()
	SetBarrier(nil)
	defer SetBarrier(old)

	svc := newTestService()
	_, err := svc.BarrierHasRecoveryKeys(context.Background(), &emptypb.Empty{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
}

func TestServiceBarrierHasRecoveryKeys_ReportsNoneBeforeGeneration(t *testing.T) {
	b := setupBarrier(t)
	ctx := context.Background()
	creds := seal.MustCredentials([]byte("test-password"))
	defer creds.Secret.Destroy()
	require.NoError(t, b.Initialize(ctx, creds))
	svc := newTestService()

	resp, err := svc.BarrierHasRecoveryKeys(ctx, &emptypb.Empty{})
	require.NoError(t, err)
	assert.False(t, resp.HasKeys, "a freshly initialized barrier has no recovery keys yet")
}

func TestServiceBarrierEnableEncryption_Unavailable(t *testing.T) {
	svc := NewService(nil, nil, nil)
	_, err := svc.BarrierEnableEncryption(context.Background(), &pb.BarrierEnableEncryptionRequest{Strategy: "passphrase"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceBarrierEnableEncryption_MigratorNotConfigured(t *testing.T) {
	// The XKMSService is wired but has no EncryptionMigrator composed: the
	// handler must surface this as a typed error, not attempt the migration.
	svc := NewService(nil, nil, &xkms.XKMSService{})
	_, err := svc.BarrierEnableEncryption(context.Background(), &pb.BarrierEnableEncryptionRequest{
		Strategy: "passphrase", Passphrase: "hunter2",
	})
	require.Error(t, err)
	assert.NotEqual(t, codes.OK, status.Code(err))
}
