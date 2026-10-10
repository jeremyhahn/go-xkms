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

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// This file covers remaining go-xkms #705 batch-A gaps too small to warrant
// their own file: the WithLocalTrust construction option, the
// PasswordStoreUnlock/Lock "no session on the system store" branch, and the
// FIDO2 RPCs' validation/unavailable branches (the WebAuthn ceremony success
// path is exercised by service_fido2_registration_policy_test.go and the
// transport-layer tests; standing up a full ceremony here would duplicate
// that without pinning any new behavior).

func TestWithLocalTrust(t *testing.T) {
	svc := NewService(nil, nil, nil, WithLocalTrust())
	assert.True(t, svc.localTrust)

	plain := NewService(nil, nil, nil)
	assert.False(t, plain.localTrust)
}

// --- PasswordStoreUnlock / PasswordStoreLock: system store has no session ---

func newSystemPasswordGRPCService(t *testing.T) *Service {
	t.Helper()
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetPasswordStore(newTestPasswordStore(t))
	return NewService(nil, nil, xkmsSvc)
}

func TestServicePasswordStoreUnlock_SystemStoreUnsupported(t *testing.T) {
	// The system-level store has no unlock session (only tenant stores do);
	// this pins that this is reported as Unimplemented, not silently ignored
	// or confused with a credential failure.
	svc := newSystemPasswordGRPCService(t)
	_, err := svc.PasswordStoreUnlock(context.Background(), &pb.PasswordStoreUnlockRequest{
		Credential: &pb.PasswordVaultCredential{Factor: "passphrase", Passphrase: "correct horse battery"},
	})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

func TestServicePasswordStoreLock_SystemStoreUnsupported(t *testing.T) {
	svc := newSystemPasswordGRPCService(t)
	_, err := svc.PasswordStoreLock(context.Background(), &pb.PasswordStoreLockRequest{})
	assert.Equal(t, codes.Unimplemented, status.Code(err))
}

// --- FIDO2: validation and unavailable branches ---

func TestServiceBeginAuthentication_MissingEmail(t *testing.T) {
	svc := newTestService()
	_, err := svc.BeginAuthentication(context.Background(), &pb.BeginAuthenticationRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceBeginAuthentication_Unavailable(t *testing.T) {
	svc := newTestService()
	_, err := svc.BeginAuthentication(context.Background(), &pb.BeginAuthenticationRequest{Email: "a@example.com"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceFinishAuthentication_MissingSessionID(t *testing.T) {
	svc := newTestService()
	_, err := svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceFinishAuthentication_Unavailable(t *testing.T) {
	svc := newTestService()
	_, err := svc.FinishAuthentication(context.Background(), &pb.FinishAuthenticationRequest{SessionId: "s1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceFinishRegistration_MissingSessionID(t *testing.T) {
	svc := newTestService()
	_, err := svc.FinishRegistration(context.Background(), &pb.FinishRegistrationRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestServiceFinishRegistration_Unavailable(t *testing.T) {
	svc := newTestService()
	_, err := svc.FinishRegistration(context.Background(), &pb.FinishRegistrationRequest{SessionId: "s1"})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestServiceBeginRegistration_Unavailable(t *testing.T) {
	svc := newTestService()
	_, err := svc.BeginRegistration(context.Background(), &pb.BeginRegistrationRequest{Email: "a@example.com"})
	require.Error(t, err)
	assert.Equal(t, codes.Unavailable, status.Code(err))
}
