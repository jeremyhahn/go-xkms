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
	"fmt"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	pb "github.com/jeremyhahn/go-xkms/pkg/api/grpc/proto/xkmsv1"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/invitetest"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/webauthntest"
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// newInviteGRPCService returns a Service whose XKMSService resolves
// invitations from an in-memory invite store, and a token inviting the
// pending account "invitee@example.com".
func newInviteGRPCService(t *testing.T) (*Service, string) {
	t.Helper()
	ctx := context.Background()
	users := newGRPCFakeUserClient()
	invitee, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "invitee@example.com", Email: "invitee@example.com", Name: "Invitee",
		TenantID: qrdbsdk.SystemTenantID, Pending: true,
	})
	require.NoError(t, err)

	invites, err := invitetest.New(grpcSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	token, _, err := invites.Create(ctx, fmt.Sprint(invitee.ID), "", time.Hour)
	require.NoError(t, err)

	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetUserClients(users, &grpcFakeRoleClient{})
	xkmsSvc.SetInviteStore(invites)
	xkmsSvc.SetInviteUserClient(grpcInviteUsers{users})
	return NewService(nil, nil, xkmsSvc), token
}

// TestGetInvite_DescribesTheInvitation proves GetInvite answers with the
// invited account and the enrollment methods it may use.
func TestGetInvite_DescribesTheInvitation(t *testing.T) {
	s, token := newInviteGRPCService(t)

	resp, err := s.GetInvite(context.Background(), &pb.GetInviteRequest{TenantId: qrdbsdk.SystemTenantID, Token: token})
	require.NoError(t, err)
	assert.Equal(t, "invitee@example.com", resp.GetEmail())
	assert.Equal(t, "Invitee", resp.GetDisplayName())
	assert.Equal(t, []string{"webauthn", "piv"}, resp.GetMethods())
	assert.True(t, resp.GetExpiresAt().AsTime().After(time.Now()))
}

// TestGetInvite_UnknownTokenIsNotFound proves an unusable token gets the one
// opaque NotFound answer.
func TestGetInvite_UnknownTokenIsNotFound(t *testing.T) {
	s, _ := newInviteGRPCService(t)

	_, err := s.GetInvite(context.Background(), &pb.GetInviteRequest{TenantId: qrdbsdk.SystemTenantID, Token: "never-issued"})
	st := status.Convert(err)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Equal(t, xkms.ErrInviteUnusable.Error(), st.Message())
}

// inviteRPCs returns every invite redemption RPC of s, each with a complete
// request for token.
func inviteRPCs(s *Service, token string) map[string]func() error {
	ctx := context.Background()
	return map[string]func() error{
		"GetInvite": func() error {
			_, err := s.GetInvite(ctx, &pb.GetInviteRequest{Token: token})
			return err
		},
		"BeginInviteRegistration": func() error {
			_, err := s.BeginInviteRegistration(ctx, &pb.BeginInviteRegistrationRequest{Token: token})
			return err
		},
		"FinishInviteRegistration": func() error {
			_, err := s.FinishInviteRegistration(ctx, &pb.FinishInviteRegistrationRequest{Token: token, SessionId: "s1", AttestationJson: "{}"})
			return err
		},
		"ActivateInvitePIV": func() error {
			_, err := s.ActivateInvitePIV(ctx, &pb.ActivateInvitePIVRequest{Token: token, CertPem: "PEM"})
			return err
		},
	}
}

// TestInviteRPCs_Unconfigured proves the invite RPCs answer Unavailable on a
// server with no XKMSService, or one with no invite store.
func TestInviteRPCs_Unconfigured(t *testing.T) {
	servers := map[string]*Service{
		"no service":      NewService(nil, nil, nil),
		"no invite store": NewService(nil, nil, &xkms.XKMSService{}),
	}
	for server, s := range servers {
		for name, call := range inviteRPCs(s, "tok") {
			t.Run(server+"/"+name, func(t *testing.T) {
				assert.Equal(t, codes.Unavailable, status.Code(call()))
			})
		}
	}
}

// TestInviteRPCs_RequireTheirFields proves each RPC refuses a request
// missing a field it needs before reaching the service.
func TestInviteRPCs_RequireTheirFields(t *testing.T) {
	s := NewService(nil, nil, nil)
	ctx := context.Background()

	for name, call := range inviteRPCs(s, "") {
		t.Run(name+"/no token", func(t *testing.T) {
			assert.Equal(t, codes.InvalidArgument, status.Code(call()))
		})
	}

	_, err := s.GetInvite(ctx, nil)
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.FinishInviteRegistration(ctx, &pb.FinishInviteRegistrationRequest{Token: "tok", SessionId: "s1"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
	_, err = s.ActivateInvitePIV(ctx, &pb.ActivateInvitePIVRequest{Token: "tok"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestInvitationErrorStatus proves each redemption error reaches the wire
// with the code every transport agrees on, and an unusable token's detail
// never does.
func TestInvitationErrorStatus(t *testing.T) {
	tests := []struct {
		name    string
		err     error
		code    codes.Code
		message string
	}{
		{"unusable token", fmt.Errorf("lookup: %w", xkms.ErrInviteUnusable), codes.NotFound, xkms.ErrInviteUnusable.Error()},
		{"undecodable certificate", &xkms.ErrPIVCertDecode{Reason: "no PEM block"}, codes.InvalidArgument, "invite: piv certificate decode: no PEM block"},
		{"rejected certificate", &xkms.ErrPIVCertRejected{Err: errors.New("unknown issuer")}, codes.FailedPrecondition, "invite: piv certificate chain verification failed: unknown issuer"},
		{"not configured", xkms.ErrNotConfigured, codes.Unavailable, xkms.ErrNotConfigured.Error()},
		{"tenant not served", fmt.Errorf("begin: %w", errors.Join(xkms.ErrInviteTenantNotServed, errors.New("user store names no tenant"))), codes.PermissionDenied, xkms.ErrInviteTenantNotServed.Error()},
		{"unclassified", errTPMPolicyUnclassified, codes.Internal, errTPMPolicyUnclassified.Error()},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			st := status.Convert(invitationErrorStatus(tt.err))
			assert.Equal(t, tt.code, st.Code())
			assert.Equal(t, tt.message, st.Message())
		})
	}
}

// TestInviteRegistration_TenantNotServedIsPermissionDenied proves passkey
// enrolment through an invitation whose account is outside the tenant the
// relying party serves answers PermissionDenied on both registration RPCs,
// as REST answers 403, never Internal.
// grpcInviteUsers gives the fake user client the conditional activations
// xkms.InviteUserClient requires, without which every invite RPC answers
// not configured; the tests here never reach an activation.
type grpcInviteUsers struct{ *grpcFakeUserClient }

func (grpcInviteUsers) ActivatePendingUser(context.Context, uint64) (*qrdbtransport.User, error) {
	return nil, errors.New("activation must not be reached")
}

func (grpcInviteUsers) ActivateWithCertBinding(context.Context, uint64, string, int64) (*qrdbtransport.User, error) {
	return nil, errors.New("activation must not be reached")
}

func TestInviteRegistration_TenantNotServedIsPermissionDenied(t *testing.T) {
	const tenant = "acme"
	ctx := context.Background()
	users := newGRPCFakeUserClient()
	invitee, err := users.CreateUser(ctx, &qrdbtransport.CreateUserRequest{
		Username: "invitee@acme.example", Email: "invitee@acme.example", Name: "Invitee",
		TenantID: tenant, Pending: true,
	})
	require.NoError(t, err)
	invites, err := invitetest.New(grpcSingleStoreResolver{store: qrdbsdk.NewMemoryKVStore()})
	require.NoError(t, err)
	token, _, err := invites.Create(ctx, fmt.Sprint(invitee.ID), tenant, time.Hour)
	require.NoError(t, err)

	stores := webauthntest.NewStores(t)
	rp, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:          "example.com",
			RPDisplayName: "Example",
			RPOrigins:     []string{"https://example.com"},
		},
		UserStore:       stores.Users,
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: stores.Credentials,
	})
	require.NoError(t, err)
	xkmsSvc := &xkms.XKMSService{}
	xkmsSvc.SetUserClients(users, &grpcFakeRoleClient{})
	xkmsSvc.SetInviteStore(invites)
	xkmsSvc.SetWebAuthn(rp)
	xkmsSvc.SetInviteUserClient(grpcInviteUsers{users})
	s := NewService(nil, nil, xkmsSvc)

	rpcs := map[string]func() error{
		"BeginInviteRegistration": func() error {
			_, err := s.BeginInviteRegistration(ctx, &pb.BeginInviteRegistrationRequest{TenantId: tenant, Token: token})
			return err
		},
		"FinishInviteRegistration": func() error {
			_, err := s.FinishInviteRegistration(ctx, &pb.FinishInviteRegistrationRequest{TenantId: tenant, Token: token, SessionId: "s1", AttestationJson: "{}"})
			return err
		},
	}
	for name, call := range rpcs {
		t.Run(name, func(t *testing.T) {
			st := status.Convert(call())
			assert.Equal(t, codes.PermissionDenied, st.Code())
			assert.Equal(t, xkms.ErrInviteTenantNotServed.Error(), st.Message())
		})
	}
}
