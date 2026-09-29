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
	"github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// newFIDO2PolicyService wires a gRPC Service around the xkms singleton with a
// real WebAuthn relying party whose registration policy is the given value
// (nil = the config never decided, i.e. the go-xkms#184 secure default).
func newFIDO2PolicyService(t *testing.T, allow *bool) *Service {
	t.Helper()
	svc, _ := newFIDO2RelyingPartyService(t, allow)
	return svc
}

// newFIDO2RelyingPartyService is newFIDO2PolicyService that also returns the
// relying party, for tests that inspect or change the accounts it holds.
func newFIDO2RelyingPartyService(t *testing.T, allow *bool) (*Service, *webauthn.Service) {
	t.Helper()

	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	rp, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:                    "example.com",
			RPDisplayName:           "Example",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: allow,
		},
		UserStore:       webauthn.NewMemoryUserStore(),
		SessionStore:    webauthn.NewMemorySessionStore(),
		CredentialStore: webauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	svc.SetWebAuthn(rp)

	return NewService(nil, nil, svc), rp
}

// TestBeginRegistration_DefaultClosedReturnsPermissionDenied pins the gRPC
// side of the go-xkms#184 wire contract (docs/webauthn/api.md: "public
// registration disabled" => PermissionDenied): an unknown user under the
// default-closed policy is refused with codes.PermissionDenied, not the
// codes.Internal every other ceremony failure maps to.
func TestBeginRegistration_DefaultClosedReturnsPermissionDenied(t *testing.T) {
	svc := newFIDO2PolicyService(t, nil)

	resp, err := svc.BeginRegistration(context.Background(), &pb.BeginRegistrationRequest{
		Email:       "stranger@example.com",
		DisplayName: "Stranger",
	})

	require.Error(t, err)
	assert.Nil(t, resp)
	st, ok := status.FromError(err)
	require.True(t, ok, "want a gRPC status error, got %T: %v", err, err)
	assert.Equal(t, codes.PermissionDenied, st.Code(),
		"closed registration must surface as PermissionDenied on the wire")
}

// TestBeginRegistration_ExplicitOpenAllowsUnknownUser is the contrast case:
// with the policy explicitly opened the same request succeeds, proving the
// PermissionDenied above comes from the policy gate and not from the mock
// wiring.
func TestBeginRegistration_ExplicitOpenAllowsUnknownUser(t *testing.T) {
	open := true
	svc := newFIDO2PolicyService(t, &open)

	resp, err := svc.BeginRegistration(context.Background(), &pb.BeginRegistrationRequest{
		Email:       "newcomer@example.com",
		DisplayName: "Newcomer",
	})

	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.NotEmpty(t, resp.SessionId)
	assert.Contains(t, resp.OptionsJson, "publicKey")
}

// TestBeginRegistration_SessionStoreFullReturnsResourceExhausted pins the
// gRPC answer when the relying party holds its maximum number of unfinished
// ceremonies: ResourceExhausted, not Internal.
func TestBeginRegistration_SessionStoreFullReturnsResourceExhausted(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"mem": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "mem",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	open := true
	rp, err := webauthn.NewService(webauthn.ServiceParams{
		Config: &webauthn.Config{
			RPID:                    "example.com",
			RPDisplayName:           "Example",
			RPOrigins:               []string{"https://example.com"},
			AllowPublicRegistration: &open,
		},
		UserStore:       webauthn.NewMemoryUserStore(),
		SessionStore:    webauthn.NewMemorySessionStore(webauthn.WithMaxSessions(1)),
		CredentialStore: webauthn.NewMemoryCredentialStore(),
	})
	require.NoError(t, err)
	svc.SetWebAuthn(rp)
	grpcSvc := NewService(nil, nil, svc)

	_, err = grpcSvc.BeginRegistration(context.Background(), &pb.BeginRegistrationRequest{Email: "a@example.com"})
	require.NoError(t, err)
	_, err = grpcSvc.BeginRegistration(context.Background(), &pb.BeginRegistrationRequest{Email: "b@example.com"})
	st, ok := status.FromError(err)
	require.True(t, ok, "want a gRPC status error, got %T: %v", err, err)
	assert.Equal(t, codes.ResourceExhausted, st.Code())
}
