package xkms

import (
	"context"
	"testing"

	qrdbquic "github.com/jeremyhahn/go-qrdb/sdk/go/transport/quic"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
)

// A host composed over a dialed qrdb transport client (SetUserClients with
// the client's users, no WithNodeUsers) has no guarded activation: the
// transport client does not implement InviteUserClient. CreateUser must
// then refuse an invited (pending) account before it reaches the store,
// rather than persist an account no invitation can ever activate.
func TestCreateUser_TransportUserClientRefusesPendingAccount(t *testing.T) {
	svc, _, roles := setupServiceWithUserClients(t)

	sent := 0
	client := qrdbquic.NewFrameTransport("xkms", func(context.Context, string, string, []byte) (uint16, []byte, error) {
		sent++
		return 500, nil, nil
	})
	_, guarded := any(client).(InviteUserClient)
	require.False(t, guarded, "the pinned qrdb transport client has no guarded activation")

	svc.SetUserClients(client, roles)
	require.Nil(t, svc.inviteUserClient())

	_, err := svc.CreateUser(context.Background(), &transport.CreateUserRequest{
		Username: "erin", Email: "erin@example.com",
	})
	require.ErrorIs(t, err, ErrNotConfigured)
	require.Zero(t, sent, "no pending account may be persisted over the transport")

	_, err = svc.GetInvite(context.Background(), &transport.GetInviteRequest{TenantID: "t", Token: "x"})
	require.ErrorIs(t, err, ErrNotConfigured)
}
