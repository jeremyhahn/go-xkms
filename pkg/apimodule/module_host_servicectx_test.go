package apimodule

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestModule_HostConfig_RefreshStoreWritesUnderAnonymousContext pins
// go-xkms#2287 on the apimodule host path: login routes are public, so
// the refresh store is written under a context with no identity. The
// module must hand the REST host its WithServiceContext binder, so the
// store's KV writes run as the node's service principal against an
// embedded node that enforces authentication.
func TestModule_HostConfig_RefreshStoreWritesUnderAnonymousContext(t *testing.T) {
	node := barriertest.NewPrincipalNode(t)
	svc := &xkms.XKMSService{}
	m, err := NewModule(func() *xkms.XKMSService { return svc },
		WithQRDBClient(node.Client),
		WithServiceContext(node.ServiceContext))
	require.NoError(t, err)

	hc, err := m.hostConfig(svc)
	require.NoError(t, err)
	require.NotNil(t, hc.QRDBClient)
	require.NotNil(t, hc.ServiceContext, "the module must pass its service context to the REST host")

	store, err := token.NewQRDBRefreshStore(hc.QRDBClient.KV(), token.WithCallContext(hc.ServiceContext))
	require.NoError(t, err)
	ctx := context.Background()
	rec := &token.Record{JTI: "j1", Family: "f1", Subject: "admin", ExpiresAt: time.Now().Add(time.Hour).Unix()}
	require.NoError(t, store.Save(ctx, rec))
	got, err := store.Get(ctx, "f1", "j1")
	require.NoError(t, err)
	require.Equal(t, "admin", got.Subject)
}
