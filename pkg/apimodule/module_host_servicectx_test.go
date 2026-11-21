package apimodule

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// TestModule_HostConfig_RefreshStoreWritesUnderAnonymousContext pins
// go-xkms#2287 on the apimodule host path: login routes are public, so
// the refresh store is written under a context with no identity. The
// module must hand the REST host its WithServiceContext binder, so the
// store's KV writes run as the node's service principal against an
// embedded node that enforces authentication.
// The module hands its service context to the REST host config; the host's
// own use of it is covered by rest.TestNewHostServer_IssuerMintsUnderAnonymousContext.
func TestModule_HostConfig_CarriesServiceContext(t *testing.T) {
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
	ctx, err := hc.ServiceContext(context.Background())
	require.NoError(t, err)
	require.NotNil(t, ctx)
}
