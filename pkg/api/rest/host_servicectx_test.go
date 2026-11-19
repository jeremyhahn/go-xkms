package rest

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/testutil/barriertest"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// The issuer NewHostServer builds must write its refresh bookkeeping under
// the host's service context (go-xkms#2287): login routes are public, so a
// mint runs under an anonymous request context, and an authenticating
// embedded node refuses anonymous KV calls.
func TestNewHostServer_IssuerMintsUnderAnonymousContext(t *testing.T) {
	xkms.Reset()
	t.Cleanup(xkms.Reset)
	require.NoError(t, xkms.Initialize(&xkms.ServiceConfig{
		Backends:       map[string]xkms.Backend{"test": xkmsmocks.NewMockKeyStore()},
		DefaultBackend: "test",
	}))
	svc, err := xkms.Get()
	require.NoError(t, err)

	node := barriertest.NewPrincipalNode(t)
	srv, err := NewHostServer(context.Background(), &HostConfig{
		XKMSService:    svc,
		QRDBClient:     node.Client(),
		ServiceContext: node.ServiceContext,
	})
	require.NoError(t, err)
	require.NotNil(t, srv.tokenIssuer, "the host must build a token issuer")

	pair, err := srv.tokenIssuer.Mint(context.Background(), &auth.Identity{Subject: "admin", TenantID: "system"})
	require.NoError(t, err, "the host's issuer must mint under an anonymous context")
	require.NoError(t, srv.tokenIssuer.Revoke(context.Background(), pair.RefreshToken),
		"the host's issuer must revoke under an anonymous context")
}
