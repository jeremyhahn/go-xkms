package server

import (
	"context"
	"os"
	"os/exec"
	"testing"

	qrdbuser "github.com/jeremyhahn/go-qrdb/pkg/user"
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	xkmsmocks "github.com/jeremyhahn/go-xkms/pkg/xkms/mocks"
)

// pivOnlyRefreshChildEnv marks the child process of
// TestInitializeTokenIssuer_PIVOnlyRefreshOverNode.
const pivOnlyRefreshChildEnv = "XKMS_TEST_PIV_ONLY_REFRESH_CHILD"

// TestInitializeTokenIssuer_PIVOnlyRefreshOverNode proves a PIV/mTLS-only
// deployment (no WebAuthn, so RegisterWebAuthnGrant never runs) refreshes a
// session over an enforcing embedded node: the issuer's user resolver runs
// as the service principal, which needs users:read for the current-account
// check. go-qrdb's role grants are process-global and registered once, so a
// WebAuthn grant registered by another test in this binary would hide a
// missing resolver grant; the body therefore runs in a fresh process.
func TestInitializeTokenIssuer_PIVOnlyRefreshOverNode(t *testing.T) {
	if os.Getenv(pivOnlyRefreshChildEnv) == "1" {
		pivOnlyRefreshOverNode(t)
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestInitializeTokenIssuer_PIVOnlyRefreshOverNode$", "-test.count=1")
	cmd.Env = append(os.Environ(), pivOnlyRefreshChildEnv+"=1")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "PIV-only refresh child process failed:\n%s", out)
}

func pivOnlyRefreshOverNode(t *testing.T) {
	cfg := qrdbsdk.DefaultDaemonConfig()
	cfg.Raft.DataDir = t.TempDir()
	cfg.Databases = []qrdbsdk.DaemonDatabaseConfig{{Name: "default", Backend: "memory"}}
	cfg.Protocols.REST = false
	cfg.Protocols.GRPC = false
	cfg.Protocols.QUIC = false
	cfg.Protocols.Unix = false
	cfg.Protocols.MCP = false
	cfg.Seal.Enabled = false
	node, err := qrdbnode.NewStandaloneNode(context.Background(), cfg, nil, serviceprincipal.Option())
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, node.Close()) })

	// WebAuthn is off: the config carries no WebAuthn section and nothing
	// registers the WebAuthn grant.
	s := newTokenIssuerServer(t, xkmsmocks.NewMockKeyStore(), &config.Config{})
	s.qrdbNode = node
	s.qrdbClient = node.Client()
	require.NoError(t, s.initializeTokenIssuer())
	require.NotNil(t, s.tokenIssuer)

	ctx := context.Background()
	u, err := node.UserService().CreateUser(ctx, &qrdbuser.CreateUserRequest{
		Username: "piv-alice",
		Email:    "piv-alice@example.com",
		Name:     "piv-alice",
	})
	require.NoError(t, err)
	pair, err := s.tokenIssuer.Mint(ctx, &auth.Identity{
		Subject: "piv-alice",
		Metadata: map[string]string{
			"auth_method":               "mtls",
			auth.SubjectKindMetadataKey: auth.SubjectKindUsername,
		},
	})
	require.NoError(t, err)

	refreshed, err := s.tokenIssuer.Refresh(ctx, pair.RefreshToken)
	require.NoError(t, err, "a PIV-only refresh over the node must resolve the account as the service principal")
	assert.NotEmpty(t, refreshed.AccessToken)
	assert.NotEmpty(t, refreshed.RefreshToken)

	// The resolver grant is read-only: the principal still cannot delete
	// accounts, which only the WebAuthn grant adds.
	sctx, err := node.ServiceContext(ctx)
	require.NoError(t, err)
	err = node.Client().Users().DeleteUser(sctx, u.ID)
	require.Error(t, err)
	var denied *qrdbsdk.PermissionDeniedError
	assert.ErrorAs(t, err, &denied)
}
