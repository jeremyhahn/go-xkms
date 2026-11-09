package server

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"log/slog"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbnode "github.com/jeremyhahn/go-qrdb/sdk/go/node"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/rest"
	"github.com/jeremyhahn/go-xkms/pkg/auth"
	"github.com/jeremyhahn/go-xkms/pkg/auth/token"
	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/embeddednode/serviceprincipal"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/jeremyhahn/go-xkms/pkg/xkms"
)

var errSigningKeyRefused = errors.New("backend: signing key refused")

// signingKeyBackend is the part of a backend the token issuer touches. With
// signer nil it refuses to provision a key; otherwise it reports the key
// present and hands out signer.
type signingKeyBackend struct {
	xkms.Backend
	signer crypto.Signer
}

func (b *signingKeyBackend) Type() types.StoreType { return types.StoreSoftware }

func (b *signingKeyBackend) GetKey(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	if b.signer == nil {
		return nil, errSigningKeyRefused
	}
	return b.signer, nil
}

func (b *signingKeyBackend) GenerateECDSA(context.Context, *types.KeyAttributes) (crypto.PrivateKey, error) {
	return nil, errSigningKeyRefused
}

func (b *signingKeyBackend) Signer(context.Context, *types.KeyAttributes) (crypto.Signer, error) {
	return b.signer, nil
}

func newTokenIssuerServer(t *testing.T, backend xkms.Backend, cfg *config.Config) *Server {
	t.Helper()
	s := newMinimalServer(t, cfg)
	s.defaultBackendName = "software"
	s.backends = map[string]xkms.Backend{"software": backend}
	return s
}

// TestInitializeTokenIssuer_SigningKeyFailureIsSoft proves a backend that
// cannot provision the JWT signing key leaves the issuer off without
// failing startup, and says so in the log.
func TestInitializeTokenIssuer_SigningKeyFailureIsSoft(t *testing.T) {
	var logs bytes.Buffer
	s := newTokenIssuerServer(t, &signingKeyBackend{}, &config.Config{})
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))

	require.NoError(t, s.initializeTokenIssuer())
	assert.Nil(t, s.tokenIssuer)
	assert.Contains(t, logs.String(), "Token issuer disabled")
	assert.Contains(t, logs.String(), errSigningKeyRefused.Error())
}

// TestInitializeTokenIssuer_ConfigErrorAborts gives a refresh TTL beyond the
// revocation tombstone: an issuer configuration error aborts startup.
func TestInitializeTokenIssuer_ConfigErrorAborts(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tooLong := (token.RevocationTombstoneTTL * 2).String()
	s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{
		Auth: config.AuthConfig{Session: &config.SessionConfig{RefreshTokenTTL: tooLong}},
	})

	err = s.initializeTokenIssuer()
	var initErr *ErrServiceInit
	require.ErrorAs(t, err, &initErr)
	assert.Equal(t, "token issuer", initErr.Service)
	var configErr *rest.TokenIssuerConfigError
	assert.ErrorAs(t, err, &configErr)
	assert.Nil(t, s.tokenIssuer)
}

// TestInitializeTokenIssuer_EmbeddedNode_RefreshInHolderTenant mints the
// PIV/mTLS identity for a holder in a non-system tenant and refreshes it
// through xkmsd's own issuer wiring: the refresh re-check must find the
// holder in the token's tenant, and only there.
func TestInitializeTokenIssuer_EmbeddedNode_RefreshInHolderTenant(t *testing.T) {
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

	_, err = node.UserService().CreateUser(qrdbsdk.ContextWithTenant(context.Background(), "acme"),
		&qrdbsdk.CreateUserRequest{Username: "bob", Email: "bob@example.com", TenantID: "acme"})
	require.NoError(t, err)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	s := newTokenIssuerServer(t, &signingKeyBackend{signer: key}, &config.Config{})
	s.qrdbNode = node
	s.qrdbClient = node.Client()
	require.NoError(t, s.initializeTokenIssuer())
	require.NotNil(t, s.tokenIssuer)

	pivIdentity := func(tenant string) *auth.Identity {
		return &auth.Identity{
			Subject:  "bob",
			TenantID: tenant,
			Metadata: map[string]string{auth.SubjectKindMetadataKey: auth.SubjectKindUsername},
		}
	}

	pair, err := s.tokenIssuer.Mint(context.Background(), pivIdentity("acme"))
	require.NoError(t, err)
	refreshed, err := s.tokenIssuer.Refresh(context.Background(), pair.RefreshToken)
	require.NoError(t, err)
	assert.NotEmpty(t, refreshed.AccessToken)

	// Strict tenant isolation: the same username claimed in another tenant
	// does not resolve to the acme holder.
	pair, err = s.tokenIssuer.Mint(context.Background(), pivIdentity("other"))
	require.NoError(t, err)
	_, err = s.tokenIssuer.Refresh(context.Background(), pair.RefreshToken)
	assert.ErrorIs(t, err, auth.ErrRefreshSubjectNotFound)
}
