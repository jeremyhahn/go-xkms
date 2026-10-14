package server

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/oidc/credential"
	"github.com/jeremyhahn/go-xkms/pkg/seal"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func TestBuildOIDCCredentials_AlreadyBuiltIsKept(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	built := &credential.Service{}
	s.oidcCredentials = built

	s.buildOIDCCredentials()
	assert.Same(t, built, s.OIDCCredentialService())
}

func TestBuildOIDCCredentials_WithoutNodeStaysOff(t *testing.T) {
	var logs bytes.Buffer
	s := newMinimalServer(t, &config.Config{})
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))

	s.buildOIDCCredentials()
	assert.Nil(t, s.OIDCCredentialService())
	assert.Contains(t, logs.String(), "barrier registry and qrdb node")
}

// TestBuildOIDCCredentials_NoCoordinationStaysOff gives the server a client
// whose transport serves no coordination plane: the feature stays off and
// the reason is logged.
func TestBuildOIDCCredentials_NoCoordinationStaysOff(t *testing.T) {
	client, _, err := testutil.NewQRDBFakeClient()
	require.NoError(t, err)
	var logs bytes.Buffer
	s := newMinimalServer(t, &config.Config{})
	s.logger = slog.New(slog.NewTextHandler(&logs, nil))
	s.barrierRegistry = &seal.BarrierRegistry{}
	s.qrdbClient = client

	s.buildOIDCCredentials()
	assert.Nil(t, s.OIDCCredentialService())
	assert.Contains(t, logs.String(), "level=WARN")
	assert.Contains(t, logs.String(), "xkms feature off")
}
