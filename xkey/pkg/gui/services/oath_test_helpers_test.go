package services

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/oath"
)

// oathCredWithSecret installs secret on c through SetSecret and returns c.
// Credential.Secret is no longer an exported field (#210: the secret lives in
// protected memory), so test literals hand the value in here instead.
func oathCredWithSecret(t *testing.T, c *oath.Credential, secret string) *oath.Credential {
	t.Helper()
	require.NoError(t, c.SetSecret(secret))
	return c
}
