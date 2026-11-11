package seal

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDestroyCredentials_ZeroValueIsANoOp pins the nil-safety the TPM2 paths
// rely on: CredentialsFor yields the zero Credentials for an empty secret, and
// destroying it must not dereference the absent Sealed.
func TestDestroyCredentials_ZeroValueIsANoOp(t *testing.T) {
	creds, err := CredentialsFor(t.Context(), nil)
	require.NoError(t, err)
	require.Nil(t, creds.Secret)

	assert.NoError(t, DestroyCredentials(creds))
	assert.NoError(t, DestroyCredentials(Credentials{}))
}

// TestDestroyCredentials_DestroysTheSecret proves a real credential's secret
// is released: a later Open is refused.
func TestDestroyCredentials_DestroysTheSecret(t *testing.T) {
	creds, err := CredentialsFor(t.Context(), []byte("a passphrase"))
	require.NoError(t, err)
	require.NotNil(t, creds.Secret)

	require.NoError(t, DestroyCredentials(creds))

	_, openErr := creds.Secret.Open(t.Context())
	assert.Error(t, openErr, "a destroyed secret must not open")
}
