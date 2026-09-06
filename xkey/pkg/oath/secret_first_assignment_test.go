package oath

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCredential_SetSecret_FreshCredentialIsNilSafe pins the assumption the
// allocate-then-destroy ordering in SetSecret/setSecretBytes relies on: a
// freshly allocated Credential has a nil secret, and (*secure.Buffer).Destroy
// on a nil receiver is a documented no-op in go-qrdb (pkg/secure/buffer.go:
// `if b == nil { return }`). If a future go-qrdb release drops that guard,
// this test -- not a production enrollment -- is where the panic surfaces.
//
// It also covers the second assignment, where the previous buffer is real and
// must be destroyed before the replacement is installed.
func TestCredential_SetSecret_FreshCredentialIsNilSafe(t *testing.T) {
	t.Parallel()

	cred := &Credential{}
	require.False(t, cred.HasSecret(), "a zero Credential carries no secret")

	require.NotPanics(t, func() {
		require.NoError(t, cred.SetSecret("JBSWY3DPEHPK3PXP"))
	}, "first assignment on a zero Credential must not panic (nil receiver Destroy)")
	require.True(t, cred.HasSecret())

	require.NotPanics(t, func() {
		require.NoError(t, cred.SetSecret("GEZDGNBVGY3TQOJQ"))
	}, "replacement must destroy the previous buffer and install the new one")
	require.Equal(t, "GEZDGNBVGY3TQOJQ", cred.SecretString())
}
