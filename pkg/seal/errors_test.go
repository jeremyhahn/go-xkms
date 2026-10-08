package seal

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// assertRootKeyUnsealError checks that err is the typed root-key unseal
// failure for strategy: go-qrdb's ErrInvalidCredentials, with the backend's
// own error still in the chain.
func assertRootKeyUnsealError(t *testing.T, err error, strategy StrategyID, backendErr error) {
	t.Helper()
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrInvalidCredentials)
	assert.ErrorIs(t, err, backendErr)
	var unsealErr *RootKeyUnsealError
	require.ErrorAs(t, err, &unsealErr)
	assert.Equal(t, strategy, unsealErr.Strategy)
}

func TestRootKeyUnsealError_NamesTheStrategyAndCause(t *testing.T) {
	err := &RootKeyUnsealError{Strategy: StrategyTPM2, Err: errors.New("policy check failed")}

	assert.Equal(t, "seal: tpm2 could not unseal the root key: policy check failed", err.Error())
}

func TestRootKeyUnsealError_MatchesInvalidCredentialsNotDecryptionFailed(t *testing.T) {
	backendErr := errors.New("key not found")
	var err error = &RootKeyUnsealError{Strategy: StrategyAWSKMS, Err: backendErr}

	assertRootKeyUnsealError(t, err, StrategyAWSKMS, backendErr)
	assert.NotErrorIs(t, err, ErrDecryptionFailed,
		"a hardware unseal failure must not read as a wrong passphrase")
}
