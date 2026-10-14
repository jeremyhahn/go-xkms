package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestClusterStrategyDeps_UnresolvedPassphraseFails configures a passphrase
// reference that was never resolved: the strategy dependencies refuse to
// build rather than protect the CA key with an empty passphrase.
func TestClusterStrategyDeps_UnresolvedPassphraseFails(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	s.config.Cluster.RaftEnrollment.CAKeyProtection = "passphrase"
	s.config.Cluster.RaftEnrollment.CAKeyPassphrase = &types.SecretValue{Raw: "env:XKMS_UNSET_CA_PASSPHRASE"}

	deps, err := s.clusterStrategyDeps(storage.NewMemory(), storage.NewMemory())
	assert.Nil(t, deps)
	var initErr *ErrServiceInit
	require.ErrorAs(t, err, &initErr)
	assert.Equal(t, "cluster CA key passphrase credential", initErr.Service)
	var unresolved *types.SecretReferenceUnresolvedError
	assert.ErrorAs(t, err, &unresolved)
}
