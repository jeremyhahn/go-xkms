package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	clustercapkg "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
)

// TestClusterSecretDeliveryService_TPMKEKStrategy proves a strategy that
// delivers enrollment material (tpm-kek) yields a service carrying its
// secret provider.
func TestClusterSecretDeliveryService_TPMKEKStrategy(t *testing.T) {
	s := clusterRuntimeTestServer(t)
	strategy, err := clustercapkg.NewKeyStrategy(clustercapkg.KeyStrategyTPMKEK)
	require.NoError(t, err)
	s.clusterCAKeyStrategy = strategy
	s.ca = &mockTrustedCA{initialized: true}

	svc := s.ClusterSecretDeliveryService()
	require.NotNil(t, svc)
	require.True(t, svc.HasProviders())
}
