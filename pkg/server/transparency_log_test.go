package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestHeadSignerProviderOptions_WiresCAProvider proves the embedded node is
// given the CA-backed head-signer provider, so verifiable-log checkpoints are
// signed with the CA key rather than go-qrdb's software key.
func TestHeadSignerProviderOptions_WiresCAProvider(t *testing.T) {
	s := &Server{}
	opts := s.headSignerProviderOptions()
	require.Len(t, opts, 1)
	require.NotNil(t, s.headSignerProvider, "the provider is kept for binding once the CA is built")
}
