package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestWithTenantLoginCAFencedHolders_AppendsHolders pins that the option
// accumulates the fenced claim holders the boot pass hands to the factory.
func TestWithTenantLoginCAFencedHolders_AppendsHolders(t *testing.T) {
	s := &Server{}
	withTenantLoginCAFencedHolders("host-a/1")(s)
	withTenantLoginCAFencedHolders("host-b/2", "host-c/3")(s)
	require.Equal(t, []string{"host-a/1", "host-b/2", "host-c/3"}, s.tenantLoginCAFencedHolders)
}
