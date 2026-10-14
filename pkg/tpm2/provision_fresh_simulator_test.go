//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newFreshProvisionHarness returns an unprovisioned simulator whose config
// carries no hierarchy auth, matching the empty auth of a factory-fresh TPM.
func newFreshProvisionHarness(t *testing.T, mutate func(*Config)) *simHarness {
	t.Helper()
	return newUnprovisionedSimHarness(t, func(c *Config) {
		c.EK.HierarchyAuth = nil
		c.SSRK.HierarchyAuth = nil
		if mutate != nil {
			mutate(c)
		}
	})
}

// TestProvisionFresh_CreatesEKAndBothSRKs proves the helper persists the EK,
// the Shared SRK and the Platform SRK at their configured handles.
func TestProvisionFresh_CreatesEKAndBothSRKs(t *testing.T) {
	h := newFreshProvisionHarness(t, nil)
	cfg := h.TPM.config

	require.NoError(t, ProvisionFresh(h.TPM, cfg))

	for name, handle := range map[string]uint32{
		"EK":           cfg.EK.Handle,
		"Shared SRK":   cfg.SSRK.Handle,
		"Platform SRK": cfg.PlatformSRK.SRKHandle,
	} {
		_, _, err := h.TPM.ReadHandle(tpm2.TPMHandle(handle))
		assert.NoError(t, err, "%s must be persisted at 0x%x", name, handle)
	}
}

// TestProvisionFresh_WrapsEachStepFailure proves every step's failure is
// returned, wrapped with the step that failed, before any later step runs.
func TestProvisionFresh_WrapsEachStepFailure(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{
			name:   "EK attributes",
			mutate: func(c *Config) { c.EK.ECCConfig = &store.ECCConfig{Curve: "no-such-curve"} },
			want:   "EK attributes",
		},
		{
			name:   "SSRK attributes",
			mutate: func(c *Config) { c.SSRK.ECCConfig = &store.ECCConfig{Curve: "no-such-curve"} },
			want:   "SSRK attributes",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newFreshProvisionHarness(t, tt.mutate)
			err := ProvisionFresh(h.TPM, h.TPM.config)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.want)
		})
	}
}

// TestProvisionFresh_CreateEKFailure proves a TPM rejection of the EK is
// surfaced as the create-EK step: the configured endorsement auth does not
// match the fresh simulator's empty auth.
func TestProvisionFresh_CreateEKFailure(t *testing.T) {
	h := newUnprovisionedSimHarness(t, nil)

	err := ProvisionFresh(h.TPM, h.TPM.config)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "create EK")
}
