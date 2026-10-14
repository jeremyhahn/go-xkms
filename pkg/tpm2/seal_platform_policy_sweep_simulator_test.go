//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestSealKey_PlatformPolicy_EveryCommandFailurePropagates sweeps sealing an
// object bound to the platform policy proving no TPM failure yields a sealed
// object.
func TestSealKey_PlatformPolicy_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := sealedKeyAttrs(t, h, "seal-platform-sweep", true, nil)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.SealKey(attrs, h.Backend, true)
			return err
		}
	},
		// The last command is a deferred best-effort session flush.
		8)
}

// TestUnsealKey_PlatformPolicy_EveryCommandFailurePropagates sweeps
// unsealing an object bound to the platform policy proving no TPM failure
// yields the secret.
func TestUnsealKey_PlatformPolicy_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		attrs := sealedKeyAttrs(t, h, "unseal-platform-sweep", true, nil)
		attrs.SealData = types.NewSealData([]byte("sealed-sweep-secret"))
		_, err := h.TPM.SealKey(attrs, h.Backend, true)
		require.NoError(t, err)

		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, err := h.TPM.UnsealKey(sealedKeyAttrs(t, h, "unseal-platform-sweep", true, nil), h.Backend)
			return err
		}
	},
		// The last three commands are the deferred flushes of the sessions
		// and the loaded object; they are logged, not returned.
		-3, -2, -1)
}
