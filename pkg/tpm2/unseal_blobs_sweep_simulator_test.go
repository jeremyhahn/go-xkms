//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/require"
)

// TestUnsealFromBlobs_EveryCommandFailurePropagates sweeps the boot-time
// unseal of a sealed object read from blobs, for a password object and one
// bound to the platform policy. No TPM failure may yield the secret.
func TestUnsealFromBlobs_EveryCommandFailurePropagates(t *testing.T) {
	tests := []struct {
		name           string
		platformPolicy bool
		password       func(t *testing.T) types.Password
		// flushes are the positions, counted from the end, of the deferred
		// flushes of the sessions and the loaded object; they are logged,
		// not returned. Counting from the end keeps each row independent of
		// how many commands the authorizing session issues before them.
		flushes []int
	}{
		{
			name:     "password",
			password: func(t *testing.T) types.Password { return mustPassword(t, []byte("object-password")) },
			flushes:  []int{-3, -2, -1},
		},
		{
			name:           "platform policy",
			platformPolicy: true,
			password:       func(*testing.T) types.Password { return nil },
			flushes:        []int{-3, -2, -1},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
				h := newSimHarness(t, nil)
				keyAttrs := sealedKeyAttrs(t, h, "blob-sweep", tt.platformPolicy, tt.password(t))
				keyAttrs.SealData = types.NewSealData([]byte("efi-partition-sealed-secret"))
				resp, err := h.TPM.SealKey(keyAttrs, h.Backend, true)
				require.NoError(t, err)

				return h.TPM.transport, func(tr transport.TPM) error {
					h.TPM.transport = tr
					_, err := h.TPM.unsealFromBlobs(keyAttrs, nil, resp.OutPublic.Bytes(), resp.OutPrivate.Buffer)
					return err
				}
			}, tt.flushes...)
		})
	}
}
