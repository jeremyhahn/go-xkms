//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestProvision_ReleasesReplacedHierarchyAuth proves provisioning leaves no
// password enclave locked once the TPM is closed. Provision used to replace
// the hierarchy auth the EK and SSRK configs built with the caller's soPIN
// without clearing it, leaking two locked pages per provisioned TPM until
// the process hit RLIMIT_MEMLOCK.
func TestProvision_ReleasesReplacedHierarchyAuth(t *testing.T) {
	before := lockedBytesInUse(t)
	t.Run("provision", func(t *testing.T) { newSimHarness(t, nil) })
	assert.Equal(t, before, lockedBytesInUse(t), "a provisioned TPM must not leave a password enclave locked")
}
