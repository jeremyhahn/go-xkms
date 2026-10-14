//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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

// TestReplaceHierarchyAuth proves the replaced enclave is released, and that
// re-assigning the auth already in place leaves it usable.
func TestReplaceHierarchyAuth(t *testing.T) {
	h := newSimHarness(t, nil)
	attrs, err := SRKAttributesFromConfig(*h.TPM.config.SSRK)
	require.NoError(t, err)
	require.NotNil(t, attrs.TPMAttributes.HierarchyAuth)
	soPIN := mustPassword(t, []byte("so-pin"))

	before := lockedBytesInUse(t)
	replaceHierarchyAuth(attrs, soPIN)
	assert.Less(t, lockedBytesInUse(t), before, "the replaced enclave must be released")
	assert.Same(t, soPIN, attrs.TPMAttributes.HierarchyAuth)

	replaceHierarchyAuth(attrs, soPIN)
	assert.Equal(t, []byte("so-pin"), attrs.TPMAttributes.HierarchyAuth.Bytes(),
		"re-assigning the same auth must not clear it")
}
