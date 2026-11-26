//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

// TestProvisionSSRKHasNoAuthPolicy is the invariant itself, read back from the
// TPM: after provisioning, the object persisted at the shared SRK handle has an
// empty AuthPolicy.
//
// An AuthPolicy there would be the stale-from-birth policy this change removes:
// ProvisionOwner creates the SSRK before CreatePlatformPolicy extends the
// golden measurement, so whatever PCR state it described is gone by the time
// Provision returns.
func TestProvisionSSRKHasNoAuthPolicy(t *testing.T) {
	h := newSimHarness(t, nil)

	_, pub, err := h.TPM.ReadHandle(tpm2.TPMHandle(h.TPM.config.SSRK.Handle))
	require.NoError(t, err, "provisioning must persist a shared SRK")

	assert.Empty(t, pub.AuthPolicy.Buffer,
		"the shared SRK must be persisted with no authorization policy")

	attrs, err := h.TPM.SSRKAttributes()
	require.NoError(t, err)
	assert.False(t, (attrs.TPMPolicy == types.TPMPolicyPlatform),
		"the shared SRK's attributes must not claim a platform policy")
}

// TestSSRKPlatformPolicyConfigRejectedBeforeAnySRKIsCreated closes the loop
// between the configuration boundary and the TPM: a configuration asking for a
// platform-policy SSRK is refused where it is parsed, so provisioning is never
// reached and no key is created at the shared SRK handle.
func TestSSRKPlatformPolicyConfigRejectedBeforeAnySRKIsCreated(t *testing.T) {
	sim, err := OpenSimulator()
	require.NoError(t, err, "TPM simulator must be available; build with -tags tpm_simulator")
	t.Cleanup(func() { _ = sim.Close() })

	const configYAML = `
device: simulator
hash: SHA-256
ssrk:
  handle: 0x81000001
  algorithm: RSA
  platform-policy: true
  rsa:
    keysize: 2048
`

	var config Config
	err = yaml.Unmarshal([]byte(configYAML), &config)

	var policyErr *SSRKPlatformPolicyError
	require.ErrorAs(t, err, &policyErr,
		"the configuration must be rejected before it can provision anything")
	require.NotNil(t, config.SSRK)
	require.Zero(t, *config.SSRK, "nothing from the rejected section may be applied")

	// Nothing reached the TPM: the shared SRK handle is unoccupied.
	_, err = tpm2.ReadPublic{
		ObjectHandle: tpm2.TPMHandle(0x81000001),
	}.Execute(sim.Transport())
	require.Error(t, err, "no SRK may be created from a rejected configuration")
	assert.Equal(t, tpm2.TPMRC(0x18b), err, "expected TPM_RC_HANDLE")
}
