//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/google/go-tpm/tpm2/transport"
)

// TestPlatformPolicySession_EveryCommandFailurePropagates sweeps
// PlatformPolicySession's PCR-branch command sequence (PCR read for the
// policy digest, policy session creation, PolicyPCR, PolicyOR) proving a
// failure at any step surfaces as an error, except the trailing
// PolicyGetDigest call used only to cache the digest for logging -- its own
// documented behavior (the code ignores pgdErr entirely) is to proceed
// regardless.
func TestPlatformPolicySession_EveryCommandFailurePropagates(t *testing.T) {
	sweepEachCommandFailure(t, func(t *testing.T) (transport.TPM, func(transport.TPM) error) {
		h := newSimHarness(t, nil)
		// The session's own closer is deliberately never invoked here: doing
		// so would add its FlushContext to the same command count this sweep
		// is measuring, miscounting PlatformPolicySession's own commands.
		// Each iteration gets a fresh harness (see sweepEachCommandFailure),
		// so an unflushed session is cleaned up by that harness's teardown
		// regardless.
		return h.TPM.transport, func(tr transport.TPM) error {
			h.TPM.transport = tr
			_, _, err := h.TPM.PlatformPolicySession(nil)
			return err
		}
	}, 5)
}
