//go:build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestReadPCRs_BankOrderIsDeterministic is the map-iteration regression test.
//
// ReadPCRs used to build its result by ranging over a map[string]TPMAlgID, so
// the order of the returned []PCRBank was randomized by the Go runtime on every
// call. Any caller indexing the slice -- banks[0] meaning "the SHA-1 bank" --
// read a different bank run to run. That is what actually broke
// TestPCRExtend_Simulator, whose failure was misattributed to test isolation
// and papered over with a "passes alone but fails in suite" skip guard.
//
// Repeated calls against one TPM must agree, and must match the documented
// order, so a caller reading the source can rely on it. Against the map version
// this fails within a few iterations.
func TestReadPCRs_BankOrderIsDeterministic(t *testing.T) {
	h := newSimHarness(t, nil)

	want := []string{"SHA1", "SHA256", "SHA384", "SHA512"}

	var reference []string
	for i := 0; i < 24; i++ {
		banks, err := h.TPM.ReadPCRs([]uint{0})
		require.NoError(t, err)

		order := make([]string, 0, len(banks))
		for _, b := range banks {
			order = append(order, b.Algorithm)
		}

		if reference == nil {
			reference = order
			continue
		}
		require.Equal(t, reference, order,
			"iteration %d: ReadPCRs returned banks in a different order", i)
	}

	assert.Equal(t, want, reference,
		"the bank order must be the documented one, not merely stable")
}

// TestReadPCRs_BankSelectedByAlgorithmNotIndex documents the safe way to use
// the result. Even with a deterministic order, matching on Algorithm is what
// callers should do; this asserts the field is populated and unique so that
// contract actually holds.
func TestReadPCRs_BankSelectedByAlgorithmNotIndex(t *testing.T) {
	h := newSimHarness(t, nil)

	banks, err := h.TPM.ReadPCRs([]uint{0, 7})
	require.NoError(t, err)
	require.NotEmpty(t, banks)

	seen := make(map[string]bool, len(banks))
	for _, b := range banks {
		require.NotEmpty(t, b.Algorithm, "every bank must name its algorithm")
		require.False(t, seen[b.Algorithm], "duplicate bank %q", b.Algorithm)
		seen[b.Algorithm] = true
		assert.NotEmpty(t, b.PCRs, "bank %q carried no PCR values", b.Algorithm)
	}
}
