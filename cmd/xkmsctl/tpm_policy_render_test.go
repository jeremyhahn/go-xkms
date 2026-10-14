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

// tpm_policy_render_test.go pins the text rendering of a TPM policy's
// optional fields and its PCR values in index order.
package main

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	client "github.com/jeremyhahn/go-xkms/sdk/go"
)

func TestPrintTPMPolicyResult_TenantUpdatedAndSortedPCRs(t *testing.T) {
	policy := &client.TPMPolicy{Name: "boot", TenantID: "acme", UpdatedAt: "2026-02-01", Branches: []client.TPMPolicyBranch{{
		Conditions: []client.TPMPolicyCondition{{Type: "pcr", Bank: "sha256", PCRs: []uint{0, 7, 4},
			PCRValues: map[uint]string{7: "77", 0: "00", 4: "44"}}},
	}}}
	var out bytes.Buffer

	printTPMPolicyResult("Policy")(NewPrinter("text", &out), policy)
	assert.Contains(t, out.String(), "  Tenant:      acme\n")
	assert.Contains(t, out.String(), "  Updated:     2026-02-01\n")
	assert.Contains(t, out.String(), "    PCR 0 :    00\n    PCR 4 :    44\n    PCR 7 :    77\n")
}

func TestPrintTPMPolicyResult_IgnoresOtherResults(t *testing.T) {
	var out bytes.Buffer

	printTPMPolicyResult("Policy")(NewPrinter("text", &out), "not a policy")
	assert.Empty(t, out.String())
}
