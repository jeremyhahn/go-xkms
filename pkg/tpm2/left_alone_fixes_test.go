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
)

// TestParseIdentityProvisioningStrategy_FailsClosedOnUnknown is the fail-open
// regression test.
//
// The default arm used to return EnrollmentStrategyIAK_IDEVID_SINGLE_PASS for
// every unrecognized value, so a typo in identity-provisioning-strategy
// silently ran a different device-identity ceremony than the operator
// configured -- and made ErrInvalidEnrollmentStrategy unreachable in both
// VerifyTCGCSR and CreateTCG_CSR_IDEVID, since no input could reach a strategy
// switch's default arm.
//
// An unset value must still select the documented 6.2 default; only a value the
// operator actually typed and got wrong may fail closed.
func TestParseIdentityProvisioningStrategy_FailsClosedOnUnknown(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  EnrollmentStrategy
	}{
		{"unset selects the documented default", "", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"6.1 IAK", "IAK", EnrollmentStrategyIAK},
		{"6.2 single pass", "IAK_IDEVID_SINGLE_PASS", EnrollmentStrategyIAK_IDEVID_SINGLE_PASS},
		{"typo", "IAK_IDEVID_SINGLE_PAS", EnrollmentStrategyUnknown},
		{"wrong case", "iak", EnrollmentStrategyUnknown},
		{"leading space", " IAK", EnrollmentStrategyUnknown},
		{"unrelated value", "SOMETHING_ELSE", EnrollmentStrategyUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, ParseIdentityProvisioningStrategy(tt.input))
		})
	}
}

// TestEnrollmentStrategyUnknown_MatchesNoStrategyBranch pins the property that
// makes the fail-closed behavior work: the sentinel must not equal either real
// strategy, so every strategy switch falls through to its default arm and
// reports ErrInvalidEnrollmentStrategy.
func TestEnrollmentStrategyUnknown_MatchesNoStrategyBranch(t *testing.T) {
	assert.NotEqual(t, EnrollmentStrategyIAK, EnrollmentStrategyUnknown)
	assert.NotEqual(t, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS, EnrollmentStrategyUnknown)

	switch ParseIdentityProvisioningStrategy("definitely-not-a-strategy") {
	case EnrollmentStrategyIAK, EnrollmentStrategyIAK_IDEVID_SINGLE_PASS:
		t.Fatal("an unrecognized strategy must not match a real strategy branch")
	}
}
