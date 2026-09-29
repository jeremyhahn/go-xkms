// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// TestProvisionFresh_RefusesIncompleteInput proves the helper refuses a nil
// TPM and a configuration missing any key section instead of dereferencing
// nil. The success path is exercised on the simulator by every
// pkg/backend/tpm2 test that opens a fresh simulator, and on swtpm by the
// pkg/tpmpolicy vTPM tests.
func TestProvisionFresh_RefusesIncompleteInput(t *testing.T) {
	assert.ErrorIs(t, ProvisionFresh(nil, &Config{}), ErrPlatformKeyStoreNilTPM)
	tpm := &TPM2{}
	assert.ErrorIs(t, ProvisionFresh(tpm, nil), ErrFreshProvisionConfig)
	assert.ErrorIs(t, ProvisionFresh(tpm, &Config{EK: &EKConfig{}, SSRK: &SRKConfig{}}), ErrFreshProvisionConfig)
}
