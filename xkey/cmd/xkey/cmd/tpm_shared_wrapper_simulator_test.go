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

//go:build tpm_simulator

package cmd

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSharedTPMWithoutSetterFails is #2325 (2): a sharedTPM over a TPM that
// lacks SetPlatformKeyStore fails the test instead of dropping the key
// store silently.
func TestSharedTPMWithoutSetterFails(t *testing.T) {
	var failure string
	s := sharedTPM{fatalf: func(format string, args ...any) { failure = fmt.Sprintf(format, args...) }}
	s.SetPlatformKeyStore(nil)
	assert.Contains(t, failure, "SetPlatformKeyStore")
}
