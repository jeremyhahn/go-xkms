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

package xkms

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/autofill"
)

// TestReexport_AutofillPolicyNames pins that the sdk/go autofill policy
// constants xkey uses are the pkg/autofill values.
func TestReexport_AutofillPolicyNames(t *testing.T) {
	require.Equal(t, autofill.FillModeAutoFill, FillModeAutoFill)
	require.Equal(t, autofill.FillModeClickToFill, FillModeClickToFill)
	require.Equal(t, autofill.TOTPPolicyAuto, TOTPPolicyAuto)
	require.Equal(t, autofill.TOTPPolicyPrompt, TOTPPolicyPrompt)
}
