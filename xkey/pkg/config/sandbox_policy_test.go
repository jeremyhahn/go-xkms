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

package config

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAPIExplorerSandboxPolicy_Empty(t *testing.T) {
	assert.NoError(t, ValidateAPIExplorerSandboxPolicy(""), "empty means unset, not invalid")
}

func TestValidateAPIExplorerSandboxPolicy_SafeDefault(t *testing.T) {
	assert.NoError(t, ValidateAPIExplorerSandboxPolicy(SafeDefaultAPIExplorerSandboxPolicy))
}

func TestValidateAPIExplorerSandboxPolicy_ScriptsAndSameOriginRefused(t *testing.T) {
	err := ValidateAPIExplorerSandboxPolicy("allow-same-origin allow-scripts allow-forms allow-popups")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSandboxPolicyCombo))
}

func TestValidateAPIExplorerSandboxPolicy_ScriptsAndSameOriginRefused_OrderIndependent(t *testing.T) {
	// Token order must not matter: "allow-scripts allow-same-origin" is the
	// same dangerous combination as "allow-same-origin allow-scripts".
	err := ValidateAPIExplorerSandboxPolicy("allow-scripts allow-same-origin")
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrSandboxPolicyCombo))
}

func TestValidateAPIExplorerSandboxPolicy_ScriptsAloneAllowed(t *testing.T) {
	// Without allow-same-origin, the srcdoc frame has a unique opaque
	// origin, so allow-scripts alone cannot reach window.parent.
	assert.NoError(t, ValidateAPIExplorerSandboxPolicy("allow-scripts allow-forms"))
}

func TestValidateAPIExplorerSandboxPolicy_SameOriginAloneAllowed(t *testing.T) {
	// Without allow-scripts, no script in the previewed response can ever
	// run, so the shared origin is inert.
	assert.NoError(t, ValidateAPIExplorerSandboxPolicy("allow-same-origin allow-forms"))
}

func TestValidateAPIExplorerSandboxPolicy_ForbiddenDirectives(t *testing.T) {
	cases := []string{
		"allow-top-navigation",
		"allow-top-navigation-by-user-activation",
		"allow-top-navigation-to-custom-protocols",
		"allow-popups-to-escape-sandbox",
		"allow-modals",
	}
	for _, directive := range cases {
		t.Run(directive, func(t *testing.T) {
			err := ValidateAPIExplorerSandboxPolicy("allow-forms " + directive)
			require.Error(t, err)
			assert.True(t, errors.Is(err, ErrSandboxPolicyForbiddenDirective))
			assert.Contains(t, err.Error(), directive)
		})
	}
}

func TestValidateAPIExplorerSandboxPolicy_UnrecognizedTokenAllowed(t *testing.T) {
	// The validator only refuses the specific tokens it knows are dangerous;
	// it is not a whitelist of every legitimate sandbox directive.
	assert.NoError(t, ValidateAPIExplorerSandboxPolicy("allow-forms allow-downloads"))
}
