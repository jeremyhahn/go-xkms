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

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setVar sets a package-level flag variable for the duration of the test.
func setVar[T any](t *testing.T, p *T, v T) {
	t.Helper()
	saved := *p
	*p = v
	t.Cleanup(func() { *p = saved })
}

// runWithTemplateFlag runs run as if the user had passed --template value,
// so the flag reads as explicitly set. target is the variable the real
// command binds the flag to; it is restored when the test ends.
func runWithTemplateFlag(t *testing.T, run func(*cobra.Command, []string) error, target *string, value string) error {
	t.Helper()
	setVar(t, target, *target)
	cmd := &cobra.Command{}
	cmd.Flags().StringVar(target, "template", "rsa2048", "")
	require.NoError(t, cmd.Flags().Set("template", value))
	return run(cmd, nil)
}

// TestRunIAKCreate_ExplicitInvalidTemplate proves an explicitly set unknown
// template is still refused with the typed error.
func TestRunIAKCreate_ExplicitInvalidTemplate(t *testing.T) {
	err := runWithTemplateFlag(t, runIAKCreate, &iakCreateTemplate, "dsa1024")
	assert.ErrorIs(t, err, ErrInvalidIAKTemplate)
}

// TestRunIDevIDCreate_ExplicitInvalidTemplate proves an explicitly set
// unknown template is still refused with the typed error.
func TestRunIDevIDCreate_ExplicitInvalidTemplate(t *testing.T) {
	err := runWithTemplateFlag(t, runIDevIDCreate, &idevidCreateTemplate, "dsa1024")
	assert.ErrorIs(t, err, ErrInvalidIDevIDTemplate)
}
