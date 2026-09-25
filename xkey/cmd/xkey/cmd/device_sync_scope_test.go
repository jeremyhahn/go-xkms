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

//go:build ble

package cmd

import (
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
)

func syncScopeTestCmd() *cobra.Command {
	cmd := &cobra.Command{}
	cmd.Flags().Bool("trust-store", false, "")
	cmd.Flags().Bool("oath", false, "")
	cmd.Flags().Bool("passwords", false, "")
	cmd.Flags().Bool("all", false, "")
	return cmd
}

func TestResolveSyncScope_NoFlagsIsAnError(t *testing.T) {
	_, err := resolveSyncScope(syncScopeTestCmd())
	require.ErrorIs(t, err, ErrDeviceSyncNoScope)
}

func TestResolveSyncScope_All(t *testing.T) {
	cmd := syncScopeTestCmd()
	require.NoError(t, cmd.Flags().Set("all", "true"))

	scope, err := resolveSyncScope(cmd)
	require.NoError(t, err)
	require.Equal(t, syncScope{TrustStore: true, OATH: true, Passwords: true}, scope)
}

func TestResolveSyncScope_IndividualFlagsOverrideAll(t *testing.T) {
	cmd := syncScopeTestCmd()
	require.NoError(t, cmd.Flags().Set("all", "true"))
	require.NoError(t, cmd.Flags().Set("oath", "true"))

	scope, err := resolveSyncScope(cmd)
	require.NoError(t, err)
	require.Equal(t, syncScope{OATH: true}, scope,
		"an explicit individual flag selects only itself, ignoring --all")
}

func TestResolveSyncScope_SinglePasswords(t *testing.T) {
	cmd := syncScopeTestCmd()
	require.NoError(t, cmd.Flags().Set("passwords", "true"))

	scope, err := resolveSyncScope(cmd)
	require.NoError(t, err)
	require.Equal(t, syncScope{Passwords: true}, scope)
}

func TestScopeLabels_Empty(t *testing.T) {
	require.Empty(t, syncScope{}.scopeLabels())
}

func TestScopeLabels_AllSelected(t *testing.T) {
	labels := syncScope{TrustStore: true, OATH: true, Passwords: true}.scopeLabels()
	require.Equal(t, []string{"trust-store", "oath", "passwords"}, labels)
}

func TestScopeLabels_SingleSelection(t *testing.T) {
	require.Equal(t, []string{"oath"}, syncScope{OATH: true}.scopeLabels())
}
