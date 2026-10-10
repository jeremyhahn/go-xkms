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

package cmd

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/gui"
)

// App access command errors.
var (
	// ErrAppAccessLoadFailed indicates the xKey settings file could not be read.
	ErrAppAccessLoadFailed = errors.New("app-access: failed to load xKey settings")

	// ErrAppAccessSaveFailed indicates the xKey settings file could not be written.
	ErrAppAccessSaveFailed = errors.New("app-access: failed to save xKey settings")
)

// appAccessCmd is the parent command for the local app access setting.
var appAccessCmd = &cobra.Command{
	Use:   "app-access",
	Short: "Let other apps use your keys while xKey is open",
	Long: `Show or change the local app access setting.

When local app access is on, xKey opens a private local socket while it is
open and unlocked. The browser extension's native-messaging host and the
PKCS#11 module reach your keys through it. When it is off (the default),
nothing listens, and "xkey extension serve" refuses to start.

This is the same setting as "Let other apps use my keys while xKey is open"
in the Settings view. A running xKey reads it at startup: change it in
Settings while xKey is open, or restart xKey after changing it here.

Examples:
  xkey app-access status
  xkey app-access enable
  xkey app-access disable`,
}

var appAccessStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show whether local app access is on",
	Args:  cobra.NoArgs,
	RunE:  runAppAccessStatus,
}

var appAccessEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Let other apps use your keys while xKey is open",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return setAppAccess(cmd, true)
	},
}

var appAccessDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Stop other apps from using your keys",
	Args:  cobra.NoArgs,
	RunE: func(cmd *cobra.Command, _ []string) error {
		return setAppAccess(cmd, false)
	},
}

func init() {
	RootCmd.AddCommand(appAccessCmd)
	appAccessCmd.AddCommand(appAccessStatusCmd, appAccessEnableCmd, appAccessDisableCmd)
}

// localAppAccessEnabled reports the saved local app access setting.
func localAppAccessEnabled() (bool, error) {
	cfg, err := gui.LoadGUIConfig()
	if err != nil {
		return false, &SentinelCauseError{Sentinel: ErrAppAccessLoadFailed, Cause: err}
	}
	return cfg.LocalAppAccessEnabled, nil
}

// runAppAccessStatus prints the saved local app access setting.
func runAppAccessStatus(cmd *cobra.Command, _ []string) error {
	enabled, err := localAppAccessEnabled()
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), appAccessState(enabled))
	return nil
}

// setAppAccess saves the local app access setting.
func setAppAccess(cmd *cobra.Command, enabled bool) error {
	cfg, err := gui.LoadGUIConfig()
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrAppAccessLoadFailed, Cause: err}
	}
	cfg.LocalAppAccessEnabled = enabled
	if err := gui.SaveGUIConfig(cfg); err != nil {
		return &SentinelCauseError{Sentinel: ErrAppAccessSaveFailed, Cause: err}
	}
	_, _ = fmt.Fprintln(cmd.OutOrStdout(), appAccessState(enabled))
	return nil
}

// appAccessState is the one-line description of the setting.
func appAccessState(enabled bool) string {
	if enabled {
		return "Local app access: on"
	}
	return "Local app access: off"
}
