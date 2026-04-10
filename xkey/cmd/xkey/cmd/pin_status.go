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
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var (
	// pinStatusJSON controls JSON output for pin status.
	pinStatusJSON bool
)

// pinStatusInfo is the CLI-facing PIN status representation.
type pinStatusInfo struct {
	Initialized     bool   `json:"initialized"`
	SOPINSet        bool   `json:"so_pin_set"`
	UserPINSet      bool   `json:"user_pin_set"`
	Strategy        string `json:"strategy"`
	FailedAttempts  int    `json:"failed_attempts"`
	MaxAttempts     int    `json:"max_attempts"`
	IsLocked        bool   `json:"is_locked"`
	RecoverySeconds int    `json:"recovery_seconds"`
}

// pinStatusCmd shows the current PIN and lockout status.
var pinStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show PIN and lockout status",
	Long: `Show the current PIN configuration and lockout status.

Displays whether SO and User PINs are set, the active strategy,
and lockout status including failed attempt count and recovery time.

Examples:
  # Show PIN status
  xkey pin status

  # Show status as JSON
  xkey pin status --json`,
	RunE: runPINStatus,
}

func init() {
	pinStatusCmd.Flags().BoolVar(&pinStatusJSON, "json", false,
		"output status as JSON")

	pinCmd.AddCommand(pinStatusCmd)
}

func runPINStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	// Resolve data directory.
	dataDir, err := resolvePINDataDir()
	if err != nil {
		return err
	}

	// Create PIN service.
	svc, err := createPINService(dataDir)
	if err != nil {
		return err
	}

	lockout := svc.GetLockoutStatus()

	info := pinStatusInfo{
		Initialized: svc.IsInitialized(),
		SOPINSet:    svc.SOPINSet(),
		UserPINSet:  svc.UserPINSet(),
		Strategy:    string(svc.Strategy()),
	}

	if lockout != nil {
		info.FailedAttempts = lockout.FailedAttempts
		info.MaxAttempts = lockout.MaxAttempts
		info.IsLocked = lockout.IsLocked
		info.RecoverySeconds = lockout.RecoverySeconds
	}

	if pinStatusJSON {
		return writeJSON(out, info)
	}

	fmt.Fprintln(out, "PIN Status:")
	fmt.Fprintf(out, "  Initialized:      %s\n", boolToYesNo(info.Initialized))
	fmt.Fprintf(out, "  SO PIN set:       %s\n", boolToYesNo(info.SOPINSet))
	fmt.Fprintf(out, "  User PIN set:     %s\n", boolToYesNo(info.UserPINSet))
	fmt.Fprintf(out, "  Strategy:         %s\n", info.Strategy)
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Lockout Status:")
	fmt.Fprintf(out, "  Failed attempts:  %d / %d\n", info.FailedAttempts, info.MaxAttempts)
	fmt.Fprintf(out, "  Locked:           %s\n", boolToYesNo(info.IsLocked))

	if info.IsLocked && info.RecoverySeconds > 0 {
		duration := time.Duration(info.RecoverySeconds) * time.Second
		fmt.Fprintf(out, "  Recovery in:      %s\n", duration.String())
	}

	return nil
}

// boolToYesNo converts a bool to "Yes" or "No".
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
