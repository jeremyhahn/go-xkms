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
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

var (
	// pinStatusJSON controls JSON output for pin status.
	pinStatusJSON bool
)

// pinStatusInfo is the CLI-facing PIN status representation. The embedded
// stateSourceInfo names which authority answered, so a JSON consumer can
// tell a live daemon reading from a cold data directory apart.
type pinStatusInfo struct {
	// StorePresent reports whether a PIN store exists at all. False means
	// the resolved data directory holds no PIN state directory — a fresh
	// install or a misresolved path — which is a different fact from a
	// present store with no PINs set, and is rendered differently.
	StorePresent bool `json:"store_present"`

	Initialized     bool   `json:"initialized"`
	SOPINSet        bool   `json:"so_pin_set"`
	UserPINSet      bool   `json:"user_pin_set"`
	Strategy        string `json:"strategy"`
	FailedAttempts  int    `json:"failed_attempts"`
	MaxAttempts     int    `json:"max_attempts"`
	IsLocked        bool   `json:"is_locked"`
	RecoverySeconds int    `json:"recovery_seconds"`

	stateSourceInfo
}

// pinStatusCmd shows the current PIN and lockout status.
var pinStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show PIN and lockout status",
	Long: `Show the current PIN configuration and lockout status.

Displays whether SO and User PINs are set, the active strategy,
and lockout status including failed attempt count and recovery time.

When a daemon is running it holds the live PIN state, so the status is read
from it over the IPC socket. With no daemon running the on-disk data
directory is read instead. The reported source names which one answered:
"Initialized: No" from a cold data directory and from a live daemon are
different facts.

Examples:
  # Show PIN status (daemon when running, data directory otherwise)
  xkey pin status

  # Require the running daemon
  xkey pin status --source daemon

  # Read the on-disk data directory even while a daemon runs
  xkey pin status --source disk

  # Name the daemon socket explicitly
  xkey pin status --socket /run/user/1000/xkey/xkey.sock

  # Show status as JSON
  xkey pin status --json`,
	RunE: runPINStatus,
}

func init() {
	pinStatusCmd.Flags().BoolVar(&pinStatusJSON, "json", false,
		"output status as JSON")
	addStateSourceFlags(pinStatusCmd, stateSelectorsLocal)

	pinCmd.AddCommand(pinStatusCmd)
}

func runPINStatus(cmd *cobra.Command, args []string) error {
	out := cmd.OutOrStdout()

	selection, err := stateSourceSelection(cmd, stateSelectorsLocal)
	if err != nil {
		return err
	}

	info, src, err := resolvePINStatus(cmd, selection)
	if err != nil {
		return err
	}
	info.stateSourceInfo = src.info()

	if pinStatusJSON {
		return writeJSON(out, info)
	}

	if !info.StorePresent {
		_, _ = fmt.Fprintln(out, "PIN Status:")
		_, _ = fmt.Fprintln(out, "  PIN store:        not found")
		_, _ = fmt.Fprintln(out)
		_, _ = fmt.Fprintf(out, "No PIN state directory exists under %s.\n", src.Location)
		_, _ = fmt.Fprintln(out, "Run 'xkey pin set-so' to initialize, or point --data-dir /")
		_, _ = fmt.Fprintln(out, "XKEY_DATA_DIR at the device's data directory.")
		_, _ = fmt.Fprintln(out)
		writeSource(out, src)
		return nil
	}

	_, _ = fmt.Fprintln(out, "PIN Status:")
	_, _ = fmt.Fprintf(out, "  Initialized:      %s\n", boolToYesNo(info.Initialized))
	_, _ = fmt.Fprintf(out, "  SO PIN set:       %s\n", boolToYesNo(info.SOPINSet))
	_, _ = fmt.Fprintf(out, "  User PIN set:     %s\n", boolToYesNo(info.UserPINSet))
	_, _ = fmt.Fprintf(out, "  Strategy:         %s\n", info.Strategy)
	_, _ = fmt.Fprintln(out)
	_, _ = fmt.Fprintln(out, "Lockout Status:")
	_, _ = fmt.Fprintf(out, "  Failed attempts:  %d / %d\n", info.FailedAttempts, info.MaxAttempts)
	_, _ = fmt.Fprintf(out, "  Locked:           %s\n", boolToYesNo(info.IsLocked))

	if info.IsLocked && info.RecoverySeconds > 0 {
		duration := time.Duration(info.RecoverySeconds) * time.Second
		_, _ = fmt.Fprintf(out, "  Recovery in:      %s\n", duration.String())
	}

	_, _ = fmt.Fprintln(out)
	writeSource(out, src)

	return nil
}

// resolvePINStatus asks the running daemon first and reads the on-disk data
// directory only when no daemon can answer, returning the labelled source
// alongside the status.
func resolvePINStatus(cmd *cobra.Command, selection string) (pinStatusInfo, stateSource, error) {
	state, socketPath, answered, reason, err := askDaemon(cmd, selection,
		func(client *ipc.Client) (*ipc.PINStateResult, error) {
			return client.StatePIN()
		})
	if err != nil {
		return pinStatusInfo{}, stateSource{}, err
	}
	if answered {
		return pinStatusInfo{
			StorePresent:    true,
			Initialized:     state.Initialized,
			SOPINSet:        state.SOPINSet,
			UserPINSet:      state.UserPINSet,
			Strategy:        state.Strategy,
			FailedAttempts:  state.FailedAttempts,
			MaxAttempts:     state.MaxAttempts,
			IsLocked:        state.IsLocked,
			RecoverySeconds: state.RecoverySeconds,
		}, daemonSource(socketPath), nil
	}

	info, dataDir, err := readPINStatusFromDisk()
	if err != nil {
		return pinStatusInfo{}, stateSource{}, err
	}
	return info, diskSource(dataDir, reason), nil
}

// readPINStatusFromDisk reports the PIN state recorded in the on-disk data
// directory. It remains the correct answer when no daemon holds the device.
func readPINStatusFromDisk() (pinStatusInfo, string, error) {
	// Resolve without creating anything: a status read must not
	// manufacture an empty store that masks a misresolved path.
	dataDir, err := resolvePINDataDirExisting()
	if err != nil {
		return pinStatusInfo{}, "", err
	}

	svc, err := openPINService(dataDir)
	if err != nil {
		var notFound *PINStoreNotFoundError
		if errors.As(err, &notFound) {
			// No store at all. Report the fact instead of a confident
			// "not set": a fresh install and a wrong data directory
			// must not print the same thing.
			return pinStatusInfo{StorePresent: false}, dataDir, nil
		}
		return pinStatusInfo{}, dataDir, err
	}

	info := pinStatusInfo{
		StorePresent: true,
		Initialized:  svc.IsInitialized(),
		SOPINSet:     svc.SOPINSet(),
		UserPINSet:   svc.UserPINSet(),
		Strategy:     string(svc.Strategy()),
	}

	if lockout := svc.GetLockoutStatus(); lockout != nil {
		info.FailedAttempts = lockout.FailedAttempts
		info.MaxAttempts = lockout.MaxAttempts
		info.IsLocked = lockout.IsLocked
		info.RecoverySeconds = lockout.RecoverySeconds
	}

	return info, dataDir, nil
}

// boolToYesNo converts a bool to "Yes" or "No".
func boolToYesNo(b bool) string {
	if b {
		return "Yes"
	}
	return "No"
}
