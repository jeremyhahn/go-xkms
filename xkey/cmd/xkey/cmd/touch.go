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

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
	"github.com/spf13/cobra"
)

// Touch command errors.
var (
	ErrTouchDaemonNotRunning = errors.New("touch: daemon is not running (start with 'xkey fido2')")
	ErrTouchFailed           = errors.New("touch: operation failed")
)

// touchCmd approves a pending user presence request or types a password via the
// virtual keyboard. It communicates with the running xkey daemon over IPC.
var touchCmd = &cobra.Command{
	Use:   "touch",
	Short: "Approve pending user presence or type a password",
	Long: `Simulate touching a physical security key.

When the xkey daemon has a pending WebAuthn user presence request, this
command approves it. When no request is pending and a default password is
configured, it types the default password via the virtual keyboard.

Use --password to explicitly type a named password from the static password
store.

This command communicates with the running xkey daemon via IPC.

Examples:
  # Approve pending WebAuthn request or type default password
  xkey touch

  # Type a specific named password
  xkey touch --password "DatabaseProd"

  # Custom socket path
  xkey touch --socket /tmp/xkey.sock`,
	RunE: runTouch,
}

func init() {
	RootCmd.AddCommand(touchCmd)

	touchCmd.Flags().String("password", "", "Name of password to type")
	touchCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")
}

// runTouch executes the touch command. It connects to the daemon via IPC and
// either approves a pending user presence request or types a named password.
func runTouch(cmd *cobra.Command, args []string) (err error) {
	out := cmd.OutOrStdout()
	passwordName, _ := cmd.Flags().GetString("password")
	socketPath, _ := cmd.Flags().GetString("socket")

	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	client := ipc.NewClient(socketPath)
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	var resp *ipc.Response

	if passwordName != "" {
		resp, err = client.TypePassword(passwordName)
	} else {
		resp, err = client.Touch()
	}

	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return ErrTouchDaemonNotRunning
		}
		return &SentinelCauseError{Sentinel: ErrTouchFailed, Cause: err}
	}

	if resp.Status == ipc.StatusError {
		return &DetailError{Err: ErrTouchFailed, Detail: fmt.Sprintf(": %s", resp.Error)}
	}

	// Print action result.
	switch resp.Action {
	case ipc.ActionApprovedUP:
		_, _ = fmt.Fprintln(out, "User presence approved")
	case ipc.ActionTypedPassword:
		_, _ = fmt.Fprintln(out, "Password typed")
	case ipc.ActionNoPending:
		_, _ = fmt.Fprintln(out, "No pending request")
	default:
		_, _ = fmt.Fprintf(out, "OK: %s\n", resp.Action)
	}

	return nil
}
