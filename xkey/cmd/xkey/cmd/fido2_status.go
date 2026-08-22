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

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// This file gives `xkey fido2` real subcommands.
//
// `fido2` runs the virtual authenticator in the FOREGROUND. Before this, it
// accepted and ignored any positional argument, so `xkey fido2 status` did not
// report status — it silently started a SECOND authenticator and blocked
// forever. A typo could leave an extra virtual security key attached to the
// host, which then makes every enrollment ambiguous ("several authenticators
// are attached"). An unrecognised subcommand must fail, not start a daemon.
//
// `start` is registered explicitly so existing `xkey fido2 start ...`
// invocations keep working now that bare `fido2` rejects stray arguments.

var (
	// ErrFIDO2StatusDaemonNotRunning indicates no daemon is listening.
	ErrFIDO2StatusDaemonNotRunning = errors.New("fido2: daemon is not running (start with 'xkey fido2')")

	// ErrFIDO2StatusFailed indicates the status query failed.
	ErrFIDO2StatusFailed = errors.New("fido2: status query failed")
)

// fido2StartCmd runs the virtual authenticator. It is an explicit alias for
// the bare `fido2` command so the documented invocation keeps working.
var fido2StartCmd = &cobra.Command{
	Use:   "start",
	Short: "Run the FIDO2/WebAuthn virtual USB device (same as 'xkey fido2')",
	Long: `Run the FIDO2/WebAuthn virtual USB device in the foreground.

This is an explicit alias for 'xkey fido2'. It exists so that the daemon has a
named verb alongside 'status', and so an unrecognised subcommand fails instead
of silently starting a second authenticator.`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return fido2Cmd.RunE(cmd, args)
	},
}

// fido2StatusCmd reports whether the virtual authenticator is running.
var fido2StatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Report whether the FIDO2 virtual device daemon is running",
	Long: `Query the running xKey FIDO2 daemon over IPC and report its state.

Exits non-zero when no daemon is listening, so scripts can gate on it.`,
	Args: cobra.NoArgs,
	RunE: runFIDO2Status,
}

func init() {
	fido2Cmd.AddCommand(fido2StartCmd)
	fido2Cmd.AddCommand(fido2StatusCmd)

	fido2StatusCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")

	// Inherit the daemon's flags so `fido2 start` accepts everything bare
	// `fido2` does. Without this, moving an existing invocation to the named
	// verb would break on unknown flags.
	fido2StartCmd.Flags().AddFlagSet(fido2Cmd.Flags())

	// With start/status registered, a stray argument on bare `fido2` is a
	// mistake rather than a daemon launch.
	fido2Cmd.Args = cobra.NoArgs
}

// runFIDO2Status queries the daemon over IPC.
func runFIDO2Status(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()
	socketPath, _ := cmd.Flags().GetString("socket")
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	client := ipc.NewClient(socketPath)
	defer func() { _ = client.Close() }()

	resp, err := client.Status()
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return ErrFIDO2StatusDaemonNotRunning
		}
		return &SentinelCauseError{Sentinel: ErrFIDO2StatusFailed, Cause: err}
	}
	if resp.Status == ipc.StatusError {
		return &DetailError{Err: ErrFIDO2StatusFailed, Detail: fmt.Sprintf(": %s", resp.Error)}
	}

	_, _ = fmt.Fprintf(out, "FIDO2 daemon: running (%s)\n", resp.Action)
	_, _ = fmt.Fprintf(out, "Socket:       %s\n", socketPath)
	return nil
}
