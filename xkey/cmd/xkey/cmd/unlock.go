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
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// This file wires the app unlock to a CLI verb.
//
// The IPC transport (ipc.Client.Unlock, MessageTypeUnlock, UnlockHandler) all
// existed already; nothing reached it from the command line, so a locked
// instance could only be unlocked through the GUI. That blocks exactly the
// automation xkey is meant to support: a locked daemon refuses CTAP2
// operations with "operation denied", which reads like an authenticator
// rejection rather than "this app is locked".

var (
	// ErrUnlockDaemonNotRunning indicates no daemon is listening.
	ErrUnlockDaemonNotRunning = errors.New("unlock: daemon is not running")

	// ErrUnlockMissingPIN indicates no PIN was supplied.
	ErrUnlockMissingPIN = errors.New("unlock: a PIN is required (--pin, --pin-stdin, or XKEY_PIN)")

	// ErrUnlockFailed indicates the daemon rejected the unlock.
	ErrUnlockFailed = errors.New("unlock: failed")
)

// unlockCmd unlocks a running xKey instance over IPC.
var unlockCmd = &cobra.Command{
	Use:   "unlock",
	Short: "Unlock a running xKey instance",
	Long: `Unlock a running xKey instance by sending its user PIN over IPC.

A locked instance refuses CTAP2 operations, which surfaces to a caller as
"operation denied" rather than anything mentioning the lock — so unlocking is
usually what is needed when an enrollment is denied by a daemon that is
otherwise running.

The PIN may be supplied three ways, in precedence order:

  --pin-stdin      read the PIN from standard input (preferred: it keeps the
                   PIN out of the process list and the shell history)
  XKEY_PIN         environment variable
  --pin            flag value (visible in 'ps'; use for local development only)

Examples:
  # Preferred
  printf '%s' "$PIN" | xkey unlock --pin-stdin

  # Environment
  XKEY_PIN="$PIN" xkey unlock

  # Explicit flag (development)
  xkey unlock --pin 1234`,
	Args: cobra.NoArgs,
	RunE: runUnlock,
}

func init() {
	RootCmd.AddCommand(unlockCmd)

	unlockCmd.Flags().String("pin", "", "User PIN (visible in the process list; prefer --pin-stdin)")
	unlockCmd.Flags().Bool("pin-stdin", false, "Read the user PIN from standard input")
	unlockCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")
}

// readAllStdin reads the whole of standard input.
func readAllStdin() ([]byte, error) {
	return io.ReadAll(os.Stdin)
}

// resolveUnlockPIN returns the PIN from the highest-precedence source
// supplied. Reading from stdin is preferred because a PIN passed as a flag is
// visible to every process on the host via /proc.
func resolveUnlockPIN(cmd *cobra.Command) (string, error) {
	if fromStdin, _ := cmd.Flags().GetBool("pin-stdin"); fromStdin {
		data, err := readAllStdin()
		if err != nil {
			return "", &SentinelCauseError{Sentinel: ErrUnlockFailed, Cause: err}
		}
		if pin := strings.TrimRight(string(data), "\r\n"); pin != "" {
			return pin, nil
		}
		return "", ErrUnlockMissingPIN
	}
	if pin := os.Getenv("XKEY_PIN"); pin != "" {
		return pin, nil
	}
	if pin, _ := cmd.Flags().GetString("pin"); pin != "" {
		return pin, nil
	}
	return "", ErrUnlockMissingPIN
}

// runUnlock sends the unlock over IPC.
func runUnlock(cmd *cobra.Command, _ []string) error {
	out := cmd.OutOrStdout()

	pin, err := resolveUnlockPIN(cmd)
	if err != nil {
		return err
	}

	socketPath, _ := cmd.Flags().GetString("socket")
	if socketPath == "" {
		socketPath = ipc.DefaultSocketPath()
	}

	client := ipc.NewClient(socketPath)
	defer func() { _ = client.Close() }()

	resp, err := client.Unlock(pin)
	if err != nil {
		if errors.Is(err, ipc.ErrDaemonNotRunning) {
			return ErrUnlockDaemonNotRunning
		}
		return &SentinelCauseError{Sentinel: ErrUnlockFailed, Cause: err}
	}
	if resp.Status == ipc.StatusError {
		// The daemon's message is reported verbatim: a wrong PIN and a
		// daemon that cannot unlock at all are different problems.
		return &DetailError{Err: ErrUnlockFailed, Detail: fmt.Sprintf(": %s", resp.Error)}
	}

	_, _ = fmt.Fprintln(out, "Unlocked")
	return nil
}
