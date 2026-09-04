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
	"sort"
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

	// ErrUnlockStillLocked indicates the daemon granted the unlock but still
	// reports itself locked. Reporting that as success is a fail-open: every
	// automated flow built on it proceeds on a false premise, and the failure
	// surfaces later in an unrelated subsystem.
	ErrUnlockStillLocked = errors.New("unlock: the daemon is still locked")

	// ErrUnlockIncomplete indicates the unlock released some subsystems and
	// left others locked.
	//
	// The daemon's status action reports the APP LOCK only, so it cannot
	// express this: a PIN that releases the app lock without unsealing the
	// barrier leaves the daemon reporting itself unlocked while the barrier
	// is still sealed — the exact state the reported ceremony ran in. The
	// per-subsystem report in the unlock result is what catches it.
	ErrUnlockIncomplete = errors.New("unlock: incomplete")
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

On success the command names the subsystems it released, for example
"Unlocked: app lock, barrier", and confirms that state against the daemon's own
view of its lock. It exits non-zero when the daemon rejected the PIN, when a
subsystem it governs is still locked, or when the daemon still reports itself
locked — an unlock that reported success while the barrier was still sealed
would make every automated flow proceed on a false premise.

` + pinUsage + `

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

	addPINFlags(unlockCmd)
	unlockCmd.Flags().String("socket", "", "IPC socket path (default: auto-detect)")
}

// resolveUnlockPIN resolves the PIN through the shared CLI resolver and
// applies unlock's own policy: unlocking without a PIN is meaningless, so an
// absent PIN is an error here even though the resolver treats it as a
// legitimate state for callers whose authenticator may have none.
func resolveUnlockPIN(cmd *cobra.Command) (string, error) {
	pin, err := resolvePINInput(cmd)
	if err != nil {
		return "", err
	}
	if pin == "" {
		return "", ErrUnlockMissingPIN
	}
	return pin, nil
}

// runUnlock sends the unlock over IPC and confirms the resulting state.
//
// Success is taken from the unlock result, not from the transport status, and
// is then checked against the daemon's own view of its lock state. An unlock
// that reports success on a daemon that is still locked is worse than a
// failure: the ceremony that follows fails somewhere unrelated ("operation
// denied" from the authenticator) and names the wrong subsystem.
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
	// A client must not infer success from the transport status alone. The
	// unlock result is the daemon's actual answer.
	if resp.Unlock == nil {
		return &DetailError{Err: ErrUnlockFailed, Detail: ": the daemon returned no unlock result"}
	}
	if !resp.Unlock.Success {
		return &DetailError{Err: ErrUnlockFailed, Detail: fmt.Sprintf(": %s", resp.Unlock.Error)}
	}

	// A subsystem the PIN governs that stayed locked is a failure even though
	// the daemon granted the unlock, and it is finer-grained than the status
	// action below can report. Name what did open alongside it: an operator
	// told only "still locked" cannot tell which half worked.
	if len(resp.Unlock.StillLocked) > 0 {
		detail := ": still locked: " + joinSubsystems(resp.Unlock.StillLocked)
		if len(resp.Unlock.Unlocked) > 0 {
			detail += " (unlocked: " + joinSubsystems(resp.Unlock.Unlocked) + ")"
		}
		return &DetailError{Err: ErrUnlockIncomplete, Detail: detail}
	}

	confirmed, err := confirmUnlocked(client)
	if err != nil {
		return err
	}

	// Name the subsystems that were released. A blanket "Unlocked" tells an
	// operator nothing about which of the app lock and the barrier the PIN
	// actually opened; a daemon that does not report them still gets the
	// bare line.
	if len(resp.Unlock.Unlocked) > 0 {
		_, _ = fmt.Fprintf(out, "Unlocked: %s\n", joinSubsystems(resp.Unlock.Unlocked))
	} else {
		_, _ = fmt.Fprintln(out, "Unlocked")
	}
	if !confirmed {
		// The daemon owns no app lock, so there is no state to confirm. Say
		// so rather than letting the bare success line imply one was checked.
		_, _ = fmt.Fprintln(out, "Lock state could not be confirmed: this daemon does not report one")
	}
	return nil
}

// joinSubsystems renders subsystem names in a stable order so the output is
// diffable and scriptable.
func joinSubsystems(names []string) string {
	ordered := make([]string, len(names))
	copy(ordered, names)
	sort.Strings(ordered)
	return strings.Join(ordered, ", ")
}

// confirmUnlocked queries the daemon for its lock state after an unlock it
// reported as successful. It returns whether the state was confirmed unlocked;
// a daemon that owns no app lock reports no lock state and confirms nothing,
// which is not an error. A daemon that reports itself still locked is.
func confirmUnlocked(client *ipc.Client) (bool, error) {
	resp, err := client.Status()
	if err != nil {
		return false, &SentinelCauseError{Sentinel: ErrUnlockFailed, Cause: err}
	}
	if resp.Status == ipc.StatusError {
		return false, &DetailError{Err: ErrUnlockFailed, Detail: fmt.Sprintf(": status query failed: %s", resp.Error)}
	}

	switch resp.Action {
	case ipc.ActionUnlocked:
		return true, nil
	case ipc.ActionLocked:
		return false, ErrUnlockStillLocked
	default:
		return false, nil
	}
}
