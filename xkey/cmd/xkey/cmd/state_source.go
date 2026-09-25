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
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/ipc"
)

// This file is the single place the CLI decides WHO answers a question about
// live device state, and the single place that answer is labelled.
//
// The commands that report PIN, barrier and password-store state used to open
// the on-disk data directory in a separate process. On a running device that
// is the wrong authority: the daemon holds the barrier unsealed and the PIN
// backend open, so the directory reports a fresh, sealed, PIN-less device —
// a false negative on security state.
//
// The rule is: ask the daemon when one is running, fall back to disk when
// none is, and always say which answered. "State: Sealed" from a cold
// directory and from a live daemon are different facts; rendering them
// identically is how the original defect went unnoticed.

// State source selectors accepted by --source.
const (
	// sourceAuto prefers the daemon and falls back to on-disk state.
	sourceAuto = "auto"

	// sourceDaemon requires the running daemon and fails if it cannot answer.
	sourceDaemon = "daemon"

	// sourceDisk reads the on-disk data directory without consulting a daemon.
	sourceDisk = "disk"

	// sourceXKMSd reads from a configured remote xkmsd server.
	sourceXKMSd = "xkmsd"
)

// Human-readable names for the authority that answered.
const (
	sourceLabelDaemon = "daemon"
	sourceLabelDisk   = "data directory"
	sourceLabelXKMSd  = "xkmsd"
)

// Reasons a daemon did not answer, rendered after the source location.
const (
	reasonNoDaemon    = "no daemon running"
	reasonUnsupported = "daemon does not report this state"
	reasonExplicit    = "selected with --source disk"
)

// State source errors.
var (
	// ErrStateInvalidSource indicates an unrecognized --source value.
	ErrStateInvalidSource = errors.New("state: unsupported --source value")

	// ErrStateDaemonRequired indicates --source daemon was requested but the
	// daemon could not answer.
	ErrStateDaemonRequired = errors.New("state: --source daemon requested but the daemon cannot answer")

	// ErrStateDaemonQueryFailed indicates the daemon was reachable but the
	// query failed.
	ErrStateDaemonQueryFailed = errors.New("state: daemon query failed")
)

// stateSource records which authority answered a live-state query and, when
// it was not the daemon, why not.
type stateSource struct {
	// Kind is the human-readable authority name: "daemon", "data directory"
	// or "xkmsd".
	Kind string

	// Location is the socket path, directory or URL that was consulted.
	Location string

	// Reason explains a non-daemon answer. Empty when the daemon answered.
	Reason string
}

// daemonSource labels an answer that came from the running daemon.
func daemonSource(socketPath string) stateSource {
	return stateSource{Kind: sourceLabelDaemon, Location: socketPath}
}

// diskSource labels an answer read from the on-disk data directory.
func diskSource(dataDir, reason string) stateSource {
	return stateSource{Kind: sourceLabelDisk, Location: dataDir, Reason: reason}
}

// xkmsdSource labels an answer that came from a remote xkmsd server.
func xkmsdSource(url string) stateSource {
	return stateSource{Kind: sourceLabelXKMSd, Location: url}
}

// String renders the source as it appears in command output, e.g.
// "daemon (/run/user/1000/xkey/xkey.sock)" or
// "data directory (/home/u/.xkey) — no daemon running".
func (s stateSource) String() string {
	text := s.Kind
	if s.Location != "" {
		text += " (" + s.Location + ")"
	}
	if s.Reason != "" {
		text += " — " + s.Reason
	}
	return text
}

// FromDaemon reports whether the running daemon answered.
func (s stateSource) FromDaemon() bool {
	return s.Kind == sourceLabelDaemon
}

// writeSource prints the source line that every live-state command ends with.
func writeSource(out io.Writer, src stateSource) {
	_, _ = fmt.Fprintf(out, "Source: %s\n", src)
}

// stateSocketPath returns the IPC socket a command should use: the --socket
// flag when given, otherwise the same auto-detected path `xkey fido2 status`
// uses.
func stateSocketPath(cmd *cobra.Command) string {
	if path := strings.TrimSpace(commandFlagString(cmd, "socket")); path != "" {
		return path
	}
	return ipc.DefaultSocketPath()
}

// stateSourceSelection reads and validates the --source flag against the set
// of selectors the command supports. An unset flag selects sourceAuto.
func stateSourceSelection(cmd *cobra.Command, allowed map[string]bool) (string, error) {
	selection := strings.TrimSpace(commandFlagString(cmd, "source"))
	if selection == "" {
		return sourceAuto, nil
	}
	if !allowed[selection] {
		return "", &DetailError{
			Err:    ErrStateInvalidSource,
			Detail: fmt.Sprintf(": %q (want one of %s)", selection, sortedSelectors(allowed)),
		}
	}
	return selection, nil
}

// sortedSelectors renders an allowed-selector set for error messages.
func sortedSelectors(allowed map[string]bool) string {
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// askDaemon runs one live-state query against the daemon named by --socket.
//
// It returns answered=false only when falling back is legitimate: no daemon
// is listening, the daemon does not serve live state, or the caller asked for
// on-disk state explicitly. reason carries which of those it was, so the
// caller can label the fallback. Any other failure is returned as an error
// rather than silently degrading to a stale on-disk answer.
func askDaemon[T any](
	cmd *cobra.Command,
	selection string,
	ask func(*ipc.Client) (T, error),
) (result T, socketPath string, answered bool, reason string, err error) {
	socketPath = stateSocketPath(cmd)

	if selection == sourceDisk {
		return result, socketPath, false, reasonExplicit, nil
	}

	client := ipc.NewClient(socketPath)
	defer func() {
		if closeErr := client.Close(); closeErr != nil {
			err = errors.Join(err, closeErr)
		}
	}()

	result, askErr := ask(client)
	if askErr == nil {
		return result, socketPath, true, "", nil
	}

	switch {
	case errors.Is(askErr, ipc.ErrDaemonNotRunning):
		reason = reasonNoDaemon
	case errors.Is(askErr, ipc.ErrStateUnsupported):
		reason = reasonUnsupported
	default:
		return result, socketPath, false, "", &SentinelCauseError{
			Sentinel: ErrStateDaemonQueryFailed,
			Cause:    askErr,
		}
	}

	if selection == sourceDaemon {
		return result, socketPath, false, reason, &DetailError{
			Err:    ErrStateDaemonRequired,
			Detail: fmt.Sprintf(": %s (%s)", socketPath, reason),
		}
	}

	return result, socketPath, false, reason, nil
}

// addStateSourceFlags declares the --socket and --source flags shared by
// every command that reports live device state.
func addStateSourceFlags(cmd *cobra.Command, allowed map[string]bool) {
	cmd.Flags().String("socket", "", "IPC socket path of the running daemon (default: auto-detect)")
	cmd.Flags().String("source", sourceAuto,
		"Where to read state from: "+sortedSelectors(allowed))
}

// stateSourceInfo is the JSON projection of stateSource. Live-state commands
// embed it so `--json` consumers can tell a live answer from an on-disk one
// as reliably as a human reading the Source line.
type stateSourceInfo struct {
	Source         string `json:"source"`
	SourceLocation string `json:"source_location"`
	SourceReason   string `json:"source_reason,omitempty"`
}

// info returns the JSON projection of the source.
func (s stateSource) info() stateSourceInfo {
	return stateSourceInfo{
		Source:         s.Kind,
		SourceLocation: s.Location,
		SourceReason:   s.Reason,
	}
}

// stateSelectorsLocal is the --source set for commands whose only two
// authorities are the daemon and the on-disk data directory.
var stateSelectorsLocal = map[string]bool{
	sourceAuto:   true,
	sourceDaemon: true,
	sourceDisk:   true,
}

// stateSelectorsWithXKMSd adds the remote xkmsd authority for the one
// command that a configured server can also answer.
var stateSelectorsWithXKMSd = map[string]bool{
	sourceAuto:   true,
	sourceDaemon: true,
	sourceDisk:   true,
	sourceXKMSd:  true,
}
