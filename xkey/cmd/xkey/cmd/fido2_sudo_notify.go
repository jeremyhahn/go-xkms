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
	"log/slog"
	"os"
	"os/exec"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-xkms/xkey/pkg/notify"
)

// sudoRunuserBin is the runuser(1) binary (util-linux) used to run desktop
// notification tooling as the invoking (non-root) user when "xkey fido2"
// runs under sudo. runuser is present everywhere su is on the distributions
// xkey targets and, unlike su, needs no PAM prompt for a root caller.
const sudoRunuserBin = "runuser"

// buildSudoDialogArgv builds the argv that shows a zenity confirmation
// dialog as sudoUser. Every value from req (operation, RP ID, user name --
// all of which a hostile web page controls via
// navigator.credentials.create()/get()) is placed inside the single
// "--text=<value>" argv element via fmt.Sprintf, never assembled into a
// string a shell will parse: runuser execs "env" and "zenity" directly, no
// "sh -c" is ever in this argv. "--no-markup" additionally stops a caller
// from injecting Pango markup into the rendered dialog text.
func buildSudoDialogArgv(sudoUser string, req *notify.TouchRequest, timeout time.Duration) []string {
	text := fmt.Sprintf(
		"%s request from %s\n\nUser: %s\n\nClick Approve to authorize this action.",
		req.Operation, req.RPID, req.UserName,
	)
	return []string{
		sudoRunuserBin, "-u", sudoUser, "--",
		"env", "DISPLAY=:0",
		"zenity", "--question", "--no-markup",
		"--icon-name=security-high",
		"--title=xKey: Touch Required",
		"--text=" + text,
		"--ok-label=✓ Approve",
		"--cancel-label=✗ Deny",
		"--width=350",
		fmt.Sprintf("--timeout=%d", int(timeout.Seconds())),
	}
}

// buildSudoTouchArgv builds the argv that runs "xkey touch --socket
// <socketPath>" as sudoUser after a dialog is approved. execPath and
// socketPath come from the running process (os.Executable, the resolved
// --socket flag), not from a WebAuthn caller, so there is nothing to
// substitute or sanitize here.
func buildSudoTouchArgv(sudoUser, execPath, socketPath string) []string {
	return []string{sudoRunuserBin, "-u", sudoUser, "--", execPath, "touch", "--socket", socketPath}
}

// buildSudoPassiveArgv builds the argv that sends a passive notify-send
// desktop notification as sudoUser. As with buildSudoDialogArgv, req's
// fields are placed in their own argv elements, never in shell text. The
// "--" before the summary/body pair stops a value that happens to start
// with '-' from being parsed by notify-send as an option.
func buildSudoPassiveArgv(sudoUser, sudoUID string, req *notify.TouchRequest) []string {
	text := fmt.Sprintf("%s request from %s\nUser: %s\nRun: xkey touch", req.Operation, req.RPID, req.UserName)
	return []string{
		sudoRunuserBin, "-u", sudoUser, "--",
		"env", "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/" + sudoUID + "/bus",
		"notify-send", "-u", "critical", "--", "xKey: Touch Required", text,
	}
}

// sudoDialogNotifier shows an interactive zenity confirmation dialog as the
// invoking (non-root) user when "xkey fido2" runs under sudo, then runs the
// touch command as that user if and only if the dialog was approved
// (zenity exits 0). The approve-then-touch sequencing that used to be a
// shell "&&" is ordinary Go control flow here: neither step is ever handed
// to a shell.
type sudoDialogNotifier struct {
	sudoUser   string
	execPath   string
	socketPath string
	timeout    time.Duration
	logger     *slog.Logger
	closed     atomic.Bool
}

// newSudoDialogNotifier creates a sudoDialogNotifier.
func newSudoDialogNotifier(sudoUser, execPath, socketPath string, timeout time.Duration, logger *slog.Logger) *sudoDialogNotifier {
	return &sudoDialogNotifier{
		sudoUser:   sudoUser,
		execPath:   execPath,
		socketPath: socketPath,
		timeout:    timeout,
		logger:     logger,
	}
}

// NotifyTouchRequired shows the zenity dialog and, on approval, runs the
// touch command. It runs asynchronously; execution errors and a denied or
// timed-out dialog are logged but do not block the caller.
func (n *sudoDialogNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	if n.closed.Load() {
		return notify.ErrNotifierClosed
	}

	sanitized := notify.SanitizeTouchRequest(req)

	go func() {
		argv := buildSudoDialogArgv(n.sudoUser, sanitized, n.timeout)
		dialog := exec.Command(argv[0], argv[1:]...)
		dialog.Env = append(os.Environ(), notify.TouchRequestEnv(sanitized)...)
		if err := dialog.Run(); err != nil {
			n.logger.Info("touch dialog denied, timed out, or failed",
				slog.String("sudo_user", n.sudoUser),
				slog.String("error", err.Error()))
			return
		}

		touchArgv := buildSudoTouchArgv(n.sudoUser, n.execPath, n.socketPath)
		touch := exec.Command(touchArgv[0], touchArgv[1:]...)
		if err := touch.Run(); err != nil {
			n.logger.Error("touch approval command failed",
				slog.String("sudo_user", n.sudoUser),
				slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Close is a no-op for sudoDialogNotifier. Subsequent calls to
// NotifyTouchRequired will return notify.ErrNotifierClosed. Close is
// idempotent.
func (n *sudoDialogNotifier) Close() error {
	n.closed.Store(true)
	return nil
}

var _ notify.Notifier = (*sudoDialogNotifier)(nil)

// sudoPassiveNotifier sends a passive notify-send desktop notification as
// the invoking (non-root) user when "xkey fido2" runs under sudo.
type sudoPassiveNotifier struct {
	sudoUser string
	sudoUID  string
	logger   *slog.Logger
	closed   atomic.Bool
}

// newSudoPassiveNotifier creates a sudoPassiveNotifier.
func newSudoPassiveNotifier(sudoUser, sudoUID string, logger *slog.Logger) *sudoPassiveNotifier {
	return &sudoPassiveNotifier{
		sudoUser: sudoUser,
		sudoUID:  sudoUID,
		logger:   logger,
	}
}

// NotifyTouchRequired sends the notify-send notification. It runs
// asynchronously; execution errors are logged but do not block the caller.
func (n *sudoPassiveNotifier) NotifyTouchRequired(req *notify.TouchRequest) error {
	if n.closed.Load() {
		return notify.ErrNotifierClosed
	}

	sanitized := notify.SanitizeTouchRequest(req)

	go func() {
		argv := buildSudoPassiveArgv(n.sudoUser, n.sudoUID, sanitized)
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), notify.TouchRequestEnv(sanitized)...)
		if err := cmd.Run(); err != nil {
			n.logger.Error("notify-send command failed",
				slog.String("sudo_user", n.sudoUser),
				slog.String("error", err.Error()))
		}
	}()

	return nil
}

// Close is a no-op for sudoPassiveNotifier. Subsequent calls to
// NotifyTouchRequired will return notify.ErrNotifierClosed. Close is
// idempotent.
func (n *sudoPassiveNotifier) Close() error {
	n.closed.Store(true)
	return nil
}

var _ notify.Notifier = (*sudoPassiveNotifier)(nil)
