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

package notify

import (
	"log/slog"
	"os/exec"
	"strings"
	"sync/atomic"
)

// CommandNotifier executes a user-provided shell command to deliver touch
// notifications. The command string supports template variables that are
// substituted at notification time:
//
//   - %o: operation ("register" or "authenticate")
//   - %r: relying party ID
//   - %n: relying party display name
//   - %u: user display name
//
// The command is executed asynchronously in a goroutine. Execution errors
// are logged but do not block the caller.
type CommandNotifier struct {
	command string
	logger  *slog.Logger
	closed  atomic.Bool
}

// NewCommandNotifier creates a CommandNotifier with the given command template.
// Returns ErrInvalidCommand if the command string is empty or contains only
// whitespace.
func NewCommandNotifier(command string, logger *slog.Logger) (*CommandNotifier, error) {
	if strings.TrimSpace(command) == "" {
		return nil, ErrInvalidCommand
	}
	return &CommandNotifier{
		command: command,
		logger:  logger,
	}, nil
}

// expandTemplate replaces template variables in the command string with
// values from the touch request.
func expandTemplate(tmpl string, req *TouchRequest) string {
	r := strings.NewReplacer(
		"%o", req.Operation,
		"%r", req.RPID,
		"%n", req.RPName,
		"%u", req.UserName,
	)
	return r.Replace(tmpl)
}

// NotifyTouchRequired expands the command template and executes it
// asynchronously. Errors from command execution are logged but do not
// block the caller.
func (n *CommandNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if n.closed.Load() {
		return ErrNotifierClosed
	}

	expanded := expandTemplate(n.command, req)

	go func() {
		cmd := exec.Command("sh", "-c", expanded)
		if err := cmd.Run(); err != nil {
			n.logger.Error("Notification command failed",
				slog.String("command", expanded),
				slog.String("error", err.Error()),
				slog.String("operation", req.Operation),
				slog.String("rp_id", req.RPID),
			)
		}
	}()

	return nil
}

// Close is a no-op for CommandNotifier. Subsequent calls to
// NotifyTouchRequired will return ErrNotifierClosed. Close is idempotent.
func (n *CommandNotifier) Close() error {
	n.closed.Store(true)
	return nil
}
