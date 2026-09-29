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
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
)

// CommandNotifier runs an operator-configured command to deliver touch
// notifications. The command template is split into argv ONCE, at
// construction, using shell-like whitespace/quote rules (see
// splitCommandTemplate), and that argv is run exactly as given: no shell,
// no wrapper, and no substitution ever changes it.
//
// Request data (operation, RP ID, RP name, user name) reaches the command
// through exactly one channel: the environment variables XKEY_OPERATION,
// XKEY_RP_ID, XKEY_RP_NAME, and XKEY_USER_NAME. There is no argv
// substitution to attack, so there is nothing for an earlier design's
// escaping rules to get wrong: no denylist of shell interpreters
// (bash -lc, sh -ec), wrappers (env, nice, nohup, sudo, doas, runuser --),
// other language interpreters (python3 -c, perl -e, node -e, pwsh
// -Command), or flag injection into a non-shell command (notify-send with
// a UserName of "--app-name=x") can reopen a substitution channel that
// does not exist. RPName and UserName originate from the calling web
// page's navigator.credentials.create()/get() call and are never trusted;
// they reach the command only as environment variable values, where a
// shell that reads them with "$XKEY_RP_ID" (in double quotes) expands the
// value without re-parsing it as code.
//
// NewCommandNotifier refuses a template containing %o, %r, %n, or %u: those
// placeholders substituted into argv, in an earlier version of this type,
// making a value part of an argv element. An operator upgrading from that
// version gets a loud, typed error at startup (ErrTemplatePlaceholder)
// instead of a silent behavior change.
//
// The command runs asynchronously in a goroutine. Execution errors are
// logged but do not block the caller.
type CommandNotifier struct {
	// argv is the operator's command, split once at construction. It never
	// changes: NotifyTouchRequired runs it exactly as given.
	argv []string

	logger *slog.Logger
	closed atomic.Bool
}

// NewCommandNotifier creates a CommandNotifier with the given command
// template. The template is split into argv immediately; NotifyTouchRequired
// never invokes a shell and never substitutes into argv. Returns
// ErrInvalidCommand if the command string is empty, contains only
// whitespace, or splits into zero argv elements. Returns ErrUnterminatedQuote
// if the template has an opening quote with no matching close. Returns
// ErrTemplatePlaceholder if the template contains %o, %r, %n, or %u: those
// substitution placeholders were removed; request data reaches the command
// through the XKEY_OPERATION, XKEY_RP_ID, XKEY_RP_NAME, XKEY_USER_NAME
// environment variables instead, for example
// sh -c 'notify-send "Touch required" "$XKEY_RP_ID"'.
func NewCommandNotifier(command string, logger *slog.Logger) (*CommandNotifier, error) {
	if strings.TrimSpace(command) == "" {
		return nil, ErrInvalidCommand
	}

	argv, err := splitCommandTemplate(command)
	if err != nil {
		return nil, err
	}
	if len(argv) == 0 {
		return nil, ErrInvalidCommand
	}

	for _, arg := range argv {
		if containsTemplatePlaceholder(arg) {
			return nil, ErrTemplatePlaceholder
		}
	}

	return &CommandNotifier{
		argv:   argv,
		logger: logger,
	}, nil
}

// templatePlaceholders are the substitution placeholders a notify-command
// template must not contain. See ErrTemplatePlaceholder.
var templatePlaceholders = [...]string{"%o", "%r", "%n", "%u"}

// containsTemplatePlaceholder reports whether arg contains any of the
// retired %o/%r/%n/%u placeholders.
func containsTemplatePlaceholder(arg string) bool {
	for _, p := range templatePlaceholders {
		if strings.Contains(arg, p) {
			return true
		}
	}
	return false
}

// splitCommandTemplate splits a notify-command template into argv using
// whitespace as the separator, honoring single and double quoted segments
// so an operator can include a literal space in one argument (for example a
// --text="..." value), and a backslash to escape the following character.
// Inside single quotes every character is literal. Inside double quotes a
// backslash escapes only '"' and '\'; every other character, including
// backslash before any other character, is literal. This is a subset of
// POSIX shell word-splitting: no variable expansion, globbing, or command
// substitution is performed, and structural shell metacharacters (;, |, &,
// $, `, >, <) are ordinary characters here, never interpreted, because the
// result is passed directly to exec.Command and no shell ever sees it.
func splitCommandTemplate(tmpl string) ([]string, error) {
	var args []string
	var cur strings.Builder
	hasCur := false

	runes := []rune(tmpl)
	n := len(runes)
	i := 0
	for i < n {
		c := runes[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			if hasCur {
				args = append(args, cur.String())
				cur.Reset()
				hasCur = false
			}
			i++

		case c == '\'':
			hasCur = true
			i++
			start := i
			for i < n && runes[i] != '\'' {
				i++
			}
			if i >= n {
				return nil, &SentinelCauseError{Sentinel: ErrUnterminatedQuote, Cause: &MessageError{Msg: "opening ' has no matching close"}}
			}
			cur.WriteString(string(runes[start:i]))
			i++ // skip closing quote

		case c == '"':
			hasCur = true
			i++
			for i < n && runes[i] != '"' {
				if runes[i] == '\\' && i+1 < n && (runes[i+1] == '"' || runes[i+1] == '\\') {
					cur.WriteRune(runes[i+1])
					i += 2
					continue
				}
				cur.WriteRune(runes[i])
				i++
			}
			if i >= n {
				return nil, &SentinelCauseError{Sentinel: ErrUnterminatedQuote, Cause: &MessageError{Msg: `opening " has no matching close`}}
			}
			i++ // skip closing quote

		case c == '\\' && i+1 < n:
			hasCur = true
			cur.WriteRune(runes[i+1])
			i += 2

		default:
			hasCur = true
			cur.WriteRune(c)
			i++
		}
	}
	if hasCur {
		args = append(args, cur.String())
	}
	return args, nil
}

// NotifyTouchRequired runs the operator's argv exactly as configured (never
// via a shell, never substituted) asynchronously, with req's fields
// available to it only as the XKEY_OPERATION/XKEY_RP_ID/XKEY_RP_NAME/
// XKEY_USER_NAME environment variables. Execution errors are logged but do
// not block the caller.
func (n *CommandNotifier) NotifyTouchRequired(req *TouchRequest) error {
	if n.closed.Load() {
		return ErrNotifierClosed
	}

	sanitized := SanitizeTouchRequest(req)

	go func() {
		cmd := exec.Command(n.argv[0], n.argv[1:]...)
		cmd.Env = append(os.Environ(), TouchRequestEnv(sanitized)...)
		if err := cmd.Run(); err != nil {
			n.logger.Error("Notification command failed",
				slog.String("argv", strings.Join(n.argv, " ")),
				slog.String("error", err.Error()),
				slog.String("operation", sanitized.Operation),
				slog.String("rp_id", sanitized.RPID),
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
