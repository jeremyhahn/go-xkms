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

package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// Test seams for interactive secret resolution. Production code always
// reads from the process stdin; tests substitute a strings.Reader and
// force the non-terminal path.
var (
	// secretStdin is the reader used when a secret is piped or read as a
	// plain line (non-terminal stdin).
	secretStdin io.Reader = os.Stdin

	// secretStdinFd returns the file descriptor used for terminal detection
	// and no-echo password reads.
	secretStdinFd = func() int { return int(os.Stdin.Fd()) }

	// isTerminalFn reports whether the descriptor is an interactive terminal.
	isTerminalFn = term.IsTerminal

	// readPasswordFn reads a secret from the terminal without echoing it.
	readPasswordFn = term.ReadPassword
)

// resolveSecret resolves a sensitive value using the canonical xkmsctl
// precedence:
//
//  1. A non-empty flag value that is not "-" is used verbatim.
//  2. The literal value "-" reads the entire stdin (trailing newline trimmed).
//  3. An empty value prompts interactively without echo when stdin is a
//     terminal, and otherwise reads a single line from stdin (so scripted
//     pipelines work without a TTY).
//
// The prompt is written to stderr so command output remains clean for
// --output json pipelines.
func resolveSecret(value, prompt string) (string, error) {
	if value == "-" {
		data, err := io.ReadAll(secretStdin)
		if err != nil {
			return "", &WrappedError{Sentinel: ErrReadSecretFailed, Err: err}
		}
		return strings.TrimRight(string(data), "\r\n"), nil
	}
	if value != "" {
		return value, nil
	}

	fd := secretStdinFd()
	if isTerminalFn(fd) {
		_, _ = fmt.Fprintf(os.Stderr, "%s: ", prompt)
		secret, err := readPasswordFn(fd)
		_, _ = fmt.Fprintln(os.Stderr)
		if err != nil {
			return "", &WrappedError{Sentinel: ErrReadSecretFailed, Err: err}
		}
		return string(secret), nil
	}

	line, err := bufio.NewReader(secretStdin).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", &WrappedError{Sentinel: ErrReadSecretFailed, Err: err}
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// resolvePIN resolves a PIN using resolveSecret and rejects empty results,
// since every PIN verb requires a non-empty credential.
func resolvePIN(value, prompt string) (string, error) {
	pin, err := resolveSecret(value, prompt)
	if err != nil {
		return "", err
	}
	if pin == "" {
		return "", ErrPINEmpty
	}
	return pin, nil
}
