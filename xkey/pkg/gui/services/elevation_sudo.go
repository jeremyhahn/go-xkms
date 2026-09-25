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

package services

import (
	"bytes"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"

	secure "github.com/jeremyhahn/go-xkms/sdk/go/secure"

	"github.com/jeremyhahn/go-enclave"
)

// SudoElevator uses sudo to re-execute the current binary with CLI
// subcommands to perform privileged operations. The user's password
// is piped via stdin to avoid shell history exposure.
type SudoElevator struct {
	log      *slog.Logger
	execPath string
	password *secure.Buffer
}

// NewSudoElevator creates a SudoElevator with the given password that
// re-invokes the current executable via sudo with CLI subcommands. A nil
// password pipes no password bytes on Run, which is valid for NOPASSWD
// sudoers configurations and for callers that only need IsAvailable.
func NewSudoElevator(password *secure.Buffer) *SudoElevator {
	path, _ := os.Executable()
	log := slog.Default().With("component", "sudo_elevator")

	log.Debug("SudoElevator created",
		"exec_path", path,
		"exec_found", path != "")

	return &SudoElevator{
		log:      log,
		execPath: path,
		password: password,
	}
}

// newSudoBufferFromString seals s into a *secure.Buffer for NewSudoElevator.
// An empty s returns (nil, nil): NewSudoElevator and Run treat a nil
// password as "no password set" rather than an empty one, matching how the
// wails request boundary represents "not supplied".
func newSudoBufferFromString(s string) (*secure.Buffer, error) {
	if s == "" {
		return nil, nil
	}
	return secure.NewBufferFromBytes([]byte(s))
}

// IsAvailable returns true if both sudo and the current executable path
// are available.
func (e *SudoElevator) IsAvailable() bool {
	if e.execPath == "" {
		e.log.Debug("IsAvailable: executable path not found")
		return false
	}
	_, err := sudoLookPath("sudo")
	available := err == nil

	e.log.Debug("IsAvailable check",
		"sudo_available", available,
		"exec_path", e.execPath)

	return available
}

// Run executes the current binary via sudo with --no-gui and the given
// CLI arguments. The sudo password and any stdin data are passed on stdin
// to avoid leaking secrets in the process argument list. After execution
// completes, the assembled stdin payload is wiped from memory.
func (e *SudoElevator) Run(args []string, stdinData []byte) ([]byte, error) {
	if e.execPath == "" {
		e.log.Debug("Run aborted: executable path not found")
		return nil, ErrElevationUnavailable
	}

	if !e.IsAvailable() {
		e.log.Debug("Run aborted: sudo unavailable")
		return nil, ErrSudoUnavailable
	}

	// Build stdin: password + newline + stdinData. A nil password (no
	// password configured) writes no password bytes, matching the
	// historical behavior for NOPASSWD sudoers configurations where sudo
	// never reads the line. Assembled into a caller-owned slice (rather
	// than a bytes.Buffer, whose read cursor would leave nothing to wipe
	// once sudo has consumed it) so it can be wiped after the pipe closes
	// -- the pageable copy cmd.Stdin requires cannot be swept the way the
	// password's own enclave can.
	var stdin []byte
	if e.password != nil {
		if err := e.password.WithBytes(func(b []byte) error {
			stdin = append(stdin, b...)
			return nil
		}); err != nil {
			return nil, &DetailError{Err: ErrElevationFailed, Detail: fmt.Sprintf(": %v", err)}
		}
	}
	stdin = append(stdin, '\n')
	stdin = append(stdin, stdinData...)
	defer secure.Wipe(stdin)

	e.log.Debug("Run executing sudo command",
		"args", args,
		"exec_path", e.execPath,
		"stdin_data_length", len(stdinData))

	// Build: sudo -S <execPath> --no-gui <args...>
	cmdArgs := make([]string, 0, 3+len(args))
	cmdArgs = append(cmdArgs, "-S", e.execPath, "--no-gui")
	cmdArgs = append(cmdArgs, args...)

	cmd := sudoCommand("sudo", cmdArgs...) // #nosec G204 -- re-invoking self
	cmd.Stdin = bytes.NewReader(stdin)

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	if err != nil {
		stderrStr := strings.TrimSpace(stderr.String())

		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode := exitErr.ExitCode()

			e.log.Debug("Run failed with exit error",
				"args", args,
				"exit_code", exitCode,
				"stderr", stderrStr,
				"error", err)

			// sudo returns exit code 1 when the password is incorrect.
			if exitCode == 1 {
				return nil, ErrElevationDenied
			}

			return nil, &DetailError{Err: ErrElevationFailed, Detail: fmt.Sprintf(": exit code %d: %s", exitCode, stderrStr)}
		}

		e.log.Debug("Run failed",
			"args", args,
			"stderr", stderrStr,
			"error", err)

		return nil, &DetailError{Err: ErrElevationFailed, Detail: fmt.Sprintf(": %v: %s", err, stderrStr)}
	}

	e.log.Debug("Run completed successfully",
		"args", args,
		"stdout_length", stdout.Len())

	return stdout.Bytes(), nil
}

// zeroBytes overwrites a byte slice with zeros to clear sensitive data
// from memory.
func zeroBytes(b []byte) {
	enclave.Wipe(b)
}
