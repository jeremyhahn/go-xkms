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
)

// SudoElevator uses sudo to re-execute the current binary with CLI
// subcommands to perform privileged operations. The user's password
// is piped via stdin to avoid shell history exposure.
type SudoElevator struct {
	log      *slog.Logger
	execPath string
	password []byte
}

// NewSudoElevator creates a SudoElevator with the given password that
// re-invokes the current executable via sudo with CLI subcommands.
func NewSudoElevator(password string) *SudoElevator {
	path, _ := os.Executable()
	log := slog.Default().With("component", "sudo_elevator")

	log.Debug("SudoElevator created",
		"exec_path", path,
		"exec_found", path != "")

	return &SudoElevator{
		log:      log,
		execPath: path,
		password: []byte(password),
	}
}

// IsAvailable returns true if both sudo and the current executable path
// are available.
func (e *SudoElevator) IsAvailable() bool {
	if e.execPath == "" {
		e.log.Debug("IsAvailable: executable path not found")
		return false
	}
	_, err := exec.LookPath("sudo")
	available := err == nil

	e.log.Debug("IsAvailable check",
		"sudo_available", available,
		"exec_path", e.execPath)

	return available
}

// Run executes the current binary via sudo with --no-gui and the given
// CLI arguments. The sudo password and any stdin data are passed on stdin
// to avoid leaking secrets in the process argument list. After execution
// completes, the password is zeroed in memory.
func (e *SudoElevator) Run(args []string, stdinData []byte) ([]byte, error) {
	if e.execPath == "" {
		e.log.Debug("Run aborted: executable path not found")
		return nil, ErrElevationUnavailable
	}

	if !e.IsAvailable() {
		e.log.Debug("Run aborted: sudo unavailable")
		return nil, ErrSudoUnavailable
	}

	// Build stdin: password + newline + stdinData
	var stdinBuf bytes.Buffer
	stdinBuf.Write(e.password)
	stdinBuf.WriteByte('\n')
	stdinBuf.Write(stdinData)

	e.log.Debug("Run executing sudo command",
		"args", args,
		"exec_path", e.execPath,
		"stdin_data_length", len(stdinData))

	// Build: sudo -S <execPath> --no-gui <args...>
	cmdArgs := make([]string, 0, 3+len(args))
	cmdArgs = append(cmdArgs, "-S", e.execPath, "--no-gui")
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("sudo", cmdArgs...) // #nosec G204 -- re-invoking self
	cmd.Stdin = &stdinBuf

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()

	// Zero the password after use regardless of outcome.
	zeroBytes(e.password)

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

			return nil, fmt.Errorf("%w: exit code %d: %s",
				ErrElevationFailed, exitCode, stderrStr)
		}

		e.log.Debug("Run failed",
			"args", args,
			"stderr", stderrStr,
			"error", err)

		return nil, fmt.Errorf("%w: %v: %s", ErrElevationFailed, err, stderrStr)
	}

	e.log.Debug("Run completed successfully",
		"args", args,
		"stdout_length", stdout.Len())

	return stdout.Bytes(), nil
}

// zeroBytes overwrites a byte slice with zeros to clear sensitive data
// from memory.
func zeroBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
