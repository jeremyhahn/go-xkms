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
	"os"
	"os/exec"
)

var (
	// ErrElevationUnavailable indicates that pkexec is not available on the system.
	ErrElevationUnavailable = errors.New("elevation: pkexec not available")

	// ErrElevationDenied indicates that the user denied the authorization prompt.
	ErrElevationDenied = errors.New("elevation: user denied authorization")

	// ErrElevationFailed indicates that the elevated operation failed.
	ErrElevationFailed = errors.New("elevation: operation failed")

	// ErrSudoUnavailable indicates that sudo is not available on the system.
	ErrSudoUnavailable = errors.New("elevation: sudo not available")

	// ErrElevationRequired indicates that privilege elevation is required
	// but no password or elevator was provided.
	ErrElevationRequired = errors.New("elevation: privilege elevation required")
)

// Elevator abstracts privilege elevation for operations requiring root.
type Elevator interface {
	// Run executes the xkey binary with elevated privileges using the
	// given CLI arguments, piping stdinData on stdin.
	Run(args []string, stdinData []byte) ([]byte, error)

	// IsAvailable returns true if privilege elevation is available.
	IsAvailable() bool
}

// PkexecElevator uses PolicyKit pkexec to re-execute the current binary
// with CLI subcommands to perform privileged operations.
type PkexecElevator struct {
	execPath string
}

// NewPkexecElevator creates a PkexecElevator that re-invokes the current
// executable via pkexec with CLI subcommands.
func NewPkexecElevator() *PkexecElevator {
	path, _ := os.Executable()
	return &PkexecElevator{execPath: path}
}

// IsAvailable returns true if both pkexec and the current executable path
// are available.
func (e *PkexecElevator) IsAvailable() bool {
	if e.execPath == "" {
		return false
	}
	_, err := exec.LookPath("pkexec")
	return err == nil
}

// Run executes the current binary via pkexec with --no-gui and the given
// CLI arguments. Secrets are passed on stdin to avoid leaking them in the
// process argument list.
func (e *PkexecElevator) Run(args []string, stdinData []byte) ([]byte, error) {
	if e.execPath == "" {
		return nil, ErrElevationUnavailable
	}

	// Build: pkexec <execPath> --no-gui <args...>
	cmdArgs := make([]string, 0, 2+len(args))
	cmdArgs = append(cmdArgs, e.execPath, "--no-gui")
	cmdArgs = append(cmdArgs, args...)

	cmd := exec.Command("pkexec", cmdArgs...) // #nosec G204 -- re-invoking self
	cmd.Stdin = bytes.NewReader(stdinData)

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			// pkexec returns exit code 126 when the user dismisses
			// the authentication dialog.
			if exitErr.ExitCode() == 126 {
				return nil, ErrElevationDenied
			}
		}
		// Include stderr in the error so the caller (and ultimately the
		// user) can see why the elevated operation failed.
		stderrStr := bytes.TrimSpace(stderr.Bytes())
		if len(stderrStr) > 0 {
			return nil, fmt.Errorf("%w: %s", ErrElevationFailed, stderrStr)
		}
		return nil, ErrElevationFailed
	}

	return stdout.Bytes(), nil
}
