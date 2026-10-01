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

// Package tpmdev opens TPM 2.0 character devices. It is the one place in
// go-xkms (and xkey) that opens one, so one rule holds everywhere: a test
// binary never reaches the host's TPM (/dev/tpm*, /dev/tpmrm*) unless the
// run opts in with XKMS_TEST_HARDWARE_TPM=1. A unit test that sealed to, or
// authorized against, the host TPM could leave real state behind or push it
// into dictionary-attack lockout; tests use the simulator or swtpm instead.
// A guard test (tpmdev_guard_test.go) keeps every other opener out of the
// tree.
package tpmdev

import (
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// EnvTestHardwareTPM opts a test run in to the host's hardware TPM.
const EnvTestHardwareTPM = "XKMS_TEST_HARDWARE_TPM"

// EnvDenyHardwareTPM, set to "1", applies the test rule to any process: the
// test targets export it, so a binary a test runs as a subprocess (which is
// not itself a test binary) is held to the same refusal.
const EnvDenyHardwareTPM = "XKMS_DENY_HARDWARE_TPM"

// ErrHardwareTPMInTest is returned when a test binary opens a hardware TPM
// without the opt-in.
var ErrHardwareTPMInTest = errors.New("tpmdev: a test may not open the host's hardware TPM; use the simulator or set " +
	EnvTestHardwareTPM + "=1")

// hardwareDevice matches the kernel's TPM character devices.
var hardwareDevice = regexp.MustCompile(`^/dev/tpm(rm)?[0-9]+$`)

// IsHardware reports whether path names a hardware TPM character device,
// following symlinks so an alias cannot pass for something else.
func IsHardware(path string) bool {
	if hardwareDevice.MatchString(filepath.Clean(path)) {
		return true
	}
	resolved, err := filepath.EvalSymlinks(path)
	return err == nil && hardwareDevice.MatchString(resolved)
}

// Allowed returns ErrHardwareTPMInTest when path is a hardware TPM and the
// process is a test (a test binary, or one run with EnvDenyHardwareTPM) that
// has not opted in; nil otherwise.
func Allowed(path string) error {
	return decide(path, testing.Testing() || envDenies())
}

// envDenies reports whether the environment holds the process to the test
// rule.
func envDenies() bool {
	return os.Getenv(EnvDenyHardwareTPM) == "1"
}

// decide applies the rule for a process that is, or is not, under test.
func decide(path string, underTest bool) error {
	if underTest && IsHardware(path) && os.Getenv(EnvTestHardwareTPM) != "1" {
		return ErrHardwareTPMInTest
	}
	return nil
}

// Open opens the TPM device at path for reading and writing, refusing a
// hardware TPM in a test binary that has not opted in.
func Open(path string) (*os.File, error) {
	if err := Allowed(path); err != nil {
		return nil, err
	}
	return os.OpenFile(path, os.O_RDWR, 0)
}
