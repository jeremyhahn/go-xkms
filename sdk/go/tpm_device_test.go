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

package xkms

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/tpmdev"
)

// TestOpenTPMDevice_RefusesHardwareTPMInTests proves the SDK entry point keeps
// pkg/tpm2/tpmdev's guard: a test binary cannot open the host's TPM without
// opting in.
func TestOpenTPMDevice_RefusesHardwareTPMInTests(t *testing.T) {
	t.Setenv(tpmdev.EnvTestHardwareTPM, "")
	f, err := OpenTPMDevice("/dev/tpmrm0")
	if f != nil {
		_ = f.Close()
	}
	if !errors.Is(err, tpmdev.ErrHardwareTPMInTest) {
		t.Fatalf("OpenTPMDevice(/dev/tpmrm0) error = %v, want ErrHardwareTPMInTest", err)
	}
}

// TestOpenTPMDevice_OpensANonHardwarePath proves a non-hardware device path (a
// simulator socket or test fixture) opens read-write, and a missing one
// reports the open error.
func TestOpenTPMDevice_OpensANonHardwarePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tpm-fixture")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := OpenTPMDevice(path)
	if err != nil {
		t.Fatalf("OpenTPMDevice(%s): %v", path, err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}

	if _, err := OpenTPMDevice(filepath.Join(t.TempDir(), "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("OpenTPMDevice(missing) error = %v, want os.ErrNotExist", err)
	}
}
