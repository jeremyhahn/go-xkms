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

//go:build tpm2

package cmd

import (
	"errors"
	"log/slog"
	"os"
	"testing"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// TestCreateTPM2PIVStorage_MissingDevice proves createTPM2PIVStorage reports
// a wrapped, typed error instead of panicking or returning a nil storage with
// a nil error when the configured TPM device does not exist.
func TestCreateTPM2PIVStorage_MissingDevice(t *testing.T) {
	cfg := &PIVConfig{
		Backend:     PIVBackendTPM2,
		StorageType: PIVStorageTypeTPM2,
		TPMDevice:   "/nonexistent/tpm-device-path",
	}

	storage, err := createTPM2PIVStorage(cfg, slog.Default())

	if err == nil {
		t.Fatal("createTPM2PIVStorage() error = nil, want error for missing TPM device")
	}
	if storage != nil {
		t.Errorf("createTPM2PIVStorage() storage = %v, want nil on error", storage)
	}

	var wrapped *WrappedError
	if !errors.As(err, &wrapped) {
		t.Fatalf("createTPM2PIVStorage() error type = %T, want *WrappedError", err)
	}
	if !errors.Is(err, xkms.ErrTPMOpeningDevice) {
		t.Errorf("createTPM2PIVStorage() error = %v, want it to wrap xkms.ErrTPMOpeningDevice", err)
	}
}

// TestCreateTPM2PIVStorage_NotATPM proves that a device path that opens
// successfully but does not speak the TPM 2.0 command protocol fails on
// first use rather than silently accepting or corrupting data.
// createTPM2PIVStorage only opens the transport and wires the certificate
// store; it does not (and per the TPM2 protocol cannot) probe the device
// until the first command is sent, so construction itself succeeds here.
func TestCreateTPM2PIVStorage_NotATPM(t *testing.T) {
	devicePath := t.TempDir() + "/not-a-tpm"
	if err := os.WriteFile(devicePath, nil, 0600); err != nil {
		t.Fatalf("failed to create fake device file: %v", err)
	}

	cfg := &PIVConfig{
		Backend:     PIVBackendTPM2,
		StorageType: PIVStorageTypeTPM2,
		TPMDevice:   devicePath,
	}

	storage, err := createTPM2PIVStorage(cfg, slog.Default())
	if err != nil {
		t.Fatalf("createTPM2PIVStorage() error = %v, want nil (opening a non-TPM file succeeds; failure surfaces on use)", err)
	}
	defer func() { _ = storage.Close() }()

	cert := generateTestCertificate(t)
	if err := storage.Store(xkms.PIVSlotAuthentication, cert); err == nil {
		t.Error("Store() error = nil, want error when the device does not speak the TPM 2.0 protocol")
	}
}
