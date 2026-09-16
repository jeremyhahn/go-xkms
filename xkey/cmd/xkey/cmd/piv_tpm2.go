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
	"log/slog"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// createTPM2PIVStorage creates a TPM2 NV RAM-backed PIV certificate storage.
//
// It opens a raw command channel to the TPM device (or Unix domain socket)
// configured in cfg.TPMDevice and layers the canonical TPM2 PIV certificate
// store from the xkms SDK on top of it. The transport is intentionally left
// open for the lifetime of the process: TPM2CertStorage.Close only releases
// the certificate store, not the underlying connection, so a single
// short-lived CLI invocation relies on process exit to release the device.
func createTPM2PIVStorage(cfg *PIVConfig, logger *slog.Logger) (xkms.PIVCertificateStorage, error) {
	logger.Info("initializing TPM2 PIV certificate storage",
		slog.String("device", cfg.TPMDevice),
	)

	tpm, err := xkms.OpenDeviceTransport(cfg.TPMDevice)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to open TPM device for PIV storage", Err: err}
	}

	storage, err := xkms.NewPIVTPM2Backend(&xkms.PIVTPM2Config{TPM: tpm})
	if err != nil {
		_ = tpm.Close()
		return nil, &WrappedError{Msg: "failed to initialize TPM2 PIV certificate storage", Err: err}
	}

	return storage, nil
}
