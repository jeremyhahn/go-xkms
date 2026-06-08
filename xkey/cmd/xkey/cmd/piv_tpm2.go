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

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// ErrPIVTPM2NotImplemented indicates that TPM2 PIV storage is not yet implemented.
var ErrPIVTPM2NotImplemented = errors.New("piv: TPM2 storage backend not yet implemented")

// createTPM2PIVStorage creates a TPM2-backed PIV certificate storage.
// This is a placeholder for future TPM2 NV storage support.
func createTPM2PIVStorage(_ *PIVConfig, _ *slog.Logger) (xkms.PIVCertificateStorage, error) {
	return nil, ErrPIVTPM2NotImplemented
}
