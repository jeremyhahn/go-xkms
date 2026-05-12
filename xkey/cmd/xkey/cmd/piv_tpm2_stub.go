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

//go:build !tpm2

package cmd

import (
	"errors"
	"log/slog"

	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
)

// ErrPIVTPM2BuildTagRequired indicates that the binary was not compiled with
// the tpm2 build tag, which is required for TPM2 PIV operations.
var ErrPIVTPM2BuildTagRequired = errors.New("piv: TPM2 support requires the tpm2 build tag")

// createTPM2PIVStorage returns an error because TPM2 support is not compiled
// into this binary.
func createTPM2PIVStorage(_ *PIVConfig, _ *slog.Logger) (pivcert.PIVCertificateStorage, error) {
	return nil, ErrPIVTPM2BuildTagRequired
}
