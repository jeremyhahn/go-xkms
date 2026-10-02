// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// Package tpmdev re-exports go-xkms pkg/tpm2/tpmdev: opening the host's TPM
// device node for xkey's TPM pairing and GUI.
package tpmdev

import pkg "github.com/jeremyhahn/go-xkms/pkg/tpm2/tpmdev"

// Open opens the TPM device at path, refusing a hardware TPM in a test
// binary that has not opted in.
var Open = pkg.Open
