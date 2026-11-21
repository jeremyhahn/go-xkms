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

//go:build !tpm_simulator

package xkms

import "github.com/jeremyhahn/go-xkms/pkg/tpm2"

// ErrTPMSimulatorNotAvailable is returned by OpenSimulator in a build without
// the tpm_simulator tag.
var ErrTPMSimulatorNotAvailable = tpm2.ErrSimulatorNotAvailable
