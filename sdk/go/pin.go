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
	"github.com/jeremyhahn/go-xkms/pkg/pinselect"
	"github.com/jeremyhahn/go-xkms/pkg/pintpm2"
)

// PIN-backend selection surface re-exported so the xkey GUI/CLI choose and
// construct a software or TPM-platform PIN backend through the SDK. The
// pinselect Config identifier is prefixed PINSelect* to stay unambiguous in
// the flat SDK namespace.

// PINSelectConfig configures PIN-backend selection.
type PINSelectConfig = pinselect.Config

// PINSoftwareProvider supplies a software PIN backend.
type PINSoftwareProvider = pinselect.SoftwareProvider

// PINTPMProvider supplies a TPM-platform PIN backend.
type PINTPMProvider = pinselect.TPMProvider

// SelectPINBackend selects a PIN backend per the given configuration.
var SelectPINBackend = pinselect.Select

// TPMPlatformAuthProvider supplies TPM platform authorization for PIN-gated keys.
type TPMPlatformAuthProvider = pintpm2.PlatformAuthProvider
