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
// the flat SDK namespace. xkey depends only on this package (sdk/go) and
// its subpackages, never on go-xkms/pkg/* directly (Architecture Gates);
// every pinselect/pintpm2 symbol a consumer needs is re-exported here
// rather than imported from pkg/* downstream.

// PINSelectConfig configures PIN-backend selection.
type PINSelectConfig = pinselect.Config

// PINSoftwareProvider supplies a software PIN backend.
type PINSoftwareProvider = pinselect.SoftwareProvider

// PINTPMProvider supplies a TPM-platform PIN backend.
type PINTPMProvider = pinselect.TPMProvider

// SelectPINBackend selects a PIN backend per the given configuration.
var SelectPINBackend = pinselect.Select

// ErrPINSelectNoSoftwareProvider is returned by SelectPINBackend when
// Config.Software is nil. The software backend is the mandatory fallback;
// without it SelectPINBackend cannot guarantee a usable PIN backend.
var ErrPINSelectNoSoftwareProvider = pinselect.ErrNoSoftwareProvider

// PINSelectSoftwareStorageError wraps a failure opening the software PIN
// store or constructing the software backend during SelectPINBackend.
type PINSelectSoftwareStorageError = pinselect.SoftwareStorageError

// TPMPlatformAuthProvider supplies TPM platform authorization for PIN-gated keys.
type TPMPlatformAuthProvider = pintpm2.PlatformAuthProvider

// PINTPMBackend is the TPM 2.0-backed PINBackend implementation: user PIN
// verification is delegated to a TPMPlatformAuthProvider (a TPM
// PlatformSRK's password auth), with no SO PIN of its own.
type PINTPMBackend = pintpm2.TPM2Backend

// NewPINTPMBackend creates a PINTPMBackend that delegates PIN verification
// to the given TPMPlatformAuthProvider.
var NewPINTPMBackend = pintpm2.NewTPM2Backend
