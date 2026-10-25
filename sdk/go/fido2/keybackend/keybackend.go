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

// Package keybackend is the SDK re-export of the FIDO2 authenticator key
// backend contract (pkg/fido2/authenticator/keybackend). Client binaries
// import this package instead of pkg/* so they depend only on the SDK.
package keybackend

import (
	"github.com/jeremyhahn/go-xkms/pkg/fido2/authenticator/keybackend"
)

const (
	AttestationFormatPacked = keybackend.AttestationFormatPacked

	COSEAlgES256 = keybackend.COSEAlgES256
	COSEAlgES384 = keybackend.COSEAlgES384
	COSEAlgES512 = keybackend.COSEAlgES512
	COSEAlgEdDSA = keybackend.COSEAlgEdDSA
)

type (
	CompositeBackend     = keybackend.CompositeBackend
	FIDO2KeyBackend      = keybackend.FIDO2KeyBackend
	FIDO2KeyCapabilities = keybackend.FIDO2KeyCapabilities
	KeyHandle            = keybackend.KeyHandle
	UserVerifier         = keybackend.UserVerifier
)

var (
	EncodeCOSEPublicKey            = keybackend.EncodeCOSEPublicKey
	NewBackendAdapter              = keybackend.NewBackendAdapter
	NewCompositeBackend            = keybackend.NewCompositeBackend
	NewTPM2AttestingBackend        = keybackend.NewTPM2AttestingBackend
	ValidateAttestationCertificate = keybackend.ValidateAttestationCertificate
)
