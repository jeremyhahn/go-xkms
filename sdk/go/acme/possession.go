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

// The device side of the device-attest-01 possession request
// (acme-device-attest-10 §5): the CSR a DICE device, or its host, assembles
// and sends at finalize. trusted-firmware's xkms adapter calls these names.
// SignPossessionCSR is the one-call form for a device reachable as a
// crypto.Signer. Each name is the deviceattest01 value itself, so errors.Is
// matches across the SDK.

package trustedca

import (
	deviceattest01 "github.com/jeremyhahn/go-xkms/pkg/acme/challenges/device-attest-01"
)

// AssemblePossessionCSR wraps a DER CertificationRequestInfo and the device's
// DER ECDSA signature over SHA-256 of it into a DER CertificationRequest.
var AssemblePossessionCSR = deviceattest01.AssemblePossessionCSR

// BuildPossessionCRI builds the CertificationRequestInfo bytes the device signs.
var BuildPossessionCRI = deviceattest01.BuildPossessionCRI

// SignPossessionCSR builds, signs and assembles the possession request in one call.
var SignPossessionCSR = deviceattest01.SignPossessionCSR

// DICENonce is SHA-256 of the key authorization, the eat_nonce a DICE attester places.
var DICENonce = deviceattest01.DICENonce

// PossessionRequest is a parsed possession request.
type PossessionRequest = deviceattest01.PossessionRequest

// ParsePossessionCSR reads a possession request from a parsed CSR.
var ParsePossessionCSR = deviceattest01.ParsePossessionCSR

// ErrPossessionCSRMalformed is returned when the request info is not one DER value.
var ErrPossessionCSRMalformed = deviceattest01.ErrPossessionCSRMalformed

// ErrPossessionSignatureInvalid is returned when the signature is not one DER ECDSA-Sig-Value.
var ErrPossessionSignatureInvalid = deviceattest01.ErrPossessionSignatureInvalid

// ErrPossessionSigningFailed is returned when the signer is missing or fails.
var ErrPossessionSigningFailed = deviceattest01.ErrPossessionSigningFailed

// ErrPossessionMeasurementsShape is returned when the claims' measurements have the wrong shape.
var ErrPossessionMeasurementsShape = deviceattest01.ErrPossessionMeasurementsShape
