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

// This file re-exports the PIV slot operation entry points from pkg/xkms.
// It provides a stable SDK-facing surface for slot key signing, slot
// attestation, and factory-resetting a PIV device.
//
// The existing PIV types (ListPIVSlotsRequest, GeneratePIVKeyRequest, ...)
// are re-exported in xkms.go; the three new types below are re-exported
// here so they travel together with the SDK entry points that use them.

import (
	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	pivbackend "github.com/jeremyhahn/go-xkms/pkg/xkms"
)

// ---------------------------------------------------------------------------
// Type aliases
// ---------------------------------------------------------------------------

// PIVSignRequest is the request payload for SignPIV.
type PIVSignRequest = transport.PIVSignRequest

// PIVSignResponse is the response payload for SignPIV.
type PIVSignResponse = transport.PIVSignResponse

// PIVAttestRequest is the request payload for AttestPIV.
type PIVAttestRequest = transport.PIVAttestRequest

// PIVAttestResponse is the response payload for AttestPIV.
type PIVAttestResponse = transport.PIVAttestResponse

// PIVResetDeviceRequest is the request payload for ResetPIV.
type PIVResetDeviceRequest = transport.PIVResetDeviceRequest

// ---------------------------------------------------------------------------
// Function re-exports
// ---------------------------------------------------------------------------

// SignPIV signs a payload with the PIV slot's private key. See
// pkg/xkms.SignPIVSlot for full semantics.
var SignPIV = pivbackend.SignPIVSlot

// AttestPIV returns attestation material for a PIV slot. See
// pkg/xkms.AttestPIVSlot for full semantics.
var AttestPIV = pivbackend.AttestPIVSlot

// ResetPIV factory-resets a PIV device (clears all certificates in the
// configured backend store). The request must set Confirm to true; otherwise
// ErrPIVResetNotConfirmed is returned. See pkg/xkms.ResetPIVDevice.
var ResetPIV = pivbackend.ResetPIVDevice

// ---------------------------------------------------------------------------
// Error re-exports
// ---------------------------------------------------------------------------

// ErrPIVResetNotConfirmed is returned when ResetPIV is called without
// Confirm=true on the request.
var ErrPIVResetNotConfirmed = pivbackend.ErrPIVResetNotConfirmed

// ErrPIVPayloadRequired is returned when SignPIV is called with an empty
// payload.
var ErrPIVPayloadRequired = pivbackend.ErrPIVPayloadRequired

// ErrPIVHashAlgorithmInvalid is returned when SignPIV is called with an
// unknown HashAlgorithm value.
var ErrPIVHashAlgorithmInvalid = pivbackend.ErrPIVHashAlgorithmInvalid

// ErrPIVNoAttestationMaterial is returned when AttestPIV cannot find a
// stored certificate for the requested slot.
var ErrPIVNoAttestationMaterial = pivbackend.ErrPIVNoAttestationMaterial
