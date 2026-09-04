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

// ImportPIVKeyRequest is the request payload for ImportPIVKey.
type ImportPIVKeyRequest = transport.ImportPIVKeyRequest

// ImportPIVKeyResponse is the response payload for ImportPIVKey.
type ImportPIVKeyResponse = transport.ImportPIVKeyResponse

// PIVKeyImporter is the optional capability a PIVKeyGenerator implements to
// accept an externally held private key into a slot.
type PIVKeyImporter = pivbackend.PIVKeyImporter

// ---------------------------------------------------------------------------
// Function re-exports
// ---------------------------------------------------------------------------

// SignPIV signs a payload with the PIV slot's private key. See
// pkg/xkms.SignPIVSlot for full semantics.
var SignPIV = pivbackend.SignPIVSlot

// AttestPIV returns attestation material for a PIV slot.
//
// It REFUSES a slot whose key arrived by import, with
// ErrPIVKeyImportedNotAttestable. A slot-generated key cannot have existed
// before it existed in the slot, so attesting it asserts both residency and
// exclusivity; an imported key may exist elsewhere, and an attestation over it
// would assert only residency while looking identical to a verifier. This
// matches the hardware — YubiKey PIV attestation is likewise available only
// for slot-generated keys — so an xkms PIV attestation is worth what a
// YubiKey one is. See pkg/xkms.AttestPIVSlot for full semantics.
var AttestPIV = pivbackend.AttestPIVSlot

// ResetPIV factory-resets a PIV device (clears all certificates in the
// configured backend store). The request must set Confirm to true; otherwise
// ErrPIVResetNotConfirmed is returned. See pkg/xkms.ResetPIVDevice.
var ResetPIV = pivbackend.ResetPIVDevice

// ImportPIVKey installs an externally held private key in a PIV slot. The key
// material may be PEM or DER, in PKCS#8, SEC 1 or PKCS#1 encoding.
//
// Import and generation are different trust classes, and a caller reading a
// later attestation needs to know which it has. A slot-generated key cannot
// have existed anywhere before it existed in the slot; an imported one can,
// and nothing the slot can say afterwards distinguishes a key that was only
// ever there from a copy retained elsewhere. An attestation over an imported
// key therefore asserts residency but NOT exclusivity — a verifier that reads
// "attested" as "generated in-slot" is drawing a conclusion the evidence does
// not support. See docs/piv-smartcard/architecture.md.
//
// A backend that cannot accept an imported key returns
// ErrPIVImportNotSupported rather than reporting success.
// See pkg/xkms.ImportPIVKey.
var ImportPIVKey = pivbackend.ImportPIVKey

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

// ErrPIVKeyMaterialRequired is returned when ImportPIVKey is called without
// key material.
var ErrPIVKeyMaterialRequired = pivbackend.ErrPIVKeyMaterialRequired

// ErrPIVKeyMaterialInvalid is returned when the bytes given to ImportPIVKey
// are not a private key in any accepted encoding.
var ErrPIVKeyMaterialInvalid = pivbackend.ErrPIVKeyMaterialInvalid

// ErrPIVImportNotSupported is returned when the resolved backend cannot accept
// an imported private key. A hardware PIV applet may refuse import for some
// slots or algorithms; the refusal is reported rather than being mistaken for
// success.
var ErrPIVImportNotSupported = pivbackend.ErrPIVImportNotSupported

// ErrPIVAlgorithmMismatch is returned when ImportPIVKey is called with a
// declared algorithm that disagrees with the supplied key.
var ErrPIVAlgorithmMismatch = pivbackend.ErrPIVAlgorithmMismatch

// ErrPIVKeyImportedNotAttestable is returned by AttestPIV for a slot whose key
// arrived by import. Attestation over an imported key would assert residency
// while a verifier reads it as exclusivity, and nothing on the wire carries
// the difference, so it is refused rather than issued.
var ErrPIVKeyImportedNotAttestable = pivbackend.ErrPIVKeyImportedNotAttestable
