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

package ipc

import "fmt"

// PKCS11Payload carries PKCS#11-specific request data in an IPC Message.
type PKCS11Payload struct {
	Action   string          `json:"action"`              // "sign", "get_piv_certificate", etc.
	Sign     *SignParams     `json:"sign,omitempty"`      // parameters for sign action
	PIVCert  *PIVCertParams  `json:"piv_cert,omitempty"`  // parameters for get_piv_certificate action
	PIVSlots *PIVSlotsParams `json:"piv_slots,omitempty"` // parameters for list_piv_slots action
}

// SignParams contains parameters for a PKCS#11 sign operation.
type SignParams struct {
	Backend string `json:"backend"`        // backend name
	KeyID   string `json:"key_id"`         // key identifier
	Data    string `json:"data"`           // base64-encoded data to sign
	Hash    string `json:"hash,omitempty"` // "SHA-256", "SHA-384", "SHA-512"
}

// SignResult contains the result of a sign operation.
type SignResult struct {
	Signature string `json:"signature"` // base64-encoded signature
}

// PIVCertParams contains parameters for a PIV certificate operation.
type PIVCertParams struct {
	Backend string `json:"backend"`          // backend name
	Slot    string `json:"slot"`             // "9a", "9c", "9d", "9e"
	Format  string `json:"format,omitempty"` // "pem" (default), "der"
}

// PIVCertResult contains the certificate data.
type PIVCertResult struct {
	Certificate string `json:"certificate"` // PEM or base64-DER
	Slot        string `json:"slot"`        // slot identifier
	Subject     string `json:"subject"`     // certificate subject
	Issuer      string `json:"issuer"`      // certificate issuer
	NotAfter    string `json:"not_after"`   // certificate expiry
}

// PIVSlotsParams contains parameters for listing PIV slots.
type PIVSlotsParams struct {
	Backend string `json:"backend"` // backend name
}

// PIVSlotInfo describes a single PIV slot.
type PIVSlotInfo struct {
	Slot      string `json:"slot"`                // slot identifier
	Algorithm string `json:"algorithm,omitempty"` // key algorithm
	Subject   string `json:"subject,omitempty"`   // certificate subject
	HasCert   bool   `json:"has_cert"`            // whether the slot has a certificate
	NotAfter  string `json:"not_after,omitempty"` // certificate expiry
}

// PIVSlotsResult contains the list of PIV slots.
type PIVSlotsResult struct {
	Slots []PIVSlotInfo `json:"slots"`
}

// BarrierStatusResult contains barrier seal status.
type BarrierStatusResult struct {
	Sealed         bool   `json:"sealed"`             // whether the barrier is sealed
	Strategy       string `json:"strategy,omitempty"` // sealing strategy
	HardwareBacked bool   `json:"hardware_backed"`    // whether hardware-backed
}

// PKCS11Result carries PKCS#11-specific response data.
type PKCS11Result struct {
	Sign          *SignResult          `json:"sign,omitempty"`
	PIVCert       *PIVCertResult       `json:"piv_cert,omitempty"`
	PIVSlots      *PIVSlotsResult      `json:"piv_slots,omitempty"`
	BarrierStatus *BarrierStatusResult `json:"barrier_status,omitempty"`
}

// Validate checks the PKCS11Payload for correctness.
func (p *PKCS11Payload) Validate() error {
	if p.Action == "" {
		return fmt.Errorf("%w: pkcs11 action is required", ErrInvalidMessage)
	}
	switch p.Action {
	case ActionSign:
		if p.Sign == nil {
			return fmt.Errorf("%w: sign params required for sign action", ErrInvalidMessage)
		}
		if p.Sign.KeyID == "" {
			return fmt.Errorf("%w: key_id is required for sign", ErrInvalidMessage)
		}
		if p.Sign.Data == "" {
			return fmt.Errorf("%w: data is required for sign", ErrInvalidMessage)
		}
	case ActionGetPIVCertificate:
		if p.PIVCert == nil {
			return fmt.Errorf("%w: piv_cert params required for get_piv_certificate", ErrInvalidMessage)
		}
		if p.PIVCert.Slot == "" {
			return fmt.Errorf("%w: slot is required for get_piv_certificate", ErrInvalidMessage)
		}
	case ActionListPIVSlots:
		// PIVSlots params are optional (backend defaults)
	case ActionBarrierStatus:
		// No params needed
	default:
		return fmt.Errorf("%w: unknown pkcs11 action %q", ErrInvalidMessage, p.Action)
	}
	return nil
}
