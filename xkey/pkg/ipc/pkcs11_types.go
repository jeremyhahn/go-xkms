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

import (
	"fmt"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
)

// PKCS11Payload carries PKCS#11-specific request data in an IPC Message.
// Action names the operation; the field of the same name carries its
// request. Requests are the SDK transport types, so an operation crosses
// the socket with exactly the fields it has on every other transport.
type PKCS11Payload struct {
	Action string `json:"action"`

	GenerateKey          *transport.GenerateKeyRequest          `json:"generate_key,omitempty"`
	Sign                 *transport.SignRequest                 `json:"sign,omitempty"`
	Verify               *transport.VerifyRequest               `json:"verify,omitempty"`
	Encrypt              *transport.EncryptRequest              `json:"encrypt,omitempty"`
	EncryptAsym          *transport.EncryptAsymRequest          `json:"encrypt_asym,omitempty"`
	Decrypt              *transport.DecryptRequest              `json:"decrypt,omitempty"`
	DeriveKey            *transport.DeriveKeyRequest            `json:"derive_key,omitempty"`
	DeriveKeyECDH        *transport.DeriveKeyECDHRequest        `json:"derive_key_ecdh,omitempty"`
	WrapKeyByID          *transport.WrapKeyByIDRequest          `json:"wrap_key_by_id,omitempty"`
	UnwrapKeyByID        *transport.UnwrapKeyByIDRequest        `json:"unwrap_key_by_id,omitempty"`
	ExportKeyMaterial    *transport.ExportKeyMaterialRequest    `json:"export_key_material,omitempty"`
	GetImportParameters  *transport.GetImportParametersRequest  `json:"get_import_parameters,omitempty"`
	ImportKey            *transport.ImportKeyRequest            `json:"import_key,omitempty"`
	ListPIVSlots         *transport.ListPIVSlotsRequest         `json:"list_piv_slots,omitempty"`
	GetPIVCertificate    *transport.GetPIVCertificateRequest    `json:"get_piv_certificate,omitempty"`
	GeneratePIVKey       *transport.GeneratePIVKeyRequest       `json:"generate_piv_key,omitempty"`
	StorePIVCertificate  *transport.StorePIVCertificateRequest  `json:"store_piv_certificate,omitempty"`
	DeletePIVCertificate *transport.DeletePIVCertificateRequest `json:"delete_piv_certificate,omitempty"`
	ImportPIVCertificate *transport.StorePIVCertificateRequest  `json:"import_piv_certificate,omitempty"`
	ExportPIVCertificate *transport.GetPIVCertificateRequest    `json:"export_piv_certificate,omitempty"`
	GeneratePIVCSR       *transport.GeneratePIVCSRRequest       `json:"generate_piv_csr,omitempty"`
}

// BarrierStatusResult contains barrier seal status. It is shared by the
// PKCS#11 barrier_status action and the state/barrier action so both report
// the barrier through one type.
type BarrierStatusResult struct {
	Initialized    bool   `json:"initialized"`        // whether the barrier has been initialized
	Sealed         bool   `json:"sealed"`             // whether the barrier is sealed
	Strategy       string `json:"strategy,omitempty"` // sealing strategy
	HardwareBacked bool   `json:"hardware_backed"`    // whether hardware-backed
}

// PKCS11Result carries PKCS#11-specific response data: the SDK transport
// response of the action, in the field of the same name. The PIV
// certificate store, delete and import actions have no result; a success
// response with an empty PKCS11Result acknowledges them.
type PKCS11Result struct {
	GenerateKey          *transport.GenerateKeyResponse         `json:"generate_key,omitempty"`
	Sign                 *transport.SignResponse                `json:"sign,omitempty"`
	Verify               *transport.VerifyResponse              `json:"verify,omitempty"`
	Encrypt              *transport.EncryptResponse             `json:"encrypt,omitempty"`
	EncryptAsym          *transport.EncryptAsymResponse         `json:"encrypt_asym,omitempty"`
	Decrypt              *transport.DecryptResponse             `json:"decrypt,omitempty"`
	DeriveKey            *transport.DeriveKeyResponse           `json:"derive_key,omitempty"`
	DeriveKeyECDH        *transport.DeriveKeyECDHResponse       `json:"derive_key_ecdh,omitempty"`
	WrapKeyByID          *transport.WrapKeyByIDResponse         `json:"wrap_key_by_id,omitempty"`
	UnwrapKeyByID        *transport.UnwrapKeyByIDResponse       `json:"unwrap_key_by_id,omitempty"`
	ExportKeyMaterial    *transport.ExportKeyMaterialResponse   `json:"export_key_material,omitempty"`
	GetImportParameters  *transport.GetImportParametersResponse `json:"get_import_parameters,omitempty"`
	ImportKey            *transport.ImportKeyResponse           `json:"import_key,omitempty"`
	ListPIVSlots         *transport.ListPIVSlotsResponse        `json:"list_piv_slots,omitempty"`
	GetPIVCertificate    *transport.GetPIVCertificateResponse   `json:"get_piv_certificate,omitempty"`
	GeneratePIVKey       *transport.GeneratePIVKeyResponse      `json:"generate_piv_key,omitempty"`
	ExportPIVCertificate *transport.GetPIVCertificateResponse   `json:"export_piv_certificate,omitempty"`
	GeneratePIVCSR       *transport.GeneratePIVCSRResponse      `json:"generate_piv_csr,omitempty"`
	BarrierStatus        *BarrierStatusResult                   `json:"barrier_status,omitempty"`
}

// pkcs11Validators maps each PKCS#11 action to the check of its request.
// Every action except list_piv_slots and barrier_status must carry its
// request; the identifier fields checked here are the ones the action cannot
// address anything without. Everything else is the embedded transport's to
// validate, exactly as on every other transport.
var pkcs11Validators = map[string]func(*PKCS11Payload) error{
	ActionGenerateKey: func(p *PKCS11Payload) error {
		return requirePKCS11Request(ActionGenerateKey, p.GenerateKey != nil)
	},
	ActionSign: func(p *PKCS11Payload) error {
		if p.Sign == nil {
			return requirePKCS11Request(ActionSign, false)
		}
		if len(p.Sign.Data) == 0 {
			return &DetailError{Err: ErrInvalidMessage, Detail: ": data is required for sign"}
		}
		return requirePKCS11Field(ActionSign, "key_id", p.Sign.KeyID)
	},
	ActionVerify: func(p *PKCS11Payload) error {
		if p.Verify == nil {
			return requirePKCS11Request(ActionVerify, false)
		}
		return requirePKCS11Field(ActionVerify, "key_id", p.Verify.KeyID)
	},
	ActionEncrypt: func(p *PKCS11Payload) error {
		if p.Encrypt == nil {
			return requirePKCS11Request(ActionEncrypt, false)
		}
		return requirePKCS11Field(ActionEncrypt, "key_id", p.Encrypt.KeyID)
	},
	ActionEncryptAsym: func(p *PKCS11Payload) error {
		if p.EncryptAsym == nil {
			return requirePKCS11Request(ActionEncryptAsym, false)
		}
		return requirePKCS11Field(ActionEncryptAsym, "key_id", p.EncryptAsym.KeyID)
	},
	ActionDecrypt: func(p *PKCS11Payload) error {
		if p.Decrypt == nil {
			return requirePKCS11Request(ActionDecrypt, false)
		}
		return requirePKCS11Field(ActionDecrypt, "key_id", p.Decrypt.KeyID)
	},
	ActionDeriveKey: func(p *PKCS11Payload) error {
		return requirePKCS11Request(ActionDeriveKey, p.DeriveKey != nil)
	},
	ActionDeriveKeyECDH: func(p *PKCS11Payload) error {
		if p.DeriveKeyECDH == nil {
			return requirePKCS11Request(ActionDeriveKeyECDH, false)
		}
		return requirePKCS11Field(ActionDeriveKeyECDH, "key_id", p.DeriveKeyECDH.KeyID)
	},
	ActionWrapKeyByID: func(p *PKCS11Payload) error {
		if p.WrapKeyByID == nil {
			return requirePKCS11Request(ActionWrapKeyByID, false)
		}
		return requirePKCS11Field(ActionWrapKeyByID, "wrapping_key_id", p.WrapKeyByID.WrappingKeyID)
	},
	ActionUnwrapKeyByID: func(p *PKCS11Payload) error {
		if p.UnwrapKeyByID == nil {
			return requirePKCS11Request(ActionUnwrapKeyByID, false)
		}
		return requirePKCS11Field(ActionUnwrapKeyByID, "unwrapping_key_id", p.UnwrapKeyByID.UnwrappingKeyID)
	},
	ActionExportKeyMaterial: func(p *PKCS11Payload) error {
		if p.ExportKeyMaterial == nil {
			return requirePKCS11Request(ActionExportKeyMaterial, false)
		}
		return requirePKCS11Field(ActionExportKeyMaterial, "key_id", p.ExportKeyMaterial.KeyID)
	},
	ActionGetImportParameters: func(p *PKCS11Payload) error {
		return requirePKCS11Request(ActionGetImportParameters, p.GetImportParameters != nil)
	},
	ActionImportKey: func(p *PKCS11Payload) error {
		return requirePKCS11Request(ActionImportKey, p.ImportKey != nil)
	},
	ActionListPIVSlots: func(*PKCS11Payload) error {
		// The request is optional: an absent one lists the default backend.
		return nil
	},
	ActionGetPIVCertificate: func(p *PKCS11Payload) error {
		if p.GetPIVCertificate == nil {
			return requirePKCS11Request(ActionGetPIVCertificate, false)
		}
		return requirePKCS11Field(ActionGetPIVCertificate, "slot", p.GetPIVCertificate.Slot)
	},
	ActionGeneratePIVKey: func(p *PKCS11Payload) error {
		if p.GeneratePIVKey == nil {
			return requirePKCS11Request(ActionGeneratePIVKey, false)
		}
		return requirePKCS11Field(ActionGeneratePIVKey, "slot", p.GeneratePIVKey.Slot)
	},
	ActionStorePIVCertificate: func(p *PKCS11Payload) error {
		if p.StorePIVCertificate == nil {
			return requirePKCS11Request(ActionStorePIVCertificate, false)
		}
		return requirePKCS11Field(ActionStorePIVCertificate, "slot", p.StorePIVCertificate.Slot)
	},
	ActionDeletePIVCertificate: func(p *PKCS11Payload) error {
		if p.DeletePIVCertificate == nil {
			return requirePKCS11Request(ActionDeletePIVCertificate, false)
		}
		return requirePKCS11Field(ActionDeletePIVCertificate, "slot", p.DeletePIVCertificate.Slot)
	},
	ActionImportPIVCertificate: func(p *PKCS11Payload) error {
		if p.ImportPIVCertificate == nil {
			return requirePKCS11Request(ActionImportPIVCertificate, false)
		}
		return requirePKCS11Field(ActionImportPIVCertificate, "slot", p.ImportPIVCertificate.Slot)
	},
	ActionExportPIVCertificate: func(p *PKCS11Payload) error {
		if p.ExportPIVCertificate == nil {
			return requirePKCS11Request(ActionExportPIVCertificate, false)
		}
		return requirePKCS11Field(ActionExportPIVCertificate, "slot", p.ExportPIVCertificate.Slot)
	},
	ActionGeneratePIVCSR: func(p *PKCS11Payload) error {
		if p.GeneratePIVCSR == nil {
			return requirePKCS11Request(ActionGeneratePIVCSR, false)
		}
		return requirePKCS11Field(ActionGeneratePIVCSR, "slot", p.GeneratePIVCSR.Slot)
	},
	ActionBarrierStatus: func(*PKCS11Payload) error {
		return nil
	},
}

// requirePKCS11Request reports a payload whose action's request is absent.
func requirePKCS11Request(action string, present bool) error {
	if present {
		return nil
	}
	return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": %s request required for %s action", action, action)}
}

// requirePKCS11Field reports an empty required field of an action's request.
func requirePKCS11Field(action, field, value string) error {
	if value != "" {
		return nil
	}
	return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": %s is required for %s", field, action)}
}

// Validate checks the PKCS11Payload for correctness.
func (p *PKCS11Payload) Validate() error {
	if p.Action == "" {
		return &DetailError{Err: ErrInvalidMessage, Detail: ": pkcs11 action is required"}
	}
	validate, ok := pkcs11Validators[p.Action]
	if !ok {
		return &DetailError{Err: ErrInvalidMessage, Detail: fmt.Sprintf(": unknown pkcs11 action %q", p.Action)}
	}
	return validate(p)
}
