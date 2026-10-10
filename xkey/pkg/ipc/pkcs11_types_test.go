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
	"encoding/json"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCS11Validators_CoverEveryDispatchedAction(t *testing.T) {
	for action := range pkcs11Handlers {
		_, ok := pkcs11Validators[action]
		assert.True(t, ok, "action %q is dispatched but never validated", action)
	}
	assert.Len(t, pkcs11Validators, len(pkcs11Handlers))
}

func TestPKCS11Payload_Validate_EveryOperation_Valid(t *testing.T) {
	for action, tc := range pkcs11Cases() {
		assert.NoError(t, tc.payload.Validate(), action)
	}
}

func TestPKCS11Payload_Validate_EveryOperation_MissingRequest(t *testing.T) {
	for action := range pkcs11Cases() {
		if action == ActionListPIVSlots {
			continue // the only operation whose request is optional
		}
		err := (&PKCS11Payload{Action: action}).Validate()
		require.ErrorIs(t, err, ErrInvalidMessage, action)
		assert.Contains(t, err.Error(), "request required for "+action+" action")
	}
}

func TestPKCS11Payload_Validate_MissingRequiredField(t *testing.T) {
	tests := map[string]struct {
		payload *PKCS11Payload
		detail  string
	}{
		"sign without key_id": {
			&PKCS11Payload{Action: ActionSign, Sign: &transport.SignRequest{Data: []byte("d")}},
			"key_id is required for sign"},
		"sign without data": {
			&PKCS11Payload{Action: ActionSign, Sign: &transport.SignRequest{KeyID: "k"}},
			"data is required for sign"},
		"verify without key_id": {
			&PKCS11Payload{Action: ActionVerify, Verify: &transport.VerifyRequest{}},
			"key_id is required for verify"},
		"encrypt without key_id": {
			&PKCS11Payload{Action: ActionEncrypt, Encrypt: &transport.EncryptRequest{}},
			"key_id is required for encrypt"},
		"encrypt_asym without key_id": {
			&PKCS11Payload{Action: ActionEncryptAsym, EncryptAsym: &transport.EncryptAsymRequest{}},
			"key_id is required for encrypt_asym"},
		"decrypt without key_id": {
			&PKCS11Payload{Action: ActionDecrypt, Decrypt: &transport.DecryptRequest{}},
			"key_id is required for decrypt"},
		"ecdh without key_id": {
			&PKCS11Payload{Action: ActionDeriveKeyECDH, DeriveKeyECDH: &transport.DeriveKeyECDHRequest{}},
			"key_id is required for derive_key_ecdh"},
		"wrap without wrapping key": {
			&PKCS11Payload{Action: ActionWrapKeyByID, WrapKeyByID: &transport.WrapKeyByIDRequest{}},
			"wrapping_key_id is required for wrap_key_by_id"},
		"unwrap without unwrapping key": {
			&PKCS11Payload{Action: ActionUnwrapKeyByID, UnwrapKeyByID: &transport.UnwrapKeyByIDRequest{}},
			"unwrapping_key_id is required for unwrap_key_by_id"},
		"export without key_id": {
			&PKCS11Payload{Action: ActionExportKeyMaterial, ExportKeyMaterial: &transport.ExportKeyMaterialRequest{}},
			"key_id is required for export_key_material"},
		"get cert without slot": {
			&PKCS11Payload{Action: ActionGetPIVCertificate, GetPIVCertificate: &transport.GetPIVCertificateRequest{}},
			"slot is required for get_piv_certificate"},
		"generate piv key without slot": {
			&PKCS11Payload{Action: ActionGeneratePIVKey, GeneratePIVKey: &transport.GeneratePIVKeyRequest{}},
			"slot is required for generate_piv_key"},
		"store cert without slot": {
			&PKCS11Payload{Action: ActionStorePIVCertificate, StorePIVCertificate: &transport.StorePIVCertificateRequest{}},
			"slot is required for store_piv_certificate"},
		"delete cert without slot": {
			&PKCS11Payload{Action: ActionDeletePIVCertificate, DeletePIVCertificate: &transport.DeletePIVCertificateRequest{}},
			"slot is required for delete_piv_certificate"},
		"import cert without slot": {
			&PKCS11Payload{Action: ActionImportPIVCertificate, ImportPIVCertificate: &transport.StorePIVCertificateRequest{}},
			"slot is required for import_piv_certificate"},
		"export cert without slot": {
			&PKCS11Payload{Action: ActionExportPIVCertificate, ExportPIVCertificate: &transport.GetPIVCertificateRequest{}},
			"slot is required for export_piv_certificate"},
		"csr without slot": {
			&PKCS11Payload{Action: ActionGeneratePIVCSR, GeneratePIVCSR: &transport.GeneratePIVCSRRequest{}},
			"slot is required for generate_piv_csr"},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := tc.payload.Validate()
			require.ErrorIs(t, err, ErrInvalidMessage)
			assert.Contains(t, err.Error(), tc.detail)
		})
	}
}

func TestPKCS11Payload_Validate_ListPIVSlots_WithoutRequest(t *testing.T) {
	assert.NoError(t, (&PKCS11Payload{Action: ActionListPIVSlots}).Validate())
}

func TestPKCS11Payload_Validate_BarrierStatus_Valid(t *testing.T) {
	assert.NoError(t, (&PKCS11Payload{Action: ActionBarrierStatus}).Validate())
}

func TestPKCS11Payload_Validate_EmptyAction(t *testing.T) {
	err := (&PKCS11Payload{}).Validate()
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pkcs11 action is required")
}

func TestPKCS11Payload_Validate_UnknownAction(t *testing.T) {
	err := (&PKCS11Payload{Action: "destroy_all_keys"}).Validate()
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestPKCS11Payload_JSONRoundtrip_EveryOperation(t *testing.T) {
	for action, tc := range pkcs11Cases() {
		data, err := json.Marshal(tc.payload)
		require.NoError(t, err, action)

		var decoded PKCS11Payload
		require.NoError(t, json.Unmarshal(data, &decoded), action)
		assert.Equal(t, tc.payload, &decoded, action)
	}
}

func TestPKCS11Payload_JSONOmitsEmptyFields(t *testing.T) {
	data, err := json.Marshal(&PKCS11Payload{Action: ActionBarrierStatus})
	require.NoError(t, err)
	assert.JSONEq(t, `{"action":"barrier_status"}`, string(data))
}

func TestPKCS11Result_JSONRoundtrip_Sign(t *testing.T) {
	original := &PKCS11Result{Sign: &transport.SignResponse{Signature: []byte("signature")}}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	var decoded PKCS11Result
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original, &decoded)
	assert.Nil(t, decoded.GetPIVCertificate)
	assert.Nil(t, decoded.BarrierStatus)
}

func TestPKCS11Result_JSONRoundtrip_BarrierStatus(t *testing.T) {
	original := &PKCS11Result{
		BarrierStatus: &BarrierStatusResult{Strategy: "software", HardwareBacked: true},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)
	var decoded PKCS11Result
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original, &decoded)
}

func TestMessage_Validate_PKCS11_Valid(t *testing.T) {
	msg := &Message{Type: MessageTypePKCS11, PKCS11: &PKCS11Payload{Action: ActionBarrierStatus}}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_PKCS11_NilPayload(t *testing.T) {
	err := (&Message{Type: MessageTypePKCS11}).Validate()
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pkcs11 payload is required")
}

func TestMessage_Validate_PKCS11_InvalidAction(t *testing.T) {
	err := (&Message{Type: MessageTypePKCS11, PKCS11: &PKCS11Payload{Action: "invalid_action"}}).Validate()
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestResponse_JSONOmitsPKCS11WhenNil(t *testing.T) {
	data, err := json.Marshal(Response{Status: StatusOK, Action: ActionDaemonReady})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "pkcs11")
}
