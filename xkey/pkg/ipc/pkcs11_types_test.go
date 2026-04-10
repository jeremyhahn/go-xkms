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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPKCS11Payload_Validate_SignAction_Valid(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionSign,
		Sign: &SignParams{
			Backend: "software",
			KeyID:   "test-key",
			Data:    "dGVzdA==",
			Hash:    "SHA-256",
		},
	}
	assert.NoError(t, p.Validate())
}

func TestPKCS11Payload_Validate_SignAction_MissingParams(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionSign,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "sign params required")
}

func TestPKCS11Payload_Validate_SignAction_MissingKeyID(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionSign,
		Sign: &SignParams{
			Data: "dGVzdA==",
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "key_id is required")
}

func TestPKCS11Payload_Validate_SignAction_MissingData(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionSign,
		Sign: &SignParams{
			KeyID: "test-key",
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "data is required")
}

func TestPKCS11Payload_Validate_GetPIVCertificate_Valid(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionGetPIVCertificate,
		PIVCert: &PIVCertParams{
			Backend: "software",
			Slot:    "9a",
			Format:  "pem",
		},
	}
	assert.NoError(t, p.Validate())
}

func TestPKCS11Payload_Validate_GetPIVCertificate_MissingParams(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionGetPIVCertificate,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "piv_cert params required")
}

func TestPKCS11Payload_Validate_GetPIVCertificate_MissingSlot(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionGetPIVCertificate,
		PIVCert: &PIVCertParams{
			Backend: "software",
		},
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "slot is required")
}

func TestPKCS11Payload_Validate_ListPIVSlots_Valid(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionListPIVSlots,
	}
	assert.NoError(t, p.Validate())
}

func TestPKCS11Payload_Validate_ListPIVSlots_WithParams(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionListPIVSlots,
		PIVSlots: &PIVSlotsParams{
			Backend: "software",
		},
	}
	assert.NoError(t, p.Validate())
}

func TestPKCS11Payload_Validate_BarrierStatus_Valid(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionBarrierStatus,
	}
	assert.NoError(t, p.Validate())
}

func TestPKCS11Payload_Validate_EmptyAction(t *testing.T) {
	p := &PKCS11Payload{}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pkcs11 action is required")
}

func TestPKCS11Payload_Validate_UnknownAction(t *testing.T) {
	p := &PKCS11Payload{
		Action: "destroy_all_keys",
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestPKCS11Payload_JSONRoundtrip_Sign(t *testing.T) {
	original := &PKCS11Payload{
		Action: ActionSign,
		Sign: &SignParams{
			Backend: "software",
			KeyID:   "my-key",
			Data:    "dGVzdCBkYXRh",
			Hash:    "SHA-256",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PKCS11Payload
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.Sign.Backend, decoded.Sign.Backend)
	assert.Equal(t, original.Sign.KeyID, decoded.Sign.KeyID)
	assert.Equal(t, original.Sign.Data, decoded.Sign.Data)
	assert.Equal(t, original.Sign.Hash, decoded.Sign.Hash)
}

func TestPKCS11Payload_JSONRoundtrip_PIVCert(t *testing.T) {
	original := &PKCS11Payload{
		Action: ActionGetPIVCertificate,
		PIVCert: &PIVCertParams{
			Backend: "pkcs11",
			Slot:    "9c",
			Format:  "der",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PKCS11Payload
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original.Action, decoded.Action)
	assert.Equal(t, original.PIVCert.Backend, decoded.PIVCert.Backend)
	assert.Equal(t, original.PIVCert.Slot, decoded.PIVCert.Slot)
	assert.Equal(t, original.PIVCert.Format, decoded.PIVCert.Format)
}

func TestPKCS11Payload_JSONOmitsEmptyFields(t *testing.T) {
	p := &PKCS11Payload{
		Action: ActionBarrierStatus,
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)

	jsonStr := string(data)
	assert.NotContains(t, jsonStr, "sign")
	assert.NotContains(t, jsonStr, "piv_cert")
	assert.NotContains(t, jsonStr, "piv_slots")
}

func TestPKCS11Result_JSONRoundtrip_Sign(t *testing.T) {
	original := &PKCS11Result{
		Sign: &SignResult{
			Signature: "c2lnbmF0dXJl",
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PKCS11Result
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.NotNil(t, decoded.Sign)
	assert.Equal(t, original.Sign.Signature, decoded.Sign.Signature)
	assert.Nil(t, decoded.PIVCert)
	assert.Nil(t, decoded.PIVSlots)
	assert.Nil(t, decoded.BarrierStatus)
}

func TestPKCS11Result_JSONRoundtrip_BarrierStatus(t *testing.T) {
	original := &PKCS11Result{
		BarrierStatus: &BarrierStatusResult{
			Sealed:         false,
			Strategy:       "software",
			HardwareBacked: true,
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PKCS11Result
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.NotNil(t, decoded.BarrierStatus)
	assert.False(t, decoded.BarrierStatus.Sealed)
	assert.Equal(t, "software", decoded.BarrierStatus.Strategy)
	assert.True(t, decoded.BarrierStatus.HardwareBacked)
}

func TestPKCS11Result_JSONRoundtrip_PIVSlots(t *testing.T) {
	original := &PKCS11Result{
		PIVSlots: &PIVSlotsResult{
			Slots: []PIVSlotInfo{
				{Slot: "9a", Algorithm: "ECDSA-P256", HasCert: true, Subject: "CN=test"},
				{Slot: "9c", HasCert: false},
			},
		},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded PKCS11Result
	require.NoError(t, json.Unmarshal(data, &decoded))

	require.NotNil(t, decoded.PIVSlots)
	require.Len(t, decoded.PIVSlots.Slots, 2)
	assert.Equal(t, "9a", decoded.PIVSlots.Slots[0].Slot)
	assert.True(t, decoded.PIVSlots.Slots[0].HasCert)
	assert.Equal(t, "9c", decoded.PIVSlots.Slots[1].Slot)
	assert.False(t, decoded.PIVSlots.Slots[1].HasCert)
}

func TestMessage_Validate_PKCS11_Valid(t *testing.T) {
	msg := &Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionBarrierStatus,
		},
	}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_PKCS11_NilPayload(t *testing.T) {
	msg := &Message{
		Type: MessageTypePKCS11,
	}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pkcs11 payload is required")
}

func TestMessage_Validate_PKCS11_InvalidAction(t *testing.T) {
	msg := &Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: "invalid_action",
		},
	}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown pkcs11 action")
}

func TestMessage_JSONRoundtrip_PKCS11(t *testing.T) {
	msg := Message{
		Type: MessageTypePKCS11,
		PKCS11: &PKCS11Payload{
			Action: ActionSign,
			Sign: &SignParams{
				Backend: "software",
				KeyID:   "test-key",
				Data:    "dGVzdA==",
			},
		},
	}

	data, err := json.Marshal(msg)
	require.NoError(t, err)

	var decoded Message
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, MessageTypePKCS11, decoded.Type)
	require.NotNil(t, decoded.PKCS11)
	assert.Equal(t, ActionSign, decoded.PKCS11.Action)
	require.NotNil(t, decoded.PKCS11.Sign)
	assert.Equal(t, "test-key", decoded.PKCS11.Sign.KeyID)
}

func TestResponse_JSONRoundtrip_PKCS11(t *testing.T) {
	resp := Response{
		Status: StatusOK,
		PKCS11: &PKCS11Result{
			Sign: &SignResult{
				Signature: "c2lnbmF0dXJl",
			},
		},
	}

	data, err := json.Marshal(resp)
	require.NoError(t, err)

	var decoded Response
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, StatusOK, decoded.Status)
	require.NotNil(t, decoded.PKCS11)
	require.NotNil(t, decoded.PKCS11.Sign)
	assert.Equal(t, "c2lnbmF0dXJl", decoded.PKCS11.Sign.Signature)
}

func TestResponse_JSONOmitsPKCS11WhenNil(t *testing.T) {
	resp := Response{
		Status: StatusOK,
		Action: ActionDaemonReady,
	}
	data, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "pkcs11")
}
