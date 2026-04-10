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

package events

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewEvent(t *testing.T) {
	before := time.Now()
	evt := NewEvent(EventPhoneConnected, map[string]string{"device": "pixel"})
	after := time.Now()

	assert.Equal(t, EventPhoneConnected, evt.Type)
	assert.NotNil(t, evt.Payload)
	assert.False(t, evt.Time.Before(before))
	assert.False(t, evt.Time.After(after))
}

func TestNewEvent_NilPayload(t *testing.T) {
	evt := NewEvent(EventError, nil)
	assert.Equal(t, EventError, evt.Type)
	assert.Nil(t, evt.Payload)
}

func TestEvent_JSONSerialization(t *testing.T) {
	evt := NewEvent(EventKeyCreated, KeyEventPayload{
		KeyID:     "key-123",
		Algorithm: "ECDSA-P256",
		Backend:   "software",
	})

	data, err := json.Marshal(evt)
	require.NoError(t, err)

	var decoded Event
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, EventKeyCreated, decoded.Type)
	assert.NotNil(t, decoded.Payload)
}

func TestEventTypes_NotEmpty(t *testing.T) {
	types := []EventType{
		EventPhoneConnected,
		EventPhoneDisconnected,
		EventPhoneScanResult,
		EventPhonePairingReq,
		EventKeyCreated,
		EventKeyDeleted,
		EventKeyUsed,
		EventTOTPGenerated,
		EventBridgeStarted,
		EventBridgeStopped,
		EventAttestationResult,
		EventSettingsChanged,
		EventAuditEntry,
		EventError,
	}
	for _, et := range types {
		t.Run(string(et), func(t *testing.T) {
			assert.NotEmpty(t, string(et))
		})
	}
}

func TestEventTypes_Unique(t *testing.T) {
	types := []EventType{
		EventPhoneConnected,
		EventPhoneDisconnected,
		EventPhoneScanResult,
		EventPhonePairingReq,
		EventKeyCreated,
		EventKeyDeleted,
		EventKeyUsed,
		EventTOTPGenerated,
		EventBridgeStarted,
		EventBridgeStopped,
		EventAttestationResult,
		EventSettingsChanged,
		EventAuditEntry,
		EventError,
	}
	seen := make(map[EventType]struct{})
	for _, et := range types {
		_, exists := seen[et]
		assert.False(t, exists, "duplicate event type: %s", et)
		seen[et] = struct{}{}
	}
}

func TestPhoneConnectedPayload_JSON(t *testing.T) {
	p := PhoneConnectedPayload{
		DeviceName: "Pixel 8",
		Address:    "AA:BB:CC:DD:EE:FF",
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)

	var decoded PhoneConnectedPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, p.DeviceName, decoded.DeviceName)
	assert.Equal(t, p.Address, decoded.Address)
}

func TestTOTPGeneratedPayload_JSON(t *testing.T) {
	p := TOTPGeneratedPayload{
		AccountID:   "github:user@example.com",
		Code:        "123456",
		TimeLeft:    15,
		AccountName: "GitHub",
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)

	var decoded TOTPGeneratedPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, p.Code, decoded.Code)
	assert.Equal(t, p.TimeLeft, decoded.TimeLeft)
}

func TestErrorPayload_JSON(t *testing.T) {
	p := ErrorPayload{
		Message:   "something went wrong",
		Component: "phone",
	}
	data, err := json.Marshal(p)
	require.NoError(t, err)

	var decoded ErrorPayload
	err = json.Unmarshal(data, &decoded)
	require.NoError(t, err)
	assert.Equal(t, p.Message, decoded.Message)
	assert.Equal(t, p.Component, decoded.Component)
}
