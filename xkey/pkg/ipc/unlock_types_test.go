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

func TestUnlockPayload_Validate_EmptyPIN(t *testing.T) {
	p := &UnlockPayload{PIN: ""}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pin is required for unlock")
}

func TestUnlockPayload_Validate_Success(t *testing.T) {
	p := &UnlockPayload{PIN: "123456"}
	assert.NoError(t, p.Validate())
}

func TestMessage_Validate_Unlock(t *testing.T) {
	msg := &Message{
		Type:   MessageTypeUnlock,
		Unlock: &UnlockPayload{PIN: "123456"},
	}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_Unlock_NilPayload(t *testing.T) {
	msg := &Message{
		Type:   MessageTypeUnlock,
		Unlock: nil,
	}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unlock payload is required")
}

func TestMessage_Validate_Unlock_EmptyPIN(t *testing.T) {
	msg := &Message{
		Type:   MessageTypeUnlock,
		Unlock: &UnlockPayload{PIN: ""},
	}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "pin is required for unlock")
}

func TestUnlockResult_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name   string
		result UnlockResult
	}{
		{
			name:   "success result",
			result: UnlockResult{Success: true},
		},
		{
			name:   "failure result with error",
			result: UnlockResult{Success: false, Error: "invalid pin"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.result)
			require.NoError(t, err)

			var decoded UnlockResult
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.result.Success, decoded.Success)
			assert.Equal(t, tt.result.Error, decoded.Error)
		})
	}
}
