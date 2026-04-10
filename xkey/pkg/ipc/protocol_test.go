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

func TestMessage_Validate_Touch(t *testing.T) {
	msg := &Message{Type: MessageTypeTouch}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_TypePassword(t *testing.T) {
	msg := &Message{Type: MessageTypeTypePassword, Name: "mypassword"}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_Status(t *testing.T) {
	msg := &Message{Type: MessageTypeStatus}
	assert.NoError(t, msg.Validate())
}

func TestMessage_Validate_UnknownType(t *testing.T) {
	msg := &Message{Type: "unknown"}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "unknown message type")
}

func TestMessage_Validate_EmptyType(t *testing.T) {
	msg := &Message{Type: ""}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "type is required")
}

func TestMessage_Validate_TypePasswordRequiresName(t *testing.T) {
	msg := &Message{Type: MessageTypeTypePassword}
	err := msg.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "name is required")
}

func TestOKResponse(t *testing.T) {
	resp := OKResponse(ActionApprovedUP)
	assert.Equal(t, StatusOK, resp.Status)
	assert.Equal(t, ActionApprovedUP, resp.Action)
	assert.Empty(t, resp.Error)
}

func TestErrorResponse(t *testing.T) {
	resp := ErrorResponse("something went wrong")
	assert.Equal(t, StatusError, resp.Status)
	assert.Empty(t, resp.Action)
	assert.Equal(t, "something went wrong", resp.Error)
}

func TestMessage_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		msg  Message
	}{
		{
			name: "touch message",
			msg:  Message{Type: MessageTypeTouch},
		},
		{
			name: "type_password message",
			msg:  Message{Type: MessageTypeTypePassword, Name: "mypass"},
		},
		{
			name: "status message",
			msg:  Message{Type: MessageTypeStatus},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.msg)
			require.NoError(t, err)

			var decoded Message
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.msg.Type, decoded.Type)
			assert.Equal(t, tt.msg.Name, decoded.Name)
		})
	}
}

func TestResponse_JSONRoundtrip(t *testing.T) {
	tests := []struct {
		name string
		resp Response
	}{
		{
			name: "ok response with action",
			resp: Response{Status: StatusOK, Action: ActionApprovedUP},
		},
		{
			name: "error response",
			resp: Response{Status: StatusError, Error: "handler failed"},
		},
		{
			name: "ok response daemon ready",
			resp: Response{Status: StatusOK, Action: ActionDaemonReady},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := json.Marshal(tt.resp)
			require.NoError(t, err)

			var decoded Response
			err = json.Unmarshal(data, &decoded)
			require.NoError(t, err)

			assert.Equal(t, tt.resp.Status, decoded.Status)
			assert.Equal(t, tt.resp.Action, decoded.Action)
			assert.Equal(t, tt.resp.Error, decoded.Error)
		})
	}
}

func TestMessage_JSONOmitsEmptyName(t *testing.T) {
	msg := Message{Type: MessageTypeTouch}
	data, err := json.Marshal(msg)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "name")
}

func TestResponse_JSONOmitsEmptyFields(t *testing.T) {
	resp := Response{Status: StatusOK, Action: ActionDaemonReady}
	data, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "error")
}

func TestOKResponse_AllActions(t *testing.T) {
	actions := []string{
		ActionApprovedUP,
		ActionTypedPassword,
		ActionNoPending,
		ActionDaemonReady,
	}

	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			resp := OKResponse(action)
			assert.Equal(t, StatusOK, resp.Status)
			assert.Equal(t, action, resp.Action)
			assert.Empty(t, resp.Error)
		})
	}
}

func TestErrorResponse_PreservesMessage(t *testing.T) {
	msg := "detailed error description with context"
	resp := ErrorResponse(msg)
	assert.Equal(t, StatusError, resp.Status)
	assert.Equal(t, msg, resp.Error)
}

// ---------------------------------------------------------------------------
// AutofillPayload validation tests for save and ignore_domain
// ---------------------------------------------------------------------------

func TestAutofillPayload_Validate_SaveAction(t *testing.T) {
	p := &AutofillPayload{
		Action:   ActionAutofillSave,
		Domain:   "example.com",
		Username: "user1",
		Password: "pass1",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_SaveAction_MissingDomain(t *testing.T) {
	p := &AutofillPayload{
		Action:   ActionAutofillSave,
		Username: "user1",
		Password: "pass1",
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "domain is required")
}

func TestAutofillPayload_Validate_SaveAction_MissingUsername(t *testing.T) {
	p := &AutofillPayload{
		Action:   ActionAutofillSave,
		Domain:   "example.com",
		Password: "pass1",
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "username is required")
}

func TestAutofillPayload_Validate_SaveAction_MissingPassword(t *testing.T) {
	p := &AutofillPayload{
		Action:   ActionAutofillSave,
		Domain:   "example.com",
		Username: "user1",
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "password is required")
}

func TestAutofillPayload_Validate_IgnoreDomainAction(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillIgnoreDomain,
		Domain: "example.com",
	}
	assert.NoError(t, p.Validate())
}

func TestAutofillPayload_Validate_IgnoreDomainAction_MissingDomain(t *testing.T) {
	p := &AutofillPayload{
		Action: ActionAutofillIgnoreDomain,
	}
	err := p.Validate()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidMessage))
	assert.Contains(t, err.Error(), "domain is required")
}
